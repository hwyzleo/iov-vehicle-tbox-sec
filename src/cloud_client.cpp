#include "cloud_client.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace tbox {
namespace sec {

namespace {

std::once_flag g_curl_init_flag;

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> result(encoded.size());
    int decoded_length = BIO_read(bmem, result.data(), static_cast<int>(result.size()));
    BIO_free_all(bmem);

    if (decoded_length > 0) {
        result.resize(decoded_length);
    } else {
        result.clear();
    }
    return result;
}

size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

} // namespace

CloudClient::CloudClient(const CloudConfig& config)
    : config_(config), initialized_(false), connected_(false) {}

ErrorCode CloudClient::initialize() {
    std::call_once(g_curl_init_flag, []() {
        curl_global_init(CURL_GLOBAL_ALL);
    });

    initialized_ = true;
    connected_ = true;
    return ErrorCode::SUCCESS;
}

void CloudClient::set_last_error(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = error;
}

ErrorCode CloudClient::submit_csr(const CertificateRequest& request,
                                 CertificateResponse& response) {
    if (!initialized_ || !connected_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    nlohmann::json payload;
    payload["csr_der"] = base64_encode(request.csr_der);
    payload["device_sn"] = request.device_sn;

    int max_attempts = config_.retry_count > 0 ? config_.retry_count : 1;
    ErrorCode last_result = ErrorCode::PKI_CONNECTION_FAILED;

    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        if (attempt > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.retry_delay_ms));
        }

        std::string response_str;
        last_result = send_http_request(config_.oapi_endpoint + "/api/v1/certificates",
                                        payload.dump(),
                                        response_str);

        if (last_result == ErrorCode::SUCCESS) {
            return parse_certificate_response(response_str, response);
        }
    }

    return last_result;
}

ErrorCode CloudClient::submit_csr_async(const CertificateRequest& request,
                                       CertificateCallback callback) {
    auto self = shared_from_this();
    async_task_ = std::async(std::launch::async, [self, request, callback]() {
        CertificateResponse response;
        ErrorCode result = self->submit_csr(request, response);
        response.error_code = result;
        callback(response);
    });

    return ErrorCode::SUCCESS;
}

bool CloudClient::is_connected() const {
    return connected_;
}

std::string CloudClient::get_last_error() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

ErrorCode CloudClient::send_http_request(const std::string& endpoint,
                                        const std::string& payload,
                                        std::string& response) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        set_last_error("Failed to create CURL handle");
        return ErrorCode::PKI_CONNECTION_FAILED;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config_.timeout_ms);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    std::string response_data;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        set_last_error(curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return ErrorCode::PKI_CONNECTION_FAILED;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (http_code != 200) {
        return handle_http_error(static_cast<int>(http_code), response_data);
    }

    response = response_data;
    return ErrorCode::SUCCESS;
}

ErrorCode CloudClient::parse_certificate_response(const std::string& response,
                                                 CertificateResponse& cert_response) {
    try {
        nlohmann::json json = nlohmann::json::parse(response);

        if (json.contains("error")) {
            cert_response.error_message = json["error"].get<std::string>();
            return ErrorCode::PKI_REJECTED;
        }

        if (json.contains("cert_der")) {
            cert_response.cert_der = base64_decode(json["cert_der"].get<std::string>());
        }

        if (json.contains("chain")) {
            cert_response.chain = base64_decode(json["chain"].get<std::string>());
        }

        return ErrorCode::SUCCESS;
    } catch (const std::exception& e) {
        set_last_error("Failed to parse response: " + std::string(e.what()));
        return ErrorCode::PKI_INVALID_RESPONSE;
    }
}

ErrorCode CloudClient::handle_http_error(int http_code, const std::string& response) {
    if (http_code == 400) {
        set_last_error("Bad request: " + response);
        return ErrorCode::PKI_REJECTED;
    } else if (http_code == 401) {
        set_last_error("Unauthorized");
        return ErrorCode::PKI_CONNECTION_FAILED;
    } else if (http_code == 403) {
        set_last_error("Forbidden");
        return ErrorCode::PKI_CONNECTION_FAILED;
    } else if (http_code == 404) {
        set_last_error("Not found");
        return ErrorCode::PKI_CONNECTION_FAILED;
    } else if (http_code == 408) {
        set_last_error("Request timeout");
        return ErrorCode::PKI_TIMEOUT;
    } else if (http_code == 500) {
        set_last_error("Internal server error");
        return ErrorCode::PKI_CONNECTION_FAILED;
    } else if (http_code == 503) {
        set_last_error("Service unavailable");
        return ErrorCode::PKI_CONNECTION_FAILED;
    } else {
        set_last_error("HTTP error " + std::to_string(http_code) + ": " + response);
        return ErrorCode::PKI_CONNECTION_FAILED;
    }
}

} // namespace sec
} // namespace tbox

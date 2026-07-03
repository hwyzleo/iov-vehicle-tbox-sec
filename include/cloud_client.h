#pragma once

#include <string>
#include <vector>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include "error_codes.h"
#include "store.h"

namespace tbox {
namespace sec {

struct CloudConfig {
    std::string oapi_endpoint;
    int timeout_ms;
    int retry_count;
    int retry_delay_ms;
};

struct CertificateRequest {
    std::vector<uint8_t> csr_der;
    std::string device_sn;
};

struct CertificateResponse {
    std::vector<uint8_t> cert_der;
    std::vector<uint8_t> chain;
    std::string error_message;
    ErrorCode error_code;
};

class CloudClient : public std::enable_shared_from_this<CloudClient> {
public:
    CloudClient(const CloudConfig& config);
    CloudClient(const CloudConfig& config, hwyz::store::Store store);

    ErrorCode initialize();

    void store_certificate(const std::vector<uint8_t>& cert_der);
    std::vector<uint8_t> load_certificate();

    ErrorCode submit_csr(const CertificateRequest& request,
                        CertificateResponse& response);

    using CertificateCallback = std::function<void(const CertificateResponse&)>;
    ErrorCode submit_csr_async(const CertificateRequest& request,
                              CertificateCallback callback);

    bool is_connected() const;

    std::string get_last_error() const;

private:
    CloudConfig config_;
    bool initialized_;
    bool connected_;
    std::string last_error_;
    mutable std::mutex error_mutex_;
    std::future<void> async_task_;
    hwyz::store::Store store_;

    void set_last_error(const std::string& error);

    ErrorCode send_http_request(const std::string& endpoint,
                               const std::string& payload,
                               std::string& response);

    ErrorCode parse_certificate_response(const std::string& response,
                                        CertificateResponse& cert_response);

    ErrorCode handle_http_error(int http_code, const std::string& response);
};

} // namespace sec
} // namespace tbox

#include "ipc_protocol.h"
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace tbox {
namespace sec {
namespace ipc {

std::vector<uint8_t> IpcSerializer::serialize_request(MethodId method, const std::string& params_json) {
    RequestHeader header;
    header.method_id = static_cast<uint32_t>(method);
    header.params_length = static_cast<uint32_t>(params_json.size());

    std::vector<uint8_t> result(sizeof(RequestHeader) + params_json.size());
    std::memcpy(result.data(), &header, sizeof(RequestHeader));
    std::memcpy(result.data() + sizeof(RequestHeader), params_json.data(), params_json.size());

    return result;
}

bool IpcSerializer::deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json) {
    if (data.size() < sizeof(RequestHeader)) {
        return false;
    }

    RequestHeader header;
    std::memcpy(&header, data.data(), sizeof(RequestHeader));

    if (data.size() < sizeof(RequestHeader) + header.params_length) {
        return false;
    }

    uint32_t method_id = header.method_id;
    if (method_id < static_cast<uint32_t>(MethodId::INITIALIZE) ||
        method_id > static_cast<uint32_t>(MethodId::RESET_STATUS)) {
        return false;
    }

    method = static_cast<MethodId>(method_id);
    params_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(RequestHeader)), header.params_length);

    return true;
}

std::vector<uint8_t> IpcSerializer::serialize_response(int32_t status_code, const std::string& response_json) {
    ResponseHeader header;
    header.status_code = status_code;
    header.data_length = static_cast<uint32_t>(response_json.size());

    std::vector<uint8_t> result(sizeof(ResponseHeader) + response_json.size());
    std::memcpy(result.data(), &header, sizeof(ResponseHeader));
    std::memcpy(result.data() + sizeof(ResponseHeader), response_json.data(), response_json.size());

    return result;
}

bool IpcSerializer::deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json) {
    if (data.size() < sizeof(ResponseHeader)) {
        return false;
    }

    ResponseHeader header;
    std::memcpy(&header, data.data(), sizeof(ResponseHeader));

    if (data.size() < sizeof(ResponseHeader) + header.data_length) {
        return false;
    }

    status_code = header.status_code;
    response_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(ResponseHeader)), header.data_length);

    return true;
}

std::string IpcSerializer::base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<uint8_t> IpcSerializer::base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> result(encoded.size());
    int len = BIO_read(bio, result.data(), static_cast<int>(encoded.size()));
    if (len > 0) {
        result.resize(len);
    } else {
        result.clear();
    }

    BIO_free_all(bio);
    return result;
}

} // namespace ipc
} // namespace sec
} // namespace tbox

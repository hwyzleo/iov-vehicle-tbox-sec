#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace sec {
namespace ipc {

enum class MethodId : uint32_t {
    INITIALIZE = 1,
    GENERATE_KEY_PAIR = 2,
    GET_CSR = 3,
    SUBMIT_CSR = 4,
    INJECT_CERTIFICATE = 5,
    APPLY_CERTIFICATE = 6,
    SET_CA_CERTIFICATE = 7,
    GET_SEED = 8,
    VERIFY_KEY = 9,
    GET_STATUS = 10,
    GET_DEVICE_INFO = 11,
    RESET_STATUS = 12,
};

struct RequestHeader {
    uint32_t method_id;
    uint32_t params_length;
} __attribute__((packed));

struct ResponseHeader {
    int32_t status_code;
    uint32_t data_length;
} __attribute__((packed));

constexpr const char* DEFAULT_SOCKET_PATH = "/tmp/tbox-sec.sock";

class IpcSerializer {
public:
    static std::vector<uint8_t> serialize_request(MethodId method, const std::string& params_json);
    static bool deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json);
    static std::vector<uint8_t> serialize_response(int32_t status_code, const std::string& response_json);
    static bool deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json);

    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
};

} // namespace ipc
} // namespace sec
} // namespace tbox

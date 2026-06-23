#pragma once

#include <vector>
#include <string>
#include <functional>
#include "error_codes.h"

namespace tbox {
namespace sec {

enum class DiagRequestType : uint8_t {
    GENERATE_KEY_PAIR = 0x01,
    READ_CSR = 0x02,
    INJECT_CERTIFICATE = 0x03,
    READ_PROVISION_STATE = 0x04,
    SUBMIT_CSR = 0x05,
    APPLY_CERTIFICATE = 0x06,
    GET_SEED = 0x07,
    VERIFY_KEY = 0x08
};

struct DiagResponse {
    ErrorCode error_code;
    std::vector<uint8_t> data;
    std::string error_message;
};

using DiagResponseCallback = std::function<void(const DiagResponse&)>;

class DiagServiceInterface {
public:
    virtual ~DiagServiceInterface() = default;

    virtual ErrorCode initialize() = 0;

    virtual ErrorCode send_request(DiagRequestType request_type,
                                  const std::vector<uint8_t>& request_data,
                                  DiagResponseCallback callback) = 0;

    virtual ErrorCode send_request_sync(DiagRequestType request_type,
                                       const std::vector<uint8_t>& request_data,
                                       DiagResponse& response) = 0;

    virtual bool is_connected() const = 0;

    virtual std::string get_service_status() const = 0;
};

} // namespace sec
} // namespace tbox

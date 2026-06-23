#pragma once

#include <vector>
#include <memory>
#include "sec_service.h"
#include "error_codes.h"

namespace tbox {
namespace diag {

using sec::ErrorCode;

struct SecurityAccessResponse {
    uint8_t nrc;  // Negative Response Code (0x00 for positive response)
    std::vector<uint8_t> data;
};

class ServiceDispatcher {
public:
    explicit ServiceDispatcher(std::shared_ptr<sec::SecService> sec_service);

    // Handle UDS SecurityAccess (0x27) service
    // sub_function: raw UDS sub-function (0x27 for requestSeed, 0x28 for sendKey)
    // For requestSeed: sub_function is odd (0x01, 0x03, ..., 0x27, etc.)
    // For sendKey: sub_function is even (0x02, 0x04, ..., 0x28, etc.)
    ErrorCode handle_security_access(uint8_t sub_function,
                                     const std::vector<uint8_t>& request_data,
                                     SecurityAccessResponse& response);

    // Reset failed attempt counter
    void reset_failed_attempts();

    // Get current failed attempt count
    int get_failed_attempts() const;

private:
    std::shared_ptr<sec::SecService> sec_service_;
    int failed_attempts_ = 0;

    ErrorCode handle_request_seed(uint8_t level, SecurityAccessResponse& response);
    ErrorCode handle_send_key(uint8_t level, const std::vector<uint8_t>& key,
                              SecurityAccessResponse& response);
    void increment_failed_attempts();
};

} // namespace diag
} // namespace tbox

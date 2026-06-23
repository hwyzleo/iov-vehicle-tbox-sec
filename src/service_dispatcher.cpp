#include "service_dispatcher.h"
#include <algorithm>

namespace tbox {
namespace diag {

ServiceDispatcher::ServiceDispatcher(std::shared_ptr<sec::SecService> sec_service)
    : sec_service_(sec_service) {}

ErrorCode ServiceDispatcher::handle_security_access(uint8_t sub_function,
                                                    const std::vector<uint8_t>& request_data,
                                                    SecurityAccessResponse& response) {
    if (!sec_service_) {
        response.nrc = 0x22; // conditionsNotCorrect
        return ErrorCode::NOT_INITIALIZED;
    }

    bool is_request_seed = (sub_function & 0x01) != 0; // Odd = requestSeed, Even = sendKey
    uint8_t raw_level = sub_function;

    if (is_request_seed) {
        return handle_request_seed(raw_level, response);
    } else {
        return handle_send_key(raw_level, request_data, response);
    }
}

ErrorCode ServiceDispatcher::handle_request_seed(uint8_t level,
                                                  SecurityAccessResponse& response) {
    std::vector<uint8_t> seed;
    ErrorCode result = sec_service_->get_seed(level, seed);

    switch (result) {
        case ErrorCode::SUCCESS:
            response.nrc = 0x00; // positive response
            response.data = seed;
            return ErrorCode::SUCCESS;

        case ErrorCode::UDS_SECURITY_DENIED:
            response.nrc = 0x37; // requiredTimeDelayNotExpired
            return result;

        case ErrorCode::SEED_GENERATION_FAILED:
            response.nrc = 0x72; // generalProgrammingFailure
            return result;

        default:
            response.nrc = 0x22; // conditionsNotCorrect
            return result;
    }
}

ErrorCode ServiceDispatcher::handle_send_key(uint8_t level,
                                              const std::vector<uint8_t>& key,
                                              SecurityAccessResponse& response) {
    // Pass the raw UDS security level to SEC
    // For sendKey with sub_function=0x28, level=0x28 (not 0x27)
    // SEC will validate that level == requestSeed_level + 1
    ErrorCode result = sec_service_->verify_key(level, key);

    switch (result) {
        case ErrorCode::SUCCESS:
            response.nrc = 0x00; // positive response
            response.data = {0x01}; // securityAccessGranted
            return ErrorCode::SUCCESS;

        case ErrorCode::UDS_SECURITY_DENIED:
            response.nrc = 0x37; // requiredTimeDelayNotExpired
            return result;

        case ErrorCode::KEY_VERIFICATION_FAILED:
            increment_failed_attempts();
            if (get_failed_attempts() >= 3) {
                response.nrc = 0x36; // exceededNumberOfAttempts
                reset_failed_attempts(); // Reset after lockout
            } else {
                response.nrc = 0x35; // invalidKey
            }
            return result;

        default:
            response.nrc = 0x22; // conditionsNotCorrect
            return result;
    }
}

void ServiceDispatcher::reset_failed_attempts() {
    failed_attempts_ = 0;
}

void ServiceDispatcher::increment_failed_attempts() {
    failed_attempts_++;
}

int ServiceDispatcher::get_failed_attempts() const {
    return failed_attempts_;
}

} // namespace diag
} // namespace tbox

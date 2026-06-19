#pragma once

#include <cstdint>
#include <string>

namespace tbox {
namespace sec {

enum class ErrorCode : uint32_t {
    SUCCESS = 0,

    // Key generation errors (SEC-1001)
    KEY_GENERATION_FAILED = 1001,
    KEY_ALREADY_EXISTS = 1002,
    KEY_NOT_FOUND = 1003,

    // CSR construction errors (SEC-1002)
    CSR_BUILD_FAILED = 2001,
    CSR_INVALID_SUBJECT = 2002,
    CSR_SIGN_FAILED = 2003,

    // PKI errors (SEC-1003, SEC-1004)
    PKI_REJECTED = 3001,
    PKI_TIMEOUT = 3002,
    PKI_CONNECTION_FAILED = 3003,
    PKI_INVALID_RESPONSE = 3004,

    // Certificate errors (SEC-1005)
    CERT_VALIDATION_FAILED = 4001,
    CERT_KEY_MISMATCH = 4002,
    CERT_EXPIRED = 4003,
    CERT_INSTALL_FAILED = 4004,

    // HSM/Secure Element errors
    HSM_INIT_FAILED = 5001,
    HSM_COMMUNICATION_FAILED = 5002,
    HSM_KEY_GENERATION_FAILED = 5003,
    HSM_SIGN_FAILED = 5004,

    // Storage errors
    STORAGE_WRITE_FAILED = 6001,
    STORAGE_READ_FAILED = 6002,
    STORAGE_CORRUPTION = 6003,

    // UDS errors
    UDS_SESSION_TIMEOUT = 7001,
    UDS_SECURITY_DENIED = 7002,
    UDS_INVALID_REQUEST = 7003,

    // General errors
    INVALID_PARAMETER = 8001,
    NOT_INITIALIZED = 8002,
    OPERATION_IN_PROGRESS = 8003,
    INTERNAL_ERROR = 9999
};

std::string error_code_to_string(ErrorCode code);
std::string error_code_to_description(ErrorCode code);

} // namespace sec
} // namespace tbox

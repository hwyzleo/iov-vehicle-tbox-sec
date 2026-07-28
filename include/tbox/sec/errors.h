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
    HSM_VERIFICATION_FAILED = 5005,

    // Storage errors
    STORAGE_WRITE_FAILED = 6001,
    STORAGE_READ_FAILED = 6002,
    STORAGE_CORRUPTION = 6003,

    // UDS errors
    UDS_SESSION_TIMEOUT = 7001,
    UDS_SECURITY_DENIED = 7002,
    UDS_INVALID_REQUEST = 7003,

    // Seed-Key errors (SEC-1007, SEC-1008)
    SEED_GENERATION_FAILED = 7007,
    KEY_VERIFICATION_FAILED = 7008,

    // Soft key errors (SEC-1009)
    SOFT_KEY_MODE_NOT_ALLOWED = 1009,

    // MQTT TLS credential errors (SEC-1010..1014, TBOX-SEC-DSN-CR-010)
    TLS_CREDENTIAL_NOT_READY = 1010,          ///< SEC-1010: TLS 凭据未就绪
    TLS_CREDENTIAL_INVALID = 1011,            ///< SEC-1011: 凭据无效、过期或撤销
    TLS_KEY_REF_INVALID = 1012,               ///< SEC-1012: 私钥引用无效或已失效
    TLS_SIGN_ALGORITHM_NOT_ALLOWED = 1013,    ///< SEC-1013: 签名算法或用途不允许
    TLS_HSM_SIGN_FAILED = 1014,               ///< SEC-1014: HSM/SE TLS 签名失败

    // ACL errors
    ACL_DENIED = 1020,                        ///< 调用方未授权访问该 profile

    // Configuration errors
    CONFIG_ERROR = 1100,

    // General errors
    INVALID_PARAMETER = 8001,
    NOT_INITIALIZED = 8002,
    OPERATION_IN_PROGRESS = 8003,
    NOT_IMPLEMENTED = 8004,
    CONNECTION_FAILED = 8005,
    PROV_NOT_CONFIGURED = 8006,
    INTERNAL_ERROR = 9999
};

std::string error_code_to_string(ErrorCode code);
std::string error_code_to_description(ErrorCode code);

} // namespace sec
} // namespace tbox

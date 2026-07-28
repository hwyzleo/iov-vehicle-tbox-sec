#include "error_codes.h"
#include "tbox/sec/types.h"

namespace tbox {
namespace sec {

std::string error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS: return "SUCCESS";
        case ErrorCode::KEY_GENERATION_FAILED: return "KEY_GENERATION_FAILED";
        case ErrorCode::KEY_ALREADY_EXISTS: return "KEY_ALREADY_EXISTS";
        case ErrorCode::KEY_NOT_FOUND: return "KEY_NOT_FOUND";
        case ErrorCode::CSR_BUILD_FAILED: return "CSR_BUILD_FAILED";
        case ErrorCode::CSR_INVALID_SUBJECT: return "CSR_INVALID_SUBJECT";
        case ErrorCode::CSR_SIGN_FAILED: return "CSR_SIGN_FAILED";
        case ErrorCode::PKI_REJECTED: return "PKI_REJECTED";
        case ErrorCode::PKI_TIMEOUT: return "PKI_TIMEOUT";
        case ErrorCode::PKI_CONNECTION_FAILED: return "PKI_CONNECTION_FAILED";
        case ErrorCode::PKI_INVALID_RESPONSE: return "PKI_INVALID_RESPONSE";
        case ErrorCode::CERT_VALIDATION_FAILED: return "CERT_VALIDATION_FAILED";
        case ErrorCode::CERT_KEY_MISMATCH: return "CERT_KEY_MISMATCH";
        case ErrorCode::CERT_EXPIRED: return "CERT_EXPIRED";
        case ErrorCode::CERT_INSTALL_FAILED: return "CERT_INSTALL_FAILED";
        case ErrorCode::HSM_INIT_FAILED: return "HSM_INIT_FAILED";
        case ErrorCode::HSM_COMMUNICATION_FAILED: return "HSM_COMMUNICATION_FAILED";
        case ErrorCode::HSM_KEY_GENERATION_FAILED: return "HSM_KEY_GENERATION_FAILED";
        case ErrorCode::HSM_SIGN_FAILED: return "HSM_SIGN_FAILED";
        case ErrorCode::HSM_VERIFICATION_FAILED: return "HSM_VERIFICATION_FAILED";
        case ErrorCode::STORAGE_WRITE_FAILED: return "STORAGE_WRITE_FAILED";
        case ErrorCode::STORAGE_READ_FAILED: return "STORAGE_READ_FAILED";
        case ErrorCode::STORAGE_CORRUPTION: return "STORAGE_CORRUPTION";
        case ErrorCode::UDS_SESSION_TIMEOUT: return "UDS_SESSION_TIMEOUT";
        case ErrorCode::UDS_SECURITY_DENIED: return "UDS_SECURITY_DENIED";
        case ErrorCode::UDS_INVALID_REQUEST: return "UDS_INVALID_REQUEST";
        case ErrorCode::SEED_GENERATION_FAILED: return "SEED_GENERATION_FAILED";
        case ErrorCode::KEY_VERIFICATION_FAILED: return "KEY_VERIFICATION_FAILED";
        case ErrorCode::INVALID_PARAMETER: return "INVALID_PARAMETER";
        case ErrorCode::NOT_INITIALIZED: return "NOT_INITIALIZED";
        case ErrorCode::OPERATION_IN_PROGRESS: return "OPERATION_IN_PROGRESS";
        case ErrorCode::NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
        case ErrorCode::CONNECTION_FAILED: return "CONNECTION_FAILED";
        case ErrorCode::PROV_NOT_CONFIGURED: return "PROV_NOT_CONFIGURED";
        case ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED: return "SOFT_KEY_MODE_NOT_ALLOWED";
        case ErrorCode::TLS_CREDENTIAL_NOT_READY: return "TLS_CREDENTIAL_NOT_READY";
        case ErrorCode::TLS_CREDENTIAL_INVALID: return "TLS_CREDENTIAL_INVALID";
        case ErrorCode::TLS_KEY_REF_INVALID: return "TLS_KEY_REF_INVALID";
        case ErrorCode::TLS_SIGN_ALGORITHM_NOT_ALLOWED: return "TLS_SIGN_ALGORITHM_NOT_ALLOWED";
        case ErrorCode::TLS_HSM_SIGN_FAILED: return "TLS_HSM_SIGN_FAILED";
        case ErrorCode::ACL_DENIED: return "ACL_DENIED";
        case ErrorCode::CONFIG_ERROR: return "CONFIG_ERROR";
        case ErrorCode::INTERNAL_ERROR: return "INTERNAL_ERROR";
        default: return "UNKNOWN";
    }
}

std::string error_code_to_description(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS: return "Operation completed successfully";
        case ErrorCode::KEY_GENERATION_FAILED: return "Failed to generate cryptographic key pair";
        case ErrorCode::KEY_ALREADY_EXISTS: return "Key already exists for this identity";
        case ErrorCode::KEY_NOT_FOUND: return "Key not found for this identity";
        case ErrorCode::CSR_BUILD_FAILED: return "Failed to build Certificate Signing Request";
        case ErrorCode::CSR_INVALID_SUBJECT: return "CSR subject fields are invalid";
        case ErrorCode::CSR_SIGN_FAILED: return "Failed to sign CSR with private key";
        case ErrorCode::PKI_REJECTED: return "PKI server rejected the certificate request";
        case ErrorCode::PKI_TIMEOUT: return "PKI server request timed out";
        case ErrorCode::PKI_CONNECTION_FAILED: return "Failed to connect to PKI server";
        case ErrorCode::PKI_INVALID_RESPONSE: return "Received invalid response from PKI server";
        case ErrorCode::CERT_VALIDATION_FAILED: return "Certificate validation failed";
        case ErrorCode::CERT_KEY_MISMATCH: return "Certificate public key does not match private key";
        case ErrorCode::CERT_EXPIRED: return "Certificate has expired";
        case ErrorCode::CERT_INSTALL_FAILED: return "Failed to install certificate";
        case ErrorCode::HSM_INIT_FAILED: return "Failed to initialize HSM/Secure Element";
        case ErrorCode::HSM_COMMUNICATION_FAILED: return "HSM communication error";
        case ErrorCode::HSM_KEY_GENERATION_FAILED: return "HSM key generation failed";
        case ErrorCode::HSM_SIGN_FAILED: return "HSM signing operation failed";
        case ErrorCode::HSM_VERIFICATION_FAILED: return "HSM verification operation failed";
        case ErrorCode::STORAGE_WRITE_FAILED: return "Failed to write to secure storage";
        case ErrorCode::STORAGE_READ_FAILED: return "Failed to read from secure storage";
        case ErrorCode::STORAGE_CORRUPTION: return "Storage data corruption detected";
        case ErrorCode::UDS_SESSION_TIMEOUT: return "UDS diagnostic session timed out";
        case ErrorCode::UDS_SECURITY_DENIED: return "UDS security access denied";
        case ErrorCode::UDS_INVALID_REQUEST: return "Invalid UDS request";
        case ErrorCode::SEED_GENERATION_FAILED: return "Failed to generate security seed";
        case ErrorCode::KEY_VERIFICATION_FAILED: return "Security key verification failed";
        case ErrorCode::INVALID_PARAMETER: return "Invalid parameter provided";
        case ErrorCode::NOT_INITIALIZED: return "Service not initialized";
        case ErrorCode::OPERATION_IN_PROGRESS: return "Another operation is already in progress";
        case ErrorCode::NOT_IMPLEMENTED: return "Operation not implemented";
        case ErrorCode::CONNECTION_FAILED: return "Failed to connect to service";
        case ErrorCode::PROV_NOT_CONFIGURED: return "PROV service has not configured VIN/ECU UID yet";
        case ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED: return "Software key file mode not allowed in production environment";
        case ErrorCode::TLS_CREDENTIAL_NOT_READY: return "MQTT TLS credential not ready";
        case ErrorCode::TLS_CREDENTIAL_INVALID: return "TLS credential invalid, expired or revoked";
        case ErrorCode::TLS_KEY_REF_INVALID: return "TLS private key reference invalid or expired";
        case ErrorCode::TLS_SIGN_ALGORITHM_NOT_ALLOWED: return "TLS signature algorithm or usage not allowed";
        case ErrorCode::TLS_HSM_SIGN_FAILED: return "HSM/SE TLS signing failed";
        case ErrorCode::ACL_DENIED: return "Caller not authorized for this profile";
        case ErrorCode::CONFIG_ERROR: return "Configuration error";
        case ErrorCode::INTERNAL_ERROR: return "Internal error";
        default: return "Unknown error";
    }
}

// ============================================================
// TLS 枚举与字符串互转（TBOX-SEC-DSN-CR-010）
// ============================================================

std::string tls_credential_status_to_string(TlsCredentialStatus s) {
    switch (s) {
        case TlsCredentialStatus::READY: return "READY";
        case TlsCredentialStatus::NOT_READY: return "NOT_READY";
        case TlsCredentialStatus::EXPIRED: return "EXPIRED";
        case TlsCredentialStatus::REVOKED: return "REVOKED";
        case TlsCredentialStatus::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

TlsCredentialStatus string_to_tls_credential_status(const std::string& s) {
    if (s == "READY") return TlsCredentialStatus::READY;
    if (s == "NOT_READY") return TlsCredentialStatus::NOT_READY;
    if (s == "EXPIRED") return TlsCredentialStatus::EXPIRED;
    if (s == "REVOKED") return TlsCredentialStatus::REVOKED;
    if (s == "ERROR") return TlsCredentialStatus::ERROR;
    return TlsCredentialStatus::NOT_READY;
}

std::string key_algorithm_to_string(KeyAlgorithm a) {
    switch (a) {
        case KeyAlgorithm::ECDSA_P256: return "ecdsa-p256";
        default: return "unknown";
    }
}

KeyAlgorithm string_to_key_algorithm(const std::string& s) {
    if (s == "ecdsa-p256") return KeyAlgorithm::ECDSA_P256;
    return KeyAlgorithm::UNKNOWN;
}

std::string signature_algorithm_to_string(SignatureAlgorithm a) {
    switch (a) {
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: return "ecdsa_secp256r1_sha256";
        default: return "unknown";
    }
}

SignatureAlgorithm string_to_signature_algorithm(const std::string& s) {
    if (s == "ecdsa_secp256r1_sha256") return SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    return SignatureAlgorithm::UNKNOWN;
}

} // namespace sec
} // namespace tbox

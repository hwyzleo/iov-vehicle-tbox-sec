#include "error_codes.h"

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
        case ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED: return "SOFT_KEY_MODE_NOT_ALLOWED";
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
        case ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED: return "Software key file mode not allowed in production environment";
        case ErrorCode::INTERNAL_ERROR: return "Internal error";
        default: return "Unknown error";
    }
}

} // namespace sec
} // namespace tbox

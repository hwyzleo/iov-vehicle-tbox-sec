#pragma once

#include <string>
#include <chrono>

namespace tbox {
namespace sec {

// Key algorithms
constexpr const char* KEY_ALGORITHM_ECDSA_P256 = "ecdsa-p256";
constexpr const char* KEY_ALGORITHM_ECDSA_P384 = "ecdsa-p384";
constexpr const char* KEY_ALGORITHM_RSA_2048 = "rsa-2048";

// Certificate settings
constexpr int DEFAULT_CERT_VALIDITY_YEARS = 10;
constexpr const char* DEFAULT_KEY_USAGE = "digitalSignature";
constexpr const char* DEFAULT_EXTENDED_KEY_USAGE = "clientAuth";

// CSR settings
constexpr const char* CSR_SUBJECT_CN_PREFIX = "ECU_UID:";
constexpr const char* CSR_SAN_TYPE_VIN = "VIN";
constexpr const char* CSR_SAN_TYPE_ECU_UID = "ECU_UID";

// Timeouts
constexpr auto DEFAULT_CLOUD_TIMEOUT = std::chrono::milliseconds(30000);
constexpr auto DEFAULT_RETRY_DELAY = std::chrono::milliseconds(1000);
constexpr int DEFAULT_RETRY_COUNT = 3;

// Storage paths
constexpr const char* DEFAULT_KEY_STORE_PATH = "/var/lib/tbox/sec/keys";
constexpr const char* DEFAULT_CERT_STORE_PATH = "/var/lib/tbox/sec/certs";
constexpr const char* DEFAULT_STATE_FILE_PATH = "/var/lib/tbox/sec/provision_state.json";

// UDS settings
constexpr uint8_t UDS_SECURITY_ACCESS_LEVEL = 0x29;
constexpr auto UDS_SESSION_TIMEOUT = std::chrono::milliseconds(5000);

// Key provisioning mode
constexpr const char* KEY_PROVISIONING_MODE_HSM = "hsm";
constexpr const char* KEY_PROVISIONING_MODE_SOFT_FILE = "soft_file";

// Software key file defaults
constexpr const char* DEFAULT_SOFT_KEY_PATH = "/var/lib/tbox/sec/soft_keys";
constexpr const char* DEFAULT_SOFT_KEY_ENC_ALGO = "aes-256-gcm";

// Error codes
constexpr const char* ERROR_CODE_PREFIX = "SEC-";

} // namespace sec
} // namespace tbox

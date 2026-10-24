//
// V2C 业务密钥公共类型实现（TBOX-SEC-DSN-CR-019）。
// 该实现同时被 TboxSecLib（daemon）与 tbox_sec_client（SDK）编译，
// 不依赖 OpenSSL / framework，仅使用标准库与显式清零。
//
#include "tbox/sec/business_key.h"

#include <cstring>
#include <utility>

namespace tbox {
namespace sec {

namespace {

/// 防优化清零（不依赖 OpenSSL，避免 client SDK 引入密码学依赖）。
void secure_zero_bytes(void* p, std::size_t n) {
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) {
        *v++ = 0;
    }
}

} // namespace

SecureBuffer::SecureBuffer(std::vector<uint8_t> data) : bytes_(std::move(data)) {}

SecureBuffer::~SecureBuffer() {
    clear();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : bytes_(std::move(other.bytes_)) {
    other.bytes_.clear();
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        clear();
        bytes_ = std::move(other.bytes_);
        other.bytes_.clear();
    }
    return *this;
}

void SecureBuffer::resize(std::size_t n) {
    bytes_.resize(n, 0);
}

void SecureBuffer::assign(const uint8_t* data, std::size_t n) {
    clear();
    if (data != nullptr && n > 0) {
        bytes_.assign(data, data + n);
    }
}

void SecureBuffer::assign(const std::vector<uint8_t>& data) {
    assign(data.data(), data.size());
}

void SecureBuffer::clear() {
    if (!bytes_.empty()) {
        secure_zero_bytes(bytes_.data(), bytes_.size());
        bytes_.clear();
    }
}

std::string business_key_state_to_string(BusinessKeyState s) {
    switch (s) {
        case BusinessKeyState::MISSING: return "MISSING";
        case BusinessKeyState::STAGED: return "STAGED";
        case BusinessKeyState::ACTIVE: return "ACTIVE";
        case BusinessKeyState::INVALID: return "INVALID";
        case BusinessKeyState::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

BusinessKeyState string_to_business_key_state(const std::string& s) {
    if (s == "MISSING") return BusinessKeyState::MISSING;
    if (s == "STAGED") return BusinessKeyState::STAGED;
    if (s == "ACTIVE") return BusinessKeyState::ACTIVE;
    if (s == "INVALID") return BusinessKeyState::INVALID;
    return BusinessKeyState::UNKNOWN;
}

std::string business_key_import_state_to_string(BusinessKeyImportState s) {
    switch (s) {
        case BusinessKeyImportState::REQUESTED: return "REQUESTED";
        case BusinessKeyImportState::STAGED: return "STAGED";
        case BusinessKeyImportState::COMMITTED: return "COMMITTED";
        case BusinessKeyImportState::FAILED: return "FAILED";
        case BusinessKeyImportState::UNKNOWN: return "UNKNOWN";
        case BusinessKeyImportState::NOT_FOUND: return "NOT_FOUND";
    }
    return "UNKNOWN";
}

BusinessKeyImportState string_to_business_key_import_state(const std::string& s) {
    if (s == "REQUESTED") return BusinessKeyImportState::REQUESTED;
    if (s == "STAGED") return BusinessKeyImportState::STAGED;
    if (s == "COMMITTED") return BusinessKeyImportState::COMMITTED;
    if (s == "FAILED") return BusinessKeyImportState::FAILED;
    if (s == "NOT_FOUND") return BusinessKeyImportState::NOT_FOUND;
    return BusinessKeyImportState::UNKNOWN;
}

// TBOX-SEC-DSN-CR-021 §2：NOT_FOUND 为 additive 数值（下一个未使用值）；
// 未知数值必须映射 UNKNOWN（禁止默认零值），不得重排/复用既有数值。
BusinessKeyImportState import_state_from_code(uint32_t code) {
    switch (code) {
        case static_cast<uint32_t>(BusinessKeyImportState::REQUESTED):
            return BusinessKeyImportState::REQUESTED;
        case static_cast<uint32_t>(BusinessKeyImportState::STAGED):
            return BusinessKeyImportState::STAGED;
        case static_cast<uint32_t>(BusinessKeyImportState::COMMITTED):
            return BusinessKeyImportState::COMMITTED;
        case static_cast<uint32_t>(BusinessKeyImportState::FAILED):
            return BusinessKeyImportState::FAILED;
        case static_cast<uint32_t>(BusinessKeyImportState::UNKNOWN):
            return BusinessKeyImportState::UNKNOWN;
        case static_cast<uint32_t>(BusinessKeyImportState::NOT_FOUND):
            return BusinessKeyImportState::NOT_FOUND;
        default:
            return BusinessKeyImportState::UNKNOWN;
    }
}

std::string key_envelope_format_to_string(KeyEnvelopeFormat f) {
    switch (f) {
        case KeyEnvelopeFormat::UNSPECIFIED: return "UNSPECIFIED";
        case KeyEnvelopeFormat::ECDH_ES_P256_V1: return kKeyEnvelopeFormatEcdhEsP256V1;
    }
    return "UNSPECIFIED";
}

KeyEnvelopeFormat string_to_key_envelope_format(const std::string& s) {
    if (s == kKeyEnvelopeFormatEcdhEsP256V1) return KeyEnvelopeFormat::ECDH_ES_P256_V1;
    return KeyEnvelopeFormat::UNSPECIFIED;
}

std::string business_key_import_phase_to_string(BusinessKeyImportPhase p) {
    switch (p) {
        case BusinessKeyImportPhase::NEW: return "NEW";
        case BusinessKeyImportPhase::VALIDATED: return "VALIDATED";
        case BusinessKeyImportPhase::PROCESSING: return "PROCESSING";
        case BusinessKeyImportPhase::UPLINK_STAGED: return "UPLINK_STAGED";
        case BusinessKeyImportPhase::BOTH_STAGED: return "BOTH_STAGED";
        case BusinessKeyImportPhase::COMMITTING: return "COMMITTING";
        case BusinessKeyImportPhase::SUCCEEDED: return "SUCCEEDED";
        case BusinessKeyImportPhase::ROLLING_BACK: return "ROLLING_BACK";
        case BusinessKeyImportPhase::FAILED: return "FAILED";
        case BusinessKeyImportPhase::OUTCOME_UNKNOWN: return "OUTCOME_UNKNOWN";
        case BusinessKeyImportPhase::RECOVERING: return "RECOVERING";
        case BusinessKeyImportPhase::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

BusinessKeyImportPhase string_to_business_key_import_phase(const std::string& s) {
    if (s == "NEW") return BusinessKeyImportPhase::NEW;
    if (s == "VALIDATED") return BusinessKeyImportPhase::VALIDATED;
    if (s == "PROCESSING") return BusinessKeyImportPhase::PROCESSING;
    if (s == "UPLINK_STAGED") return BusinessKeyImportPhase::UPLINK_STAGED;
    if (s == "BOTH_STAGED") return BusinessKeyImportPhase::BOTH_STAGED;
    if (s == "COMMITTING") return BusinessKeyImportPhase::COMMITTING;
    if (s == "SUCCEEDED") return BusinessKeyImportPhase::SUCCEEDED;
    if (s == "ROLLING_BACK") return BusinessKeyImportPhase::ROLLING_BACK;
    if (s == "FAILED") return BusinessKeyImportPhase::FAILED;
    if (s == "OUTCOME_UNKNOWN") return BusinessKeyImportPhase::OUTCOME_UNKNOWN;
    if (s == "RECOVERING") return BusinessKeyImportPhase::RECOVERING;
    return BusinessKeyImportPhase::UNKNOWN;
}

} // namespace sec
} // namespace tbox

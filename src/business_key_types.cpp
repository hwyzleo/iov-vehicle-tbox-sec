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
    }
    return "UNKNOWN";
}

BusinessKeyImportState string_to_business_key_import_state(const std::string& s) {
    if (s == "REQUESTED") return BusinessKeyImportState::REQUESTED;
    if (s == "STAGED") return BusinessKeyImportState::STAGED;
    if (s == "COMMITTED") return BusinessKeyImportState::COMMITTED;
    if (s == "FAILED") return BusinessKeyImportState::FAILED;
    return BusinessKeyImportState::UNKNOWN;
}

} // namespace sec
} // namespace tbox

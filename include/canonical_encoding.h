#pragma once

//
// CanonicalEncodingV1（TBOX-SEC-DSN-CR-020 §7）。
//
// 固定 length-prefix（unsigned uint32 big-endian）framing：
//   - string  -> UTF-8 内容 bytes；
//   - enum    -> 规范 unsigned varint；
//   - bytes   -> 原始内容；
//   - uint64  -> 固定 8 字节 unsigned big-endian。
// 每段的 value bytes 前再加 unsigned uint32 big-endian 长度前缀。
//
// 禁止使用 JSON、平台默认字符集、native struct 内存镜像或 protobuf 普通
// uint64 varint 替代本规则。
//
// Open item：FW-SEC `EnvelopeAadV1` 精确字节布局按本文件解释冻结，
// 待 FW-SEC test vector 交叉确认（见 specs/v2c-ecdh-es-keyprov/design.md §6）。
//

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace sec {
namespace canonical {

// ---- framing primitives ----

void appendUint32be(std::vector<uint8_t>& out, uint32_t v);

/// 追加 value bytes（8 字节 big-endian，不含长度前缀）。
void appendUint64be(std::vector<uint8_t>& out, uint64_t v);

/// 追加规范 unsigned varint（用于 enum value）。
void appendEnumVarint(std::vector<uint8_t>& out, uint64_t v);

/// 追加 uint32be(len) + content。
void appendLengthPrefixed(std::vector<uint8_t>& out, const std::vector<uint8_t>& content);
void appendString(std::vector<uint8_t>& out, const std::string& s);
void appendBytes(std::vector<uint8_t>& out, const uint8_t* p, std::size_t n);
void appendBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& v);

std::vector<uint8_t> uint64beBytes(uint64_t v);
std::vector<uint8_t> toBytes(const std::string& s);

// ---- digest / kcv ----

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> sha256(const std::string& s);

/// KCV = first_3_bytes(SHA-256(businessKey))（§7.3 / US-019）。
std::array<uint8_t, 3> computeKcv(const std::vector<uint8_t>& business_key);

/// 常量时间比较（长度须一致）。
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, std::size_t n);
bool constantTimeEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// ---- envelope digest（§7.1）----

struct EnvelopeDigestInput {
    uint64_t envelope_format = 0;   ///< KeyEnvelopeFormat enum value
    std::string request_id;
    std::string business_domain;
    uint64_t purpose = 0;           ///< KeyPurpose enum value
    std::string key_id;
    uint64_t business_key_version = 0;
    uint64_t wrapping_suite = 0;    ///< WrappingSuite enum value
    std::vector<uint8_t> wrapped_key;
    std::vector<uint8_t> parameters;
};

std::vector<uint8_t> computeEnvelopeDigest(const EnvelopeDigestInput& in);

// ---- AAD（EnvelopeAadV1，§7.2）----

struct EnvelopeAadInput {
    std::string envelope_version;                            ///< "v1"
    uint64_t wrapping_suite = 0;
    std::string request_id;
    std::string business_domain;
    uint64_t purpose = 0;
    std::string key_id;
    uint64_t business_key_version = 0;
    uint64_t root_key_version = 0;
    std::string derivation_version;
    std::vector<uint8_t> recipient_certificate_fingerprint;  ///< raw digest bytes
};

std::vector<uint8_t> buildEnvelopeAadV1(const EnvelopeAadInput& in);
std::vector<uint8_t> computeAadDigest(const std::vector<uint8_t>& canonical_aad);

// ---- import proof（§7.3）----

struct ProofInput {
    std::string request_id;
    std::string business_domain;
    uint64_t purpose = 0;
    std::string key_id;                        ///< 内部取 SHA-256(UTF8(keyId))
    uint64_t business_key_version = 0;
    std::vector<uint8_t> envelope_digest;
    std::vector<uint8_t> key_check_value;
};

std::vector<uint8_t> buildProofInput(const ProofInput& in);

// ---- HKDF info（FW-SEC-DSN-CR-014 §3.2）----

std::string buildHkdfInfoV1(const std::string& request_id, const std::string& business_domain,
                            const std::string& purpose_name, const std::string& key_id,
                            uint64_t business_key_version,
                            const std::string& recipient_fingerprint_hex_lower);

// ---- helpers ----

std::string toHex(const uint8_t* p, std::size_t n);
std::string toHex(const std::vector<uint8_t>& v);
bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out);

} // namespace canonical
} // namespace sec
} // namespace tbox

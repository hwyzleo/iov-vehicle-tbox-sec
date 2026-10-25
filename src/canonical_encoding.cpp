//
// CanonicalEncodingV1 实现（TBOX-SEC-DSN-CR-022 §3 / VEH-PROTO §7.2.2）。
//
#include "canonical_encoding.h"

#include "tbox/sec/business_key.h"  // kProofContextV1

#include <openssl/crypto.h>
#include <openssl/sha.h>

namespace tbox {
namespace sec {
namespace canonical {

void appendUint32be(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

void appendUint64be(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
    }
}

void appendEnumVarint(std::vector<uint8_t>& out, uint64_t v) {
    while (true) {
        uint8_t b = static_cast<uint8_t>(v & 0x7f);
        v >>= 7;
        if (v != 0) {
            out.push_back(static_cast<uint8_t>(b | 0x80));
        } else {
            out.push_back(b);
            break;
        }
    }
}

void appendLengthPrefixed(std::vector<uint8_t>& out, const std::vector<uint8_t>& content) {
    appendUint32be(out, static_cast<uint32_t>(content.size()));
    out.insert(out.end(), content.begin(), content.end());
}

void appendString(std::vector<uint8_t>& out, const std::string& s) {
    appendUint32be(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

void appendBytes(std::vector<uint8_t>& out, const uint8_t* p, std::size_t n) {
    appendUint32be(out, static_cast<uint32_t>(n));
    if (p != nullptr && n > 0) out.insert(out.end(), p, p + n);
}

void appendBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    appendBytes(out, v.data(), v.size());
}

std::vector<uint8_t> uint64beBytes(uint64_t v) {
    std::vector<uint8_t> out;
    out.reserve(8);
    appendUint64be(out, v);
    return out;
}

std::vector<uint8_t> toBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> d(SHA256_DIGEST_LENGTH);
    SHA256(data.empty() ? nullptr : data.data(), data.size(), d.data());
    return d;
}

std::vector<uint8_t> sha256(const std::string& s) {
    return sha256(toBytes(s));
}

std::array<uint8_t, 3> computeKcv(const std::vector<uint8_t>& business_key) {
    std::vector<uint8_t> d = sha256(business_key);
    return {d[0], d[1], d[2]};
}

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, std::size_t n) {
    if (a == nullptr || b == nullptr) return false;
    return CRYPTO_memcmp(a, b, n) == 0;
}

bool constantTimeEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return constantTimeEqual(a.data(), b.data(), a.size());
}

namespace {

void appendEnumSegment(std::vector<uint8_t>& out, uint64_t v) {
    std::vector<uint8_t> seg;
    appendEnumVarint(seg, v);
    appendLengthPrefixed(out, seg);
}

void appendUint64beSegment(std::vector<uint8_t>& out, uint64_t v) {
    appendLengthPrefixed(out, uint64beBytes(v));
}

} // namespace

std::vector<uint8_t> buildWireEnvelopeDigestV1(const EnvelopeDigestInput& in) {
    // PAR_PROTO_KEYPROV_ECDH_ES_P256_V1：共且仅有 9 个顶层 segment。
    std::vector<uint8_t> buf;
    appendEnumSegment(buf, in.envelope_format);
    appendString(buf, in.request_id);
    appendString(buf, in.business_domain);
    appendEnumSegment(buf, in.purpose);
    appendString(buf, in.key_id);
    appendUint64beSegment(buf, in.business_key_version);
    appendEnumSegment(buf, in.wrapping_suite);
    appendBytes(buf, in.wrapped_key);
    appendBytes(buf, in.parameters);
    return sha256(buf);
}

std::vector<uint8_t> buildParProtoAadV1(const EnvelopeAadInput& in) {
    // PAR_PROTO_KEYPROV_AAD_V1：固定 10 段（uint32be 长度前缀）；nonce 不进入 AAD。
    std::vector<uint8_t> buf;
    appendEnumSegment(buf, in.envelope_format);
    appendEnumSegment(buf, in.wrapping_suite);
    appendEnumSegment(buf, in.purpose);
    appendUint64beSegment(buf, in.business_key_version);
    appendUint64beSegment(buf, in.root_key_version);
    appendBytes(buf, in.recipient_certificate_digest);
    appendString(buf, in.request_id);
    appendString(buf, in.business_domain);
    appendString(buf, in.key_id);
    appendString(buf, in.derivation_version);
    return buf;
}

std::vector<uint8_t> computeAadDigest(const std::vector<uint8_t>& canonical_aad) {
    return sha256(canonical_aad);
}

std::vector<uint8_t> buildProofInput(const ProofInput& in) {
    std::vector<uint8_t> buf;
    appendString(buf, kProofContextV1);
    appendString(buf, in.request_id);
    appendString(buf, in.business_domain);
    appendEnumSegment(buf, in.purpose);
    appendBytes(buf, sha256(toBytes(in.key_id)));
    appendUint64beSegment(buf, in.business_key_version);
    appendBytes(buf, in.envelope_digest);
    appendBytes(buf, in.key_check_value);
    return buf;
}

std::string buildHkdfInfoV1(const std::string& request_id, const std::string& business_domain,
                            const std::string& purpose_name, const std::string& key_id,
                            uint64_t business_key_version,
                            const std::string& recipient_fingerprint_hex_lower) {
    return std::string("openiov|keyprov-wrap|v1|") + request_id + "|" + business_domain + "|" +
           purpose_name + "|" + key_id + "|" + std::to_string(business_key_version) + "|" +
           recipient_fingerprint_hex_lower;
}

std::string toHex(const uint8_t* p, std::size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(digits[p[i] >> 4]);
        out.push_back(digits[p[i] & 0x0f]);
    }
    return out;
}

std::string toHex(const std::vector<uint8_t>& v) { return toHex(v.data(), v.size()); }

bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

} // namespace canonical
} // namespace sec
} // namespace tbox

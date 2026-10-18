//
// EnvelopeValidator + ECDH-ES v1 参数解析实现（TBOX-SEC-DSN-CR-020 §5/§6/§7）。
//
#include "business_key_envelope.h"

#include "proto/security/keyprov/v1/key_provisioning.pb.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <cstring>

namespace tbox {
namespace sec {

namespace {

namespace kp = ::security::keyprov::v1;

using canonical::constantTimeEqual;
using canonical::sha256;

bool isHexLowerNonEmpty(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

} // namespace

bool purposeEnumValue(const std::string& purpose, uint64_t& out) {
    if (purpose == kBusinessPurposeUplinkAead) {
        out = kp::KEY_PURPOSE_UPLINK_AEAD;
        return true;
    }
    if (purpose == kBusinessPurposeDownlinkAead) {
        out = kp::KEY_PURPOSE_DOWNLINK_AEAD;
        return true;
    }
    return false;
}

bool wrappingSuiteEnumValue(const std::string& suite, uint64_t& out) {
    if (suite == kWrappingSuiteEcdhEsP256) {
        out = kp::WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM;
        return true;
    }
    return false;
}

bool isValidP256UncompressedPoint(const std::vector<uint8_t>& point) {
    if (point.size() != 65 || point[0] != 0x04) return false;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return false;
    bool ok = false;
    EC_POINT* pt = EC_POINT_new(group);
    if (pt != nullptr && EC_POINT_oct2point(group, pt, point.data(), point.size(), nullptr) == 1) {
        // 非无穷点 + 在曲线上
        if (!EC_POINT_is_at_infinity(group, pt) &&
            EC_POINT_is_on_curve(group, pt, nullptr) == 1) {
            ok = true;
        }
    }
    if (pt) EC_POINT_free(pt);
    EC_GROUP_free(group);
    return ok;
}

ErrorCode parseEcdhEsP256Parameters(const uint8_t* data, std::size_t n,
                                    EcdhEsP256EnvelopeParameters& out) {
    if (data == nullptr || n == 0) return ErrorCode::WRAPPED_KEY_INVALID;
    kp::EcdhEsP256EnvelopeParametersV1 msg;
    if (!msg.ParseFromArray(data, static_cast<int>(n))) return ErrorCode::WRAPPED_KEY_INVALID;

    // 规范形式回写校验：parameters 必须是 deterministic serialization。
    std::string reserialized;
    if (!msg.SerializeToString(&reserialized)) return ErrorCode::WRAPPED_KEY_INVALID;
    if (reserialized.size() != n ||
        std::memcmp(reserialized.data(), data, n) != 0) {
        return ErrorCode::WRAPPED_KEY_INVALID;
    }

    out.format_version = msg.format_version();
    out.server_ephemeral_public_key.assign(msg.server_ephemeral_public_key().begin(),
                                           msg.server_ephemeral_public_key().end());
    out.hkdf_salt.assign(msg.hkdf_salt().begin(), msg.hkdf_salt().end());
    out.hkdf_context_version = msg.hkdf_context_version();
    out.nonce.assign(msg.nonce().begin(), msg.nonce().end());
    out.authentication_tag.assign(msg.authentication_tag().begin(),
                                  msg.authentication_tag().end());
    out.canonical_aad.assign(msg.canonical_aad().begin(), msg.canonical_aad().end());
    out.aad_digest.assign(msg.aad_digest().begin(), msg.aad_digest().end());
    out.root_key_version = msg.root_key_version();
    out.derivation_version = msg.derivation_version();
    out.recipient_certificate_digest.assign(msg.recipient_certificate_digest().begin(),
                                            msg.recipient_certificate_digest().end());
    out.operation_id = msg.operation_id();
    return ErrorCode::SUCCESS;
}

std::vector<uint8_t> rebuildEnvelopeAad(const std::string& request_id,
                                        const std::string& business_domain,
                                        const WrappedKeyItem& item,
                                        const EcdhEsP256EnvelopeParameters& params) {
    canonical::EnvelopeAadInput aad;
    aad.envelope_version = "v1";
    uint64_t suite_val = 0;
    wrappingSuiteEnumValue(item.wrapping_suite, suite_val);
    aad.wrapping_suite = suite_val;
    aad.request_id = request_id;
    aad.business_domain = business_domain;
    uint64_t purpose_val = 0;
    purposeEnumValue(item.purpose, purpose_val);
    aad.purpose = purpose_val;
    aad.key_id = item.key_id;
    aad.business_key_version = item.business_key_version;
    aad.root_key_version = params.root_key_version;
    aad.derivation_version = params.derivation_version;
    aad.recipient_certificate_fingerprint = params.recipient_certificate_digest;
    return canonical::buildEnvelopeAadV1(aad);
}

ErrorCode validateEnvelope(const WrappedKeyItem& item,
                           const EnvelopeContext& ctx,
                           const EnvelopeLimits& limits,
                           ValidatedEnvelope& out) {
    // §6.2 format / suite / 算法 allowlist（首期仅 ECDH_ES_P256_V1）
    if (item.envelope_format != KeyEnvelopeFormat::ECDH_ES_P256_V1)
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    uint64_t suite_val = 0;
    if (!wrappingSuiteEnumValue(item.wrapping_suite, suite_val))
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    if (item.algorithm != kDefaultKeyAlgorithm) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

    // §6.3 parameters 解析 + 长度上限
    if (item.parameters.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
    if (item.parameters.size() > limits.max_parameters) return ErrorCode::WRAPPED_KEY_INVALID;
    EcdhEsP256EnvelopeParameters params;
    ErrorCode rc = parseEcdhEsP256Parameters(item.parameters.data(), item.parameters.size(), params);
    if (rc != ErrorCode::SUCCESS) return rc;
    if (params.format_version != 1) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.hkdf_context_version != kDefaultHkdfContextVersion)
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

    // 长度上限（PAR-PROTO §7）
    if (item.wrapped_key.empty() || item.wrapped_key.size() > limits.max_wrapped_key)
        return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.canonical_aad.size() > limits.max_canonical_aad)
        return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.hkdf_salt.size() != 32) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.nonce.size() != 12) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.authentication_tag.size() != 16) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.aad_digest.size() != 32) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.recipient_certificate_digest.size() != 32) return ErrorCode::WRAPPED_KEY_INVALID;

    // §6.4 临时公钥校验
    if (!isValidP256UncompressedPoint(params.server_ephemeral_public_key))
        return ErrorCode::WRAPPED_KEY_INVALID;

    // §6.5 证书能力门禁（ACTIVE 证书 P-256 + keyAgreement + 私钥 derive）
    if (!ctx.active_cert_p256 || !ctx.active_cert_key_agreement || !ctx.private_key_can_derive)
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (ctx.active_cert_digest.size() != params.recipient_certificate_digest.size() ||
        !constantTimeEqual(ctx.active_cert_digest, params.recipient_certificate_digest))
        return ErrorCode::WRAPPED_KEY_INVALID;

    // §6.6 AAD 重建与比对
    std::vector<uint8_t> aad = rebuildEnvelopeAad(ctx.request_id, ctx.business_domain, item, params);
    if (!constantTimeEqual(aad, params.canonical_aad)) return ErrorCode::WRAPPED_KEY_INVALID;
    if (!constantTimeEqual(sha256(aad), params.aad_digest)) return ErrorCode::WRAPPED_KEY_INVALID;

    // §6.7 envelopeDigest 重算（以收到的原始 wrappedKey + parameters）
    canonical::EnvelopeDigestInput di;
    di.envelope_format = static_cast<uint64_t>(KeyEnvelopeFormat::ECDH_ES_P256_V1);
    di.request_id = ctx.request_id;
    di.business_domain = ctx.business_domain;
    uint64_t purpose_val = 0;
    if (!purposeEnumValue(item.purpose, purpose_val)) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    di.purpose = purpose_val;
    di.key_id = item.key_id;
    di.business_key_version = item.business_key_version;
    di.wrapping_suite = suite_val;
    di.wrapped_key.assign(item.wrapped_key.data(), item.wrapped_key.data() + item.wrapped_key.size());
    di.parameters.assign(item.parameters.data(), item.parameters.data() + item.parameters.size());
    std::vector<uint8_t> computed = canonical::computeEnvelopeDigest(di);
    if (item.envelope_digest.size() != computed.size() ||
        !constantTimeEqual(item.envelope_digest, computed))
        return ErrorCode::WRAPPED_KEY_INVALID;

    // §6.8 版本/operationId
    if (item.business_key_version == 0 ||
        item.business_key_version > ((1ULL << 63) - 1))
        return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.root_key_version == 0) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.derivation_version.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
    if (params.operation_id.empty()) return ErrorCode::WRAPPED_KEY_INVALID;

    out.params = std::move(params);
    out.canonical_aad = std::move(aad);
    out.envelope_digest = std::move(computed);
    // KCV 由 provider 在 staging 计算并校验；此处仅透传期望值（供 provider 比较）。
    out.key_check_value = item.key_check_value;
    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox

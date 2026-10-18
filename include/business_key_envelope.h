#pragma once

//
// EnvelopeValidator + ECDH-ES v1 参数解析（TBOX-SEC-DSN-CR-020 §5/§6/§7）。
//
// `parameters` 为 EcdhEsP256EnvelopeParametersV1 的 deterministic Protobuf bytes；
// 解析使用 proto/security/keyprov/v1/key_provisioning.proto 生成的代码，
// 禁止手写字段 1~12 的 wire codec。
//
// 本模块只做校验与解析，不执行任何密码操作。
//

#include "canonical_encoding.h"
#include "error_codes.h"
#include "tbox/sec/business_key.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

/// EcdhEsP256EnvelopeParametersV1 的 typed 形式（仅用于验证与安全调用）。
struct EcdhEsP256EnvelopeParameters {
    uint32_t format_version = 0;                        ///< MUST == 1
    std::vector<uint8_t> server_ephemeral_public_key;   ///< 65B SEC1 uncompressed
    std::vector<uint8_t> hkdf_salt;                     ///< 32B
    std::string hkdf_context_version;                   ///< "v1"
    std::vector<uint8_t> nonce;                         ///< 12B
    std::vector<uint8_t> authentication_tag;            ///< 16B
    std::vector<uint8_t> canonical_aad;                 ///< <= 1KiB
    std::vector<uint8_t> aad_digest;                    ///< 32B
    uint64_t root_key_version = 0;
    std::string derivation_version;
    std::vector<uint8_t> recipient_certificate_digest;  ///< 32B
    std::string operation_id;
};

/// 信封字段长度上限（PAR-PROTO-DSN-CR-007 §7）。
struct EnvelopeLimits {
    std::size_t max_canonical_aad = 1024;
    std::size_t max_parameters = 2048;
    std::size_t max_wrapped_key = 4096;
};

/// 解封前校验所需的外层上下文（由 SEC 依据本地请求与 ACTIVE 证书构建）。
struct EnvelopeContext {
    std::string request_id;
    std::string business_domain;
    std::string purpose;              ///< "UPLINK_AEAD"/"DOWNLINK_AEAD"
    std::vector<uint8_t> active_cert_digest;  ///< 当前 ACTIVE 证书策略摘要（raw）
    bool active_cert_p256 = false;
    bool active_cert_key_agreement = false;
    bool private_key_can_derive = false;
};

/// 校验通过后的解析结果（原始 bytes 仍由 item.parameters 保留）。
struct ValidatedEnvelope {
    EcdhEsP256EnvelopeParameters params;
    std::vector<uint8_t> canonical_aad;    ///< 由外层上下文重建
    std::vector<uint8_t> envelope_digest;  ///< 重算值
    std::array<uint8_t, 3> key_check_value;
};

/// 用途字符串 -> KeyPurpose enum value；未知返回 false。
bool purposeEnumValue(const std::string& purpose, uint64_t& out);
/// 套件字符串 -> WrappingSuite enum value；未知返回 false。
bool wrappingSuiteEnumValue(const std::string& suite, uint64_t& out);

/// 解析 deterministic Protobuf parameters（生成代码 + 规范形式回写校验）。
/// 失败：WRAPPED_KEY_INVALID（不可解析 / 非规范 bytes / format_version 非 1）。
ErrorCode parseEcdhEsP256Parameters(const uint8_t* data, std::size_t n,
                                    EcdhEsP256EnvelopeParameters& out);

/// P-256 SEC1 uncompressed 点校验：恰 65B、首字节 0x04、在曲线上、非无穷点。
bool isValidP256UncompressedPoint(const std::vector<uint8_t>& point);

/// 解封前校验流水线（DSN §6 步骤 2~8）。任何失败均不执行密码操作。
ErrorCode validateEnvelope(const WrappedKeyItem& item,
                           const EnvelopeContext& ctx,
                           const EnvelopeLimits& limits,
                           ValidatedEnvelope& out);

/// 依据外层上下文重建 canonical AAD（供 provider 与测试复用）。
std::vector<uint8_t> rebuildEnvelopeAad(const std::string& request_id,
                                        const std::string& business_domain,
                                        const WrappedKeyItem& item,
                                        const EcdhEsP256EnvelopeParameters& params);

} // namespace sec
} // namespace tbox

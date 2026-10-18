#pragma once

//
// 非生产参考实现：ECDH-ES P-256 v1 信封封装（TBOX-SEC-DSN-CR-020 §7/§8）。
//
// 仅供测试与跨端向量生成使用，等价 FW-SEC Provider 的封装方向；不得成为
// 量产成功路径（量产侧由云端 Provider 执行封装）。
//
// 固定 serverEphemeralPrivateKey / hkdfSalt / nonce 时输出字节级确定，
// 用于冻结 golden vectors（tests/fixtures/keyprov_ecdh_es_v1_vector.json）。
//

#include "canonical_encoding.h"
#include "error_codes.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

struct KeyprovEnvelopeInput {
    std::vector<uint8_t> device_public_key;             ///< 65B SEC1 uncompressed
    std::string request_id;
    std::string business_domain = "V2C_COMM";
    std::string purpose;                                ///< "UPLINK_AEAD"/"DOWNLINK_AEAD"
    std::string key_id;
    uint64_t business_key_version = 0;
    std::vector<uint8_t> business_key;                  ///< 32B plaintext
    uint64_t root_key_version = 1;
    std::string derivation_version = "v1";
    std::string operation_id;
    std::vector<uint8_t> recipient_certificate_digest;  ///< 32B
    std::string wrapping_suite = "ECDH_ES_P256_HKDF_SHA256_AES256GCM";
    std::string key_algorithm = "AES-256";
    std::string hkdf_context_version = "v1";
    // 确定性（测试向量）可选；为空则随机生成。
    std::vector<uint8_t> server_ephemeral_private_key;  ///< 32B
    std::vector<uint8_t> hkdf_salt;                     ///< 32B
    std::vector<uint8_t> nonce;                         ///< 12B
};

struct KeyprovEnvelopeOutput {
    std::vector<uint8_t> wrapped_key;              ///< AES-GCM ciphertext only
    std::vector<uint8_t> parameters;               ///< deterministic protobuf bytes
    std::vector<uint8_t> envelope_digest;          ///< 32B
    std::array<uint8_t, 3> key_check_value{};
    // 诊断/向量字段（非秘密派生材料，仅测试向量断言使用）
    std::vector<uint8_t> canonical_aad;
    std::vector<uint8_t> aad_digest;
    std::vector<uint8_t> server_ephemeral_public_key;
    std::vector<uint8_t> hkdf_info;
    std::vector<uint8_t> ecdh_shared_secret;
    std::vector<uint8_t> kek;
    std::vector<uint8_t> proof_input;
    std::vector<uint8_t> authentication_tag;
};

/// 非生产：封装 ECDH-ES P-256 v1 信封。失败返回非 SUCCESS。
ErrorCode buildEcdhEsP256EnvelopeV1(const KeyprovEnvelopeInput& in,
                                    KeyprovEnvelopeOutput& out);

} // namespace sec
} // namespace tbox

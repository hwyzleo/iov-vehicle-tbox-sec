#pragma once

//
// V2C 密钥开通能力上报（TBOX-SEC-DSN-CR-020 §11 / US-022）。
//
// READY = 以下全部合取。任一缺失时仅允许状态查询/诊断，不接受新信封。
// PKI 未签发兼容 `keyAgreement` 证书时，代码/测试可发布，但 capability 不上报 v1、
// 导入返回 BUSINESS_KEY_NOT_READY。
//

namespace tbox {
namespace sec {

struct V2cKeyProvisioningCapability {
    bool proto_release_matched = false;          ///< PAR-PROTO release/DescriptorSet 锁定已安装
    bool envelope_format_v1 = false;             ///< 本构建已实现 ECDH_ES_P256_V1
    bool p256_ecdh = false;                      ///< HSM/eSE 支持 P-256 ECDH
    bool hkdf_sha256 = false;                    ///< HSM/eSE 支持 HKDF-SHA-256
    bool aes256_gcm_decrypt_to_slot = false;     ///< 支持 AES-256-GCM decrypt-to-slot
    bool atomic_dual_slot_commit = false;        ///< 支持双槽原子提交
    bool active_certificate_key_agreement = false;  ///< ACTIVE 证书 KU 含 keyAgreement
    bool active_private_key_can_derive = false;  ///< 私钥句柄支持 ECDH derive（不可导出）
    bool secure_journal_ready = false;           ///< 安全 journal / ledger 可用
    bool proof_key_ready = false;                ///< import proof 生成密钥可用
    bool trusted_time_ready = false;             ///< 可信时间可用

    bool all() const {
        return proto_release_matched && envelope_format_v1 && p256_ecdh && hkdf_sha256 &&
               aes256_gcm_decrypt_to_slot && atomic_dual_slot_commit &&
               active_certificate_key_agreement && active_private_key_can_derive &&
               secure_journal_ready && proof_key_ready && trusted_time_ready;
    }
};

} // namespace sec
} // namespace tbox

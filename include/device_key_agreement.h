#pragma once

//
// DeviceKeyAgreementAdapter（TBOX-SEC-DSN-CR-020 §5 / US-016）。
//
// 解析当前 ACTIVE 设备证书，判定其是否可作为 ECDH 解封装 + Import Attestation 身份：
//   - 预期终端实体 leaf（由 CertificateChainParser 保证 leaf-first）；
//   - 公钥为允许的 P-256 EC；
//   - X.509 KeyUsage 同时含 keyAgreement + digitalSignature（US-016）；
//   - EKU 仅含 clientAuth（拒绝 anyExtendedKeyUsage / serverAuth / 其他 EKU，CR-020 §2.1）；
//   - 终端实体判定：BasicConstraints 缺失或明确 CA=false 均可（不得要求扩展必须显式存在）；
//   - 关键扩展满足 allowlist，未知关键扩展 fail-closed（CR-020 §2.1/§11）；
//   - 逻辑 Profile TBOX_DEVICE_ECDH_ES_P256_V1 匹配（P-256 + 双 KU + clientAuth-only + CA=false）；
//   - 链/证书公钥与本地句柄公钥匹配；
//   - 证书摘要（SHA-256(original leaf DER 字节)，非重编码口径）用于 recipient_certificate_digest 比对；
//   - 对应同一私钥存在，且策略同时允许 ECDH derive 与 ECDSA sign。
//
// 仅有 digitalSignature/仅有 keyAgreement、Profile/关键扩展/CA=false 不满足，或句柄只具备
// sign/derive 之一，SHALL 判定为能力未就绪，且不得调用安全硬件。
//
// Open item：recipient_certificate_digest 的 DER/SPKI 口径按 SHA-256(original leaf DER)
// 冻结，待 FW-SEC test vector / PKI Profile 交叉确认
// （见 specs/v2c-ecdh-es-keyprov/design.md §4）。
//

#include "certificate_store.h"
#include "hsm_interface.h"

#include <openssl/x509.h>

#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

struct DeviceKeyAgreementCapability {
    bool active_cert_present = false;
    bool p256 = false;
    bool key_agreement = false;
    bool digital_signature = false;
    bool private_key_exists = false;
    bool private_key_can_derive = false;
    bool private_key_can_sign = false;
    std::vector<uint8_t> certificate_digest;  ///< SHA-256(original leaf DER 字节)

    // ---- TBOX-SEC-DSN-CR-020 §2.1/§11 修订门禁 ----
    bool ca_false = false;                    ///< 终端实体（BC 缺失或 CA=false）
    bool eku_client_auth_only = false;        ///< EKU 仅 clientAuth（无 anyEKU/serverAuth/其他）
    bool critical_extensions_allowed = false; ///< 关键扩展满足 allowlist（未知关键扩展 fail-closed）
    bool leaf_digest_bound = false;           ///< 原始 leaf DER 摘要已绑定（非空且覆盖 leaf）
    bool cert_chain_key_match = false;        ///< leaf 公钥与本地私钥句柄公钥匹配
    bool profile_matched = false;             ///< 逻辑 Profile TBOX_DEVICE_ECDH_ES_P256_V1 合取

    /// Profile 合取（§2.1：CA=false + P-256 + 双 KU + clientAuth-only + 关键扩展）
    bool profileOk() const {
        return ca_false && p256 && key_agreement && digital_signature &&
               eku_client_auth_only && critical_extensions_allowed;
    }
};

class DeviceKeyAgreementAdapter {
public:
    DeviceKeyAgreementAdapter(CertificateStore* cert_store,
                              HsmInterface* hsm,
                              std::string device_key_id);

    /// 探测当前能力（只读，不执行 ECDH/签名）。
    DeviceKeyAgreementCapability probe() const;

    /// 静态工具：X.509 KeyUsage 是否含 keyAgreement。
    static bool hasKeyUsageKeyAgreement(X509* cert);
    /// 静态工具：X.509 KeyUsage 是否含 digitalSignature。
    static bool hasKeyUsageDigitalSignature(X509* cert);
    /// 静态工具：公钥是否为 P-256 EC。
    static bool isP256PublicKey(X509* cert);

private:
    CertificateStore* cert_store_;
    HsmInterface* hsm_;
    std::string device_key_id_;
};

} // namespace sec
} // namespace tbox

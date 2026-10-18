#pragma once

//
// DeviceKeyAgreementAdapter（TBOX-SEC-DSN-CR-020 §5 / US-016）。
//
// 解析当前 ACTIVE 设备证书，判定其是否可作为 ECDH 解封装身份：
//   - 预期终端实体 leaf（由 CertificateChainParser 保证 leaf-first）；
//   - 公钥为允许的 P-256 EC；
//   - X.509 KeyUsage 含 keyAgreement；
//   - 证书摘要（SHA-256(leaf DER)）用于 recipient_certificate_digest 比对；
//   - 对应私钥存在且策略允许 ECDH derive。
//
// 仅有 digitalSignature 的证书 SHALL 判定为能力未就绪，且不得调用安全硬件。
//
// Open item：recipient_certificate_digest 的 DER/SPKI 口径按 SHA-256(leaf DER)
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
    bool private_key_exists = false;
    bool private_key_can_derive = false;
    std::vector<uint8_t> certificate_digest;  ///< SHA-256(leaf DER)
};

class DeviceKeyAgreementAdapter {
public:
    DeviceKeyAgreementAdapter(CertificateStore* cert_store,
                              HsmInterface* hsm,
                              std::string device_key_id);

    /// 探测当前能力（只读，不执行 ECDH）。
    DeviceKeyAgreementCapability probe() const;

    /// 静态工具：X.509 KeyUsage 是否含 keyAgreement。
    static bool hasKeyUsageKeyAgreement(X509* cert);
    /// 静态工具：公钥是否为 P-256 EC。
    static bool isP256PublicKey(X509* cert);

private:
    CertificateStore* cert_store_;
    HsmInterface* hsm_;
    std::string device_key_id_;
};

} // namespace sec
} // namespace tbox

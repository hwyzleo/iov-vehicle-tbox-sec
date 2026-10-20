//
// DeviceKeyAgreementAdapter 实现（TBOX-SEC-DSN-CR-020 §5 / US-016）。
//
#include "device_key_agreement.h"

#include "certificate_chain_parser.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>

namespace tbox {
namespace sec {

DeviceKeyAgreementAdapter::DeviceKeyAgreementAdapter(CertificateStore* cert_store,
                                                     HsmInterface* hsm,
                                                     std::string device_key_id)
    : cert_store_(cert_store), hsm_(hsm), device_key_id_(std::move(device_key_id)) {}

bool DeviceKeyAgreementAdapter::hasKeyUsageKeyAgreement(X509* cert) {
    if (cert == nullptr) return false;
    ASN1_BIT_STRING* usage = static_cast<ASN1_BIT_STRING*>(
        X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));
    if (usage == nullptr) return false;
    bool ok = false;
    if (usage->length > 0) {
        ok = (usage->data[0] & KU_KEY_AGREEMENT) != 0;
    }
    ASN1_BIT_STRING_free(usage);
    return ok;
}

bool DeviceKeyAgreementAdapter::hasKeyUsageDigitalSignature(X509* cert) {
    if (cert == nullptr) return false;
    ASN1_BIT_STRING* usage = static_cast<ASN1_BIT_STRING*>(
        X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));
    if (usage == nullptr) return false;
    bool ok = false;
    if (usage->length > 0) {
        ok = (usage->data[0] & KU_DIGITAL_SIGNATURE) != 0;
    }
    ASN1_BIT_STRING_free(usage);
    return ok;
}

bool DeviceKeyAgreementAdapter::isP256PublicKey(X509* cert) {
    if (cert == nullptr) return false;
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey == nullptr) return false;
    bool ok = false;
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec != nullptr) {
            const EC_GROUP* group = EC_KEY_get0_group(ec);
            if (group != nullptr &&
                EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1) {
                ok = true;
            }
            EC_KEY_free(ec);
        }
    }
    EVP_PKEY_free(pkey);
    return ok;
}

namespace {

// 终端实体判定（CR-020 §2.1）：BasicConstraints 缺失或明确 CA=false 均可；
// 仅当 basicConstraints 显式存在且 ca=TRUE 时才算非终端实体。
bool isCaTrue(const X509* cert) {
    BASIC_CONSTRAINTS* bc = static_cast<BASIC_CONSTRAINTS*>(
        X509_get_ext_d2i(const_cast<X509*>(cert), NID_basic_constraints, nullptr, nullptr));
    if (bc == nullptr) return false;  // 缺失：终端实体
    const bool ca = (bc->ca != 0);
    BASIC_CONSTRAINTS_free(bc);
    return ca;
}

// EKU 仅 clientAuth（CR-020 §2.1：拒绝 anyExtendedKeyUsage、serverAuth 与任何其他 EKU）。
// 要求 EKU 扩展存在、含 clientAuth 且不含其他用途。
bool hasOnlyClientAuthEku(const X509* cert) {
    EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(
        X509_get_ext_d2i(const_cast<X509*>(cert), NID_ext_key_usage, nullptr, nullptr));
    if (eku == nullptr) return false;
    if (sk_ASN1_OBJECT_num(eku) <= 0) {  // 空 EKU 不满足“仅 clientAuth”
        EXTENDED_KEY_USAGE_free(eku);
        return false;
    }
    ASN1_OBJECT* client_auth = OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1);
    bool ok = false;
    if (client_auth != nullptr) {
        ok = true;  // 存在即为首项判定基础；下面逐项检查是否只含 clientAuth
        for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
            ASN1_OBJECT* o = sk_ASN1_OBJECT_value(eku, i);
            if (OBJ_cmp(o, client_auth) != 0) {
                ok = false;  // 出现任何非 clientAuth 用途 → 拒绝
                break;
            }
        }
        ASN1_OBJECT_free(client_auth);
    }
    EXTENDED_KEY_USAGE_free(eku);
    return ok;
}

// 关键扩展 allowlist（CR-020 §2.1/§11）：仅允许标准 RFC 5280 设备 profile 扩展以
// 关键方式出现；未知/未经允许的关键扩展 fail-closed。
bool criticalExtensionsAllowed(const X509* cert) {
    if (cert == nullptr) return false;
    const STACK_OF(X509_EXTENSION)* exts = X509_get0_extensions(const_cast<X509*>(cert));
    if (exts == nullptr) return true;  // 无扩展：无关键扩展需门禁
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        if (!X509_EXTENSION_get_critical(ext)) continue;  // 非关键扩展不受门禁
        const int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
        switch (nid) {
            case NID_basic_constraints:
            case NID_key_usage:
            case NID_ext_key_usage:
            case NID_subject_alt_name:
            case NID_subject_key_identifier:
            case NID_authority_key_identifier:
                break;  // allowlist 内允许关键
            default:
                return false;  // 未知/未经允许的关键扩展 → fail-closed
        }
    }
    return true;
}

} // namespace

DeviceKeyAgreementCapability DeviceKeyAgreementAdapter::probe() const {
    DeviceKeyAgreementCapability cap;
    if (cert_store_ == nullptr || !cert_store_->hasCurrent()) return cap;

    std::string chain_pem = cert_store_->currentDeviceCertChain();
    if (chain_pem.empty()) return cap;

    CertificateChainParser parser;
    CertificateChainLimits limits;
    auto parsed = parser.parse(ByteView(chain_pem), limits);
    if (!parsed.ok || !parsed.chain.leaf) return cap;

    X509* leaf = parsed.chain.leaf.get();
    cap.active_cert_present = true;
    cap.p256 = isP256PublicKey(leaf);
    cap.key_agreement = hasKeyUsageKeyAgreement(leaf);
    cap.digital_signature = hasKeyUsageDigitalSignature(leaf);

    // CR-020 §2.1 修订门禁
    cap.ca_false = !isCaTrue(leaf);
    cap.eku_client_auth_only = hasOnlyClientAuthEku(leaf);
    cap.critical_extensions_allowed = criticalExtensionsAllowed(leaf);
    cap.profile_matched = cap.profileOk();

    // 原始 leaf DER 字节摘要（非 i2d 重编码；CR-020 §7.2）
    const auto& orig = parsed.chain.leaf_der_original_sha256;
    cap.leaf_digest_bound = false;
    for (size_t i = 0; i < orig.size(); ++i) {
        if (orig[i] != 0) { cap.leaf_digest_bound = true; break; }
    }
    if (cap.leaf_digest_bound) {
        cap.certificate_digest.assign(orig.begin(), orig.end());
    }

    if (hsm_ != nullptr && !device_key_id_.empty()) {
        cap.private_key_exists = hsm_->key_exists(device_key_id_);
        cap.private_key_can_derive = hsm_->supports_ecdh_derive(device_key_id_);
        cap.private_key_can_sign = hsm_->supports_ecdsa_sign(device_key_id_);

        // 链/证书公钥与本地私钥句柄公钥匹配（CR-020 §2.1）
        cap.cert_chain_key_match = false;
        if (cap.p256 && cap.private_key_exists) {
            EVP_PKEY* pkey = X509_get_pubkey(leaf);
            std::vector<uint8_t> local_pub;
            if (pkey != nullptr &&
                hsm_->export_public_key(device_key_id_, local_pub) == ErrorCode::SUCCESS) {
                EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
                if (ec != nullptr) {
                    const EC_GROUP* group = EC_KEY_get0_group(ec);
                    const EC_POINT* pt = EC_KEY_get0_public_key(ec);
                    if (group != nullptr && pt != nullptr) {
                        std::vector<uint8_t> cert_pub(
                            EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                               nullptr, 0, nullptr));
                        if (!cert_pub.empty()) {
                            EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                               cert_pub.data(), cert_pub.size(), nullptr);
                            cap.cert_chain_key_match = (cert_pub == local_pub);
                        }
                    }
                    EC_KEY_free(ec);
                }
            }
            EVP_PKEY_free(pkey);
        }
    }
    return cap;
}

} // namespace sec
} // namespace tbox

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
    if (!parsed.chain.cert_der_sha256.empty()) {
        const auto& d = parsed.chain.cert_der_sha256.front();
        cap.certificate_digest.assign(d.begin(), d.end());
    }

    if (hsm_ != nullptr && !device_key_id_.empty()) {
        cap.private_key_exists = hsm_->key_exists(device_key_id_);
        cap.private_key_can_derive = hsm_->supports_ecdh_derive(device_key_id_);
    }
    return cap;
}

} // namespace sec
} // namespace tbox

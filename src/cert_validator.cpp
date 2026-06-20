#include "cert_validator.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <chrono>
#include <ctime>

namespace tbox {
namespace sec {

CertValidator::CertValidator(KeyEngine* key_engine)
    : key_engine_(key_engine) {}

ErrorCode CertValidator::validate_certificate(const std::string& vin,
                                             const std::string& ecu_uid,
                                             const std::vector<uint8_t>& cert_der,
                                             bool& valid) {
    if (!key_engine_) {
        return ErrorCode::INVALID_PARAMETER;
    }

    // Check certificate validity period
    bool not_expired = false;
    ErrorCode result = check_certificate_validity(cert_der, not_expired);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (!not_expired) {
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }

    // Verify certificate signature
    bool signature_valid = false;
    result = verify_certificate_signature(cert_der, signature_valid);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (!signature_valid) {
        valid = false;
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // Match certificate key with device key
    bool key_match = false;
    result = match_certificate_key(cert_der, vin, ecu_uid, key_match);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    valid = key_match;
    return key_match ? ErrorCode::SUCCESS : ErrorCode::CERT_KEY_MISMATCH;
}

ErrorCode CertValidator::extract_certificate_info(const std::vector<uint8_t>& cert_der,
                                                 CertificateInfo& info) {
    if (cert_der.empty()) {
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // Parse DER-encoded certificate
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(NULL, &p, cert_der.size());
    if (!cert) {
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // Extract serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    BIGNUM* bn_serial = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn_serial) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    char* serial_str = BN_bn2hex(bn_serial);
    if (!serial_str) {
        BN_free(bn_serial);
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    info.serial_number = serial_str;
    OPENSSL_free(serial_str);
    BN_free(bn_serial);

    // Extract issuer
    X509_NAME* issuer_name = X509_get_issuer_name(cert);
    if (!issuer_name) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    char issuer[256];
    X509_NAME_oneline(issuer_name, issuer, sizeof(issuer));
    info.issuer = issuer;

    // Extract subject
    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (!subject_name) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    char subject[256];
    X509_NAME_oneline(subject_name, subject, sizeof(subject));
    info.subject = subject;

    // Extract validity period using ASN1_TIME_to_tm
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);

    if (!not_before || !not_after) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    struct tm tm_before = {};
    struct tm tm_after = {};
    if (!ASN1_TIME_to_tm(not_before, &tm_before) ||
        !ASN1_TIME_to_tm(not_after, &tm_after)) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // Convert tm to time_point
    time_t time_before = timegm(&tm_before);
    time_t time_after = timegm(&tm_after);
    if (time_before == -1 || time_after == -1) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    info.not_before = std::chrono::system_clock::from_time_t(time_before);
    info.not_after = std::chrono::system_clock::from_time_t(time_after);

    // Extract public key
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    int len = i2d_PublicKey(pkey, NULL);
    if (len <= 0) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return ErrorCode::CERT_VALIDATION_FAILED;
    }
    info.public_key.resize(len);
    unsigned char* pub_key_ptr = info.public_key.data();
    i2d_PublicKey(pkey, &pub_key_ptr);
    EVP_PKEY_free(pkey);

    // Extract key usage
    ASN1_BIT_STRING* usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (usage) {
        if (usage->length > 0) {
            std::string usage_str;
            if (usage->data[0] & KU_DIGITAL_SIGNATURE) usage_str += "digitalSignature,";
            if (usage->data[0] & KU_NON_REPUDIATION) usage_str += "nonRepudiation,";
            if (usage->data[0] & KU_KEY_ENCIPHERMENT) usage_str += "keyEncipherment,";
            if (usage->data[0] & KU_DATA_ENCIPHERMENT) usage_str += "dataEncipherment,";
            if (usage->data[0] & KU_KEY_AGREEMENT) usage_str += "keyAgreement,";
            if (usage->data[0] & KU_KEY_CERT_SIGN) usage_str += "keyCertSign,";
            if (usage->data[0] & KU_CRL_SIGN) usage_str += "cRLSign,";
            if (usage->data[0] & KU_ENCIPHER_ONLY) usage_str += "encipherOnly,";
            if (usage->data[0] & KU_DECIPHER_ONLY) usage_str += "decipherOnly,";
            if (!usage_str.empty()) {
                usage_str.pop_back(); // Remove trailing comma
            }
            info.key_usage = usage_str;
        }
        ASN1_BIT_STRING_free(usage);
    }

    // Extract extended key usage
    EXTENDED_KEY_USAGE* ext_usage = (EXTENDED_KEY_USAGE*)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (ext_usage) {
        std::string ext_usage_str;
        for (int i = 0; i < sk_ASN1_OBJECT_num(ext_usage); i++) {
            ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(ext_usage, i);
            if (obj) {
                char obj_txt[80];
                OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
                if (!ext_usage_str.empty()) {
                    ext_usage_str += ",";
                }
                ext_usage_str += obj_txt;
            }
        }
        info.extended_key_usage = ext_usage_str;
        EXTENDED_KEY_USAGE_free(ext_usage);
    }

    X509_free(cert);
    return ErrorCode::SUCCESS;
}

bool CertValidator::is_certificate_expired(const std::vector<uint8_t>& cert_der) {
    CertificateInfo info;
    if (extract_certificate_info(cert_der, info) != ErrorCode::SUCCESS) {
        return true; // Assume expired if can't parse
    }

    auto now = std::chrono::system_clock::now();
    return now < info.not_before || now > info.not_after;
}

ErrorCode CertValidator::validate_certificate_chain(const std::vector<std::vector<uint8_t>>& chain,
                                                   bool& valid) {
    if (chain.empty()) {
        valid = false;
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // In real implementation, validate the entire chain
    // For now, just validate the first certificate
    CertificateInfo info;
    ErrorCode result = extract_certificate_info(chain[0], info);
    if (result != ErrorCode::SUCCESS) {
        valid = false;
        return result;
    }

    // Check if self-signed (simplified)
    valid = (info.issuer == info.subject);
    return ErrorCode::SUCCESS;
}

ErrorCode CertValidator::verify_certificate_signature(const std::vector<uint8_t>& cert_der,
                                                     bool& valid) {
    // Signature verification requires issuer's public key which is not available here
    valid = false;
    return ErrorCode::NOT_IMPLEMENTED;
}

ErrorCode CertValidator::check_certificate_validity(const std::vector<uint8_t>& cert_der,
                                                   bool& valid) {
    valid = !is_certificate_expired(cert_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CertValidator::match_certificate_key(const std::vector<uint8_t>& cert_der,
                                              const std::string& vin,
                                              const std::string& ecu_uid,
                                              bool& match) {
    // Extract public key from certificate
    CertificateInfo info;
    ErrorCode result = extract_certificate_info(cert_der, info);
    if (result != ErrorCode::SUCCESS) {
        match = false;
        return result;
    }

    // Get device public key
    KeyPair key_pair;
    result = key_engine_->get_device_key(vin, ecu_uid, key_pair);
    if (result != ErrorCode::SUCCESS) {
        match = false;
        return result;
    }

    // Compare public keys
    match = (info.public_key == key_pair.public_key);
    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox

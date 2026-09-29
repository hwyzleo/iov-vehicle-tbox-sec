#include "cert_validator.h"
#include "sec_log_adapter.h"
#include "log_types.h"
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <chrono>
#include <ctime>

namespace tbox {
namespace sec {

namespace {

// Subject CN 是否与期望的 hsm_uid(ecu_uid) 一致
bool subjectCommonNameMatches(const X509* cert, const std::string& expected) {
    X509_NAME* subject = X509_get_subject_name(const_cast<X509*>(cert));
    const int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0) return false;
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
    ASN1_STRING* cn = X509_NAME_ENTRY_get_data(entry);
    unsigned char* utf8 = nullptr;
    const int len = ASN1_STRING_to_UTF8(&utf8, cn);
    if (len < 0) return false;
    const std::string cn_str(reinterpret_cast<char*>(utf8), static_cast<size_t>(len));
    OPENSSL_free(utf8);
    return cn_str == expected;
}

// KeyUsage 必须含 digitalSignature（DSN §5 证书 profile）
bool hasKeyUsageDigitalSignature(const X509* cert) {
    ASN1_BIT_STRING* usage = static_cast<ASN1_BIT_STRING*>(
        X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));
    if (!usage) return false;
    const bool ok = (usage->length > 0) && (usage->data[0] & KU_DIGITAL_SIGNATURE);
    ASN1_BIT_STRING_free(usage);
    return ok;
}

// ExtendedKeyUsage 必须含 clientAuth (1.3.6.1.5.5.7.3.2)（DSN §5 证书 profile）
bool hasClientAuthEku(const X509* cert) {
    EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(
        X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr));
    if (!eku) return false;
    ASN1_OBJECT* client_auth = OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1);
    bool ok = false;
    if (client_auth) {
        for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
            if (OBJ_cmp(sk_ASN1_OBJECT_value(eku, i), client_auth) == 0) {
                ok = true;
                break;
            }
        }
        ASN1_OBJECT_free(client_auth);
    }
    EXTENDED_KEY_USAGE_free(eku);
    return ok;
}

// 可验证自签名 leaf 识别（TBOX-SEC-DSN-CR-016 §3.2）：
// 同时满足 subject==issuer 且可用自身公钥验证签名；仅 DN 相等不足以判定自签名，
// 该检查属于 leaf profile 约束，不作为 CA 信任验证。
bool is_verifiable_self_signed(const X509* cert) {
    if (X509_NAME_cmp(X509_get_subject_name(const_cast<X509*>(cert)),
                      X509_get_issuer_name(const_cast<X509*>(cert))) != 0) {
        return false;
    }
    EVP_PKEY* pkey = X509_get_pubkey(const_cast<X509*>(cert));
    if (!pkey) return false;
    const int r = X509_verify(const_cast<X509*>(cert), pkey);
    EVP_PKEY_free(pkey);
    return r == 1;
}

} // namespace

TrustedTime SystemClockTrustedTimeProvider::get_trusted_time() const {
    // 过渡实现（TBOX-SEC-DSN-CR-016 阻塞项）：framework/平台时间可信度接口
    // 确认前，将系统时钟视为可信。生产语义须随该契约收敛。
    TrustedTime tt;
    tt.trusted = true;
    tt.utc_now = std::chrono::system_clock::now();
    tt.source = "system_clock";
    return tt;
}

CertValidator::CertValidator(KeyEngine* key_engine,
                             TrustedTimeProvider* time_provider)
    : key_engine_(key_engine),
      owned_time_provider_(
          time_provider ? nullptr : std::make_unique<SystemClockTrustedTimeProvider>()),
      time_provider_(time_provider ? time_provider : owned_time_provider_.get()) {}

ErrorCode CertValidator::validate_certificate(const std::string& vin,
                                             const std::string& ecu_uid,
                                             const std::vector<uint8_t>& cert_der,
                                             bool& valid) {
    valid = false;
    if (!key_engine_) {
        return ErrorCode::INVALID_PARAMETER;
    }

    // 1. parse/structure —— 解析 leaf DER（TBOX-SEC-DSN-CR-016 §3.2）
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(nullptr, &p, cert_der.size());
    if (!cert) {
        SecLogAdapter::certificate().error(
            "sec.cert.parse_der_failed", "证书 DER 解析失败");
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // 2~4. 证书 profile（TBOX-SEC-DSN-CR-003 §5 / REQ US-001）：
    //   Subject CN == hsm_uid(ecu_uid)；KU 含 digitalSignature；EKU 含 clientAuth。
    const bool cn_ok = subjectCommonNameMatches(cert, ecu_uid);
    const bool ku_ok = hasKeyUsageDigitalSignature(cert);
    const bool eku_ok = hasClientAuthEku(cert);

    // 5. 可验证自签名 leaf 以 profile 非法拒绝（位于 key match 之前，
    //    确保自签名 leaf 稳定返回 profile-invalid 而非被独立密钥提前映射为 key mismatch）
    const bool self_signed = is_verifiable_self_signed(cert);
    X509_free(cert);

    if (!cn_ok || !ku_ok || !eku_ok || self_signed) {
        SecLogAdapter::certificate().error(
            "sec.certificate.profile.rejected",
            "证书 profile 校验失败：CN/KeyUsage/ExtendedKeyUsage/自签名与设备身份不符",
            {{"cn_match", tbox::fw::log::FieldValue::makeBool(cn_ok)},
             {"ku_digital_signature", tbox::fw::log::FieldValue::makeBool(ku_ok)},
             {"eku_client_auth", tbox::fw::log::FieldValue::makeBool(eku_ok)},
             {"self_signed", tbox::fw::log::FieldValue::makeBool(self_signed)}});
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // 6. 可信时间位于 [notBefore, notAfter]（TBOX-SEC-DSN-CR-016 §3.2）
    bool not_expired = false;
    ErrorCode result = check_certificate_validity(cert_der, not_expired);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (!not_expired) {
        SecLogAdapter::certificate().error(
            "sec.cert.expired", "证书未生效或已过期");
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }

    // 7. 证书公钥与本地私钥匹配
    bool key_match = false;
    result = match_certificate_key(cert_der, vin, ecu_uid, key_match);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    valid = key_match;

    if (key_match) {
        SecLogAdapter::certificate().info(
            "sec.certificate.install.succeeded",
            "证书校验并安装成功",
            {
                {"cert_serial_hash", tbox::fw::log::FieldValue::makeString("cert_hash")},
                {"issuer_id", tbox::fw::log::FieldValue::makeString("cloud")}
            }
        );
    } else {
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书与私钥不匹配",
            {
                {"failure_stage", tbox::fw::log::FieldValue::makeString("key_match")},
                {"error_code", tbox::fw::log::FieldValue::makeString("SEC-1005")}
            }
        );
    }

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

    TrustedTime tt = time_provider_->get_trusted_time();
    // 时间不可判定时按 fail-closed 视为不可用（TBOX-SEC-DSN-CR-016 §3.2）
    if (!tt.trusted) {
        return true;
    }
    return tt.utc_now < info.not_before || tt.utc_now > info.not_after;
}

ErrorCode CertValidator::check_certificate_validity(const std::vector<uint8_t>& cert_der,
                                                   bool& valid) {
    TrustedTime tt = time_provider_->get_trusted_time();
    if (!tt.trusted) {
        // TBOX-SEC-DSN-CR-016 §3.2：可信时间不可用时显式失败，不得 commit
        SecLogAdapter::certificate().error(
            "sec.cert.time_untrusted",
            "可信时间不可用，拒绝证书注入（fail-closed，不得 commit）",
            {{"time_source", tbox::fw::log::FieldValue::makeString(tt.source)}});
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }

    CertificateInfo info;
    ErrorCode result = extract_certificate_info(cert_der, info);
    if (result != ErrorCode::SUCCESS) {
        valid = false;
        return result;
    }
    valid = !(tt.utc_now < info.not_before || tt.utc_now > info.not_after);
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

    // Get device public key（身份维度为 hsm_uid(ecu_uid)，不绑定 VIN，见 DSN §1.1/§3）
    KeyPair key_pair;
    result = key_engine_->get_device_key(ecu_uid, ecu_uid, key_pair);
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

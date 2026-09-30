#include "cert_validator.h"
#include "sec_log_adapter.h"
#include "log_types.h"
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
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

CertValidator::CertValidator(KeyEngine* key_engine,
                             TrustedTimeProvider& time_provider)
    : key_engine_(key_engine), time_provider_(&time_provider) {}

ErrorCode CertValidator::validate_certificate(const std::string& vin,
                                             const std::string& ecu_uid,
                                             X509* cert,
                                             bool& valid) {
    valid = false;
    if (!key_engine_) {
        return ErrorCode::INVALID_PARAMETER;
    }
    if (!cert) {
        SecLogAdapter::certificate().error(
            "sec.cert.leaf_null", "证书注入失败：leaf 为空（解析器未提取到证书）");
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // TBOX-SEC-DSN-CR-018 §4：CertValidator 不再解析原始 payload，leaf 由
    // CertificateChainParser 提取后传入（X509*，避免二次解析，本类不拥有 chain）。
    // 1~4. 证书 profile（TBOX-SEC-DSN-CR-003 §5 / REQ US-001）：
    //   Subject CN == hsm_uid(ecu_uid)；KU 含 digitalSignature；EKU 含 clientAuth。
    const bool cn_ok = subjectCommonNameMatches(cert, ecu_uid);
    const bool ku_ok = hasKeyUsageDigitalSignature(cert);
    const bool eku_ok = hasClientAuthEku(cert);

    // 5. 可验证自签名 leaf 以 profile 非法拒绝（位于 key match 之前，
    //    确保自签名 leaf 稳定返回 profile-invalid 而非被独立密钥提前映射为 key mismatch）
    const bool self_signed = is_verifiable_self_signed(cert);

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
    ErrorCode result = check_certificate_validity(cert, not_expired);
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
    result = match_certificate_key(cert, vin, ecu_uid, key_match);
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

    TrustedTimeSample tt = time_provider_->now();
    // 时间不可判定时按 fail-closed 视为不可用（CR-016 §3.2 / CR-017 §6）
    if (tt.trust_state != TimeTrustState::Trusted) {
        return true;
    }
    // 闭区间 + uncertainty（CR-017 §3）：不确定边界按不可用处理
    const auto lo = tt.utc_now - tt.uncertainty;
    const auto hi = tt.utc_now + tt.uncertainty;
    return lo < info.not_before || hi > info.not_after;
}

ErrorCode CertValidator::check_certificate_validity(X509* cert,
                                                   bool& valid) {
    TrustedTimeSample tt = time_provider_->now();
    if (tt.trust_state != TimeTrustState::Trusted) {
        // TBOX-SEC-DSN-CR-016 §3.2 / CR-017 §6：可信时间不可用时显式失败，
        // failure_stage=time_untrusted，不得 commit
        SecLogAdapter::certificate().error(
            "sec.cert.time_untrusted",
            "可信时间不可用，拒绝证书注入（fail-closed，不得 commit）",
            {{"failure_stage", tbox::fw::log::FieldValue::makeString("time_untrusted")},
             {"time_source", tbox::fw::log::FieldValue::makeString(timeSourceToString(tt.source))},
             {"trust_state", tbox::fw::log::FieldValue::makeString(timeTrustStateToString(tt.trust_state))},
             {"time_reason", tbox::fw::log::FieldValue::makeString(timeReasonToString(tt.reason))},
             {"freshness_ms", tbox::fw::log::FieldValue::makeInt(
                  static_cast<int64_t>(tt.freshness_age.count()))}});
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }

    // 从 X509* 直接读取有效期（CR-018 §4：避免二次解析）
    const ASN1_TIME* nb = X509_get0_notBefore(cert);
    const ASN1_TIME* na = X509_get0_notAfter(cert);
    struct tm tm_nb = {};
    struct tm tm_na = {};
    if (!nb || !na || !ASN1_TIME_to_tm(nb, &tm_nb) || !ASN1_TIME_to_tm(na, &tm_na)) {
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }
    const time_t t_nb = timegm(&tm_nb);
    const time_t t_na = timegm(&tm_na);
    if (t_nb == -1 || t_na == -1) {
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }
    const auto not_before = std::chrono::system_clock::from_time_t(t_nb);
    const auto not_after = std::chrono::system_clock::from_time_t(t_na);

    // 闭区间 + uncertainty（CR-017 §3）：仅当 utc_now-uncertainty >= notBefore 且
    // utc_now+uncertainty <= notAfter 时通过；不确定边界跨越按 fail-closed 处理。
    const auto lo = tt.utc_now - tt.uncertainty;
    const auto hi = tt.utc_now + tt.uncertainty;
    if (lo < not_before || hi > not_after) {
        // CR-017 §6：确定早于 notBefore/晚于 notAfter → failure_stage=time；
        // 仅 uncertainty 跨越边界 → failure_stage=time_untrusted（不得在不确定边界继续）
        const bool definite_outside =
            tt.utc_now < not_before || tt.utc_now > not_after;
        SecLogAdapter::certificate().error(
            "sec.cert.expired",
            definite_outside ? "证书未生效或已过期"
                             : "时间不确定边界跨越有效期窗口，拒绝注入（fail-closed）",
            {{"failure_stage", tbox::fw::log::FieldValue::makeString(
                 definite_outside ? "time" : "time_untrusted")},
             {"time_source", tbox::fw::log::FieldValue::makeString(timeSourceToString(tt.source))},
             {"time_reason", tbox::fw::log::FieldValue::makeString(timeReasonToString(tt.reason))}});
        valid = false;
        return ErrorCode::CERT_EXPIRED;
    }

    valid = true;
    return ErrorCode::SUCCESS;
}

ErrorCode CertValidator::match_certificate_key(X509* cert,
                                              const std::string& vin,
                                              const std::string& ecu_uid,
                                              bool& match) {
    // 从 X509* 提取证书公钥（未压缩 EC 点，与 key_engine.public_key / HSM 导出格式一致）
    std::vector<uint8_t> cert_pub;
    EVP_PKEY* pk = X509_get0_pubkey(cert);  // 借用指针，不释放
    if (pk) {
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pk);  // 新引用，需释放
        if (ec) {
            const EC_GROUP* group = EC_KEY_get0_group(ec);
            const EC_POINT* pt = EC_KEY_get0_public_key(ec);
            if (group && pt) {
                size_t len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                                nullptr, 0, nullptr);
                if (len > 0) {
                    cert_pub.resize(len);
                    EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                       cert_pub.data(), len, nullptr);
                }
            }
            EC_KEY_free(ec);
        }
    }
    if (cert_pub.empty()) {
        match = false;
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // Get device public key（身份维度为 hsm_uid(ecu_uid)，不绑定 VIN，见 DSN §1.1/§3）
    KeyPair key_pair;
    ErrorCode result = key_engine_->get_device_key(ecu_uid, ecu_uid, key_pair);
    if (result != ErrorCode::SUCCESS) {
        match = false;
        return result;
    }

    // Compare public keys
    match = (cert_pub == key_pair.public_key);
    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox

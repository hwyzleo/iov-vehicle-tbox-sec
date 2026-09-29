#include <gtest/gtest.h>
#include <cstdio>
#include "cert_validator.h"
#include "key_engine.h"
#include "hsm_interface.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

using namespace tbox::sec;

namespace {

struct X509D { void operator()(X509* p) const { if (p) X509_free(p); } };
using X509UP = std::unique_ptr<X509, X509D>;
struct EvpD { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
using EvpUP = std::unique_ptr<EVP_PKEY, EvpD>;

EvpUP gen_ec_key() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(ec)) { if (ec) EC_KEY_free(ec); return {}; }
    EvpUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}

void set_common_exts(X509* cert, bool ca, bool ku, bool eku, const char* cn) {
    X509_NAME* n = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    if (ku) {
        ASN1_BIT_STRING* bits = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set_bit(bits, 0, 1);
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_key_usage, 0, bits);
        X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); ASN1_BIT_STRING_free(bits);
    }
    if (eku) {
        EXTENDED_KEY_USAGE* e = EXTENDED_KEY_USAGE_new();
        sk_ASN1_OBJECT_push(e, OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1));
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_ext_key_usage, 0, e);
        X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); EXTENDED_KEY_USAGE_free(e);
    }
    (void)ca;
}

// 生成自签名证书（作为“伪造/无信任锚”用例）；含合法 profile（KU/EKU），
// 以便稳定命中自签名 leaf 检查而非被 profile 其它字段提前拒绝。
std::vector<uint8_t> make_self_signed(const char* cn) {
    EvpUP key = gen_ec_key();
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 99);
    set_common_exts(cert.get(), false, true, true, cn); // CN + KU + EKU
    X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()));
    X509_set_pubkey(cert.get(), key.get());
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 365 * 24 * 3600L);
    X509_sign(cert.get(), key.get(), EVP_sha256());
    unsigned char* buf = nullptr;
    int len = i2d_X509(cert.get(), &buf);
    std::vector<uint8_t> der(buf, buf + len);
    OPENSSL_free(buf);
    return der;
}

// 生成由同一 ca 签发的叶证书 + CA 证书 DER（CN / KU / EKU 可配置）
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> make_ca_signed_leaf_pair(
    const char* cn, bool ku, bool eku) {
    EvpUP ca_key = gen_ec_key();
    X509UP ca(X509_new());
    X509_set_version(ca.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca.get()), 1);
    X509_NAME* can = X509_get_subject_name(ca.get());
    X509_NAME_add_entry_by_txt(can, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Test Root CA"), -1, -1, 0);
    X509_set_issuer_name(ca.get(), can);
    X509_set_pubkey(ca.get(), ca_key.get());
    X509_gmtime_adj(X509_get_notBefore(ca.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(ca.get()), 3650 * 24 * 3600L);
    X509_sign(ca.get(), ca_key.get(), EVP_sha256());

    EvpUP dev_key = gen_ec_key();
    X509UP leaf(X509_new());
    X509_set_version(leaf.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf.get()), 2);
    X509_NAME* n = X509_get_subject_name(leaf.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca.get()));
    X509_set_pubkey(leaf.get(), dev_key.get());
    X509_gmtime_adj(X509_get_notBefore(leaf.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(leaf.get()), 365 * 24 * 3600L);
    set_common_exts(leaf.get(), false, ku, eku, cn);
    X509_sign(leaf.get(), ca_key.get(), EVP_sha256());

    unsigned char* buf = nullptr;
    int len = i2d_X509(leaf.get(), &buf);
    std::vector<uint8_t> leaf_der(buf, buf + len);
    OPENSSL_free(buf);
    buf = nullptr;
    len = i2d_X509(ca.get(), &buf);
    std::vector<uint8_t> ca_der_out(buf, buf + len);
    OPENSSL_free(buf);
    return {std::move(leaf_der), std::move(ca_der_out)};
}

// 由未压缩 EC 公钥点重建 EVP_PKEY（与 key_engine.public_key 格式一致，
// i2d_PublicKey/o2i_ECPublicKey 均为主公钥原始字节）
EvpUP pkey_from_raw_pub(const std::vector<uint8_t>& raw) {
    if (raw.empty()) return {};
    const unsigned char* p = raw.data();
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return {};
    if (!o2i_ECPublicKey(&ec, &p, raw.size())) {
        EC_KEY_free(ec);
        return {};
    }
    EvpUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}

// 生成由同一 ca 签发的叶证书（leaf 公钥使用给定原始公钥，使 key match 可通过）
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> make_ca_signed_leaf_pair_with_pubkey(
    const char* cn, const std::vector<uint8_t>& leaf_pub_raw, bool ku, bool eku) {
    EvpUP ca_key = gen_ec_key();
    X509UP ca(X509_new());
    X509_set_version(ca.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca.get()), 1);
    X509_NAME* can = X509_get_subject_name(ca.get());
    X509_NAME_add_entry_by_txt(can, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Test Root CA"), -1, -1, 0);
    X509_set_issuer_name(ca.get(), can);
    X509_set_pubkey(ca.get(), ca_key.get());
    X509_gmtime_adj(X509_get_notBefore(ca.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(ca.get()), 3650 * 24 * 3600L);
    X509_sign(ca.get(), ca_key.get(), EVP_sha256());

    EvpUP dev_key = pkey_from_raw_pub(leaf_pub_raw);
    X509UP leaf(X509_new());
    X509_set_version(leaf.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf.get()), 2);
    X509_NAME* n = X509_get_subject_name(leaf.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca.get()));
    X509_set_pubkey(leaf.get(), dev_key.get());
    X509_gmtime_adj(X509_get_notBefore(leaf.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(leaf.get()), 365 * 24 * 3600L);
    set_common_exts(leaf.get(), false, ku, eku, cn);
    X509_sign(leaf.get(), ca_key.get(), EVP_sha256());

    unsigned char* buf = nullptr;
    int len = i2d_X509(leaf.get(), &buf);
    std::vector<uint8_t> leaf_der(buf, buf + len);
    OPENSSL_free(buf);
    buf = nullptr;
    len = i2d_X509(ca.get(), &buf);
    std::vector<uint8_t> ca_der_out(buf, buf + len);
    OPENSSL_free(buf);
    return {std::move(leaf_der), std::move(ca_der_out)};
}

// 两级 CA：Root(自签名) → Issuing CA(Root 签发) → leaf(Issuing CA 签发)
// leaf 公钥使用给定原始公钥（设备公钥），使 key match 可通过。
std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
make_two_level_chain(const char* cn, const std::vector<uint8_t>& leaf_pub_raw,
                     bool ku, bool eku) {
    // Root：自签名
    EvpUP root_key = gen_ec_key();
    X509UP root(X509_new());
    X509_set_version(root.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(root.get()), 1);
    X509_NAME* rn = X509_get_subject_name(root.get());
    X509_NAME_add_entry_by_txt(rn, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Test Root CA"), -1, -1, 0);
    X509_set_issuer_name(root.get(), rn);
    X509_set_pubkey(root.get(), root_key.get());
    X509_gmtime_adj(X509_get_notBefore(root.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(root.get()), 3650 * 24 * 3600L);
    X509_sign(root.get(), root_key.get(), EVP_sha256());

    // Issuing CA：由 Root 签发（issuer = Root subject）
    EvpUP issuing_key = gen_ec_key();
    X509UP issuing(X509_new());
    X509_set_version(issuing.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(issuing.get()), 2);
    X509_NAME* in = X509_get_subject_name(issuing.get());
    X509_NAME_add_entry_by_txt(in, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Test Issuing CA"), -1, -1, 0);
    X509_set_issuer_name(issuing.get(), rn);
    X509_set_pubkey(issuing.get(), issuing_key.get());
    X509_gmtime_adj(X509_get_notBefore(issuing.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(issuing.get()), 3650 * 24 * 3600L);
    X509_sign(issuing.get(), root_key.get(), EVP_sha256());

    // leaf：由 Issuing CA 签发（issuer = Issuing CA subject，≠ Root subject）
    EvpUP leaf_key = pkey_from_raw_pub(leaf_pub_raw);
    X509UP leaf(X509_new());
    X509_set_version(leaf.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf.get()), 3);
    X509_NAME* n = X509_get_subject_name(leaf.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(leaf.get(), in);
    X509_set_pubkey(leaf.get(), leaf_key.get());
    X509_gmtime_adj(X509_get_notBefore(leaf.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(leaf.get()), 365 * 24 * 3600L);
    set_common_exts(leaf.get(), false, ku, eku, cn);
    X509_sign(leaf.get(), issuing_key.get(), EVP_sha256());

    auto der = [](X509* c) {
        unsigned char* buf = nullptr;
        int len = i2d_X509(c, &buf);
        std::vector<uint8_t> d(buf, buf + len);
        OPENSSL_free(buf);
        return d;
    };
    return {der(leaf.get()), der(root.get()), der(issuing.get())};
}

} // namespace

class CertValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string test_dir = "/tmp/test_cert";
        std::string cmd = "mkdir -p " + test_dir;
        std::system(cmd.c_str());

        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, test_dir);
        key_engine = std::make_unique<KeyEngine>(std::move(hsm));
        key_engine->initialize();

        // Generate test key（身份维度为 hsm_uid(ecu_uid)，不绑定 VIN）
        KeyPair key_pair;
        key_engine->generate_device_key("00000000000000000000000000000001",
                                        "00000000000000000000000000000001", key_pair);

        // TBOX-SEC-DSN-CR-017：显式注入可信 fake（fixture 证书以真实 now 生成，
        // 故 fake 也取当前墙钟，验证有效期窗口通过）
        TrustedTimeSample sample;
        sample.utc_now = std::chrono::system_clock::now();
        sample.trust_state = TimeTrustState::Trusted;
        sample.source = TimeSource::FakeTest;
        sample.reason = TimeReason::FakeTest;
        fake_time = std::make_unique<FakeTrustedTimeProvider>(sample);

        validator = std::make_unique<CertValidator>(key_engine.get(), *fake_time);
    }

    void TearDown() override {
        std::string cmd = "rm -rf /tmp/test_cert";
        std::system(cmd.c_str());
    }

    std::unique_ptr<KeyEngine> key_engine;
    std::unique_ptr<FakeTrustedTimeProvider> fake_time;
    std::unique_ptr<CertValidator> validator;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "00000000000000000000000000000001";
};

TEST_F(CertValidatorTest, ValidateCertificate_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, empty_cert, valid);
    // CR-016 §3.2: parse 位于最前，空证书按解析失败处理
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

TEST_F(CertValidatorTest, ValidateCertificate_InvalidDer) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert_der, valid);
    EXPECT_NE(result, ErrorCode::SUCCESS);
    EXPECT_FALSE(valid);
}

TEST_F(CertValidatorTest, ExtractCertificateInfo_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    CertificateInfo info;
    ErrorCode result = validator->extract_certificate_info(empty_cert, info);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
}

TEST_F(CertValidatorTest, ExtractCertificateInfo_InvalidDer) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER
    CertificateInfo info;
    ErrorCode result = validator->extract_certificate_info(cert_der, info);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
}

TEST_F(CertValidatorTest, IsCertificateExpired_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    EXPECT_TRUE(validator->is_certificate_expired(empty_cert));
}

TEST_F(CertValidatorTest, IsCertificateExpired_InvalidDer) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER
    EXPECT_TRUE(validator->is_certificate_expired(cert_der));
}

// 自签名叶证书必须被拒绝（无信任锚，profile 非法；该检查先于 key match，
// 独立密钥生成的自签名 fixture 稳定返回 profile-invalid）
TEST_F(CertValidatorTest, RejectSelfSignedLeaf) {
    std::vector<uint8_t> cert = make_self_signed("00000000000000000000000000000001");
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

// 未配置 root_ca 不阻断注入 sanity check：sanity 通过，最终在 key match 阶段拒绝
// （TBOX-SEC-DSN-CR-016：注入不再要求配置 CA / 不再验 CA 签名）
TEST_F(CertValidatorTest, AcceptValidProfileWithoutConfiguredCaForInstall) {
    auto [cert, ca] = make_ca_signed_leaf_pair(test_ecu_uid.c_str(), true, true);
    (void)ca;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_KEY_MISMATCH);
    EXPECT_FALSE(valid);
}

// 合法 CA 签名 + 正确 profile（CN==ecu_uid, KU=digitalSignature, EKU=clientAuth）
// 且叶证书公钥==设备公钥 → 完整 sanity check 通过（不依赖任何 Root/单跳验签）
TEST_F(CertValidatorTest, AcceptCaSignedValidProfile) {
    KeyPair key_pair;
    key_engine->get_device_key(test_ecu_uid, test_ecu_uid, key_pair);
    auto [cert, ca] = make_ca_signed_leaf_pair_with_pubkey(
        test_ecu_uid.c_str(), key_pair.public_key, true, true);
    (void)ca;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_TRUE(valid);
}

// 两级 CA：合法 leaf 由 Issuing CA 签发（issuer ≠ Root subject），公钥==设备公钥
// → 注入 sanity check 必须通过（不得因 leaf issuer 与 Root subject 不同而拒绝）
TEST_F(CertValidatorTest, AcceptIssuingCaSignedLeafForInstall) {
    KeyPair key_pair;
    key_engine->get_device_key(test_ecu_uid, test_ecu_uid, key_pair);
    auto [leaf, root, issuing] =
        make_two_level_chain(test_ecu_uid.c_str(), key_pair.public_key, true, true);
    // 构造即证明 leaf.issuer(=Issuing CA) != root.subject(=Root CA)
    CertificateInfo info;
    ASSERT_EQ(validator->extract_certificate_info(leaf, info), ErrorCode::SUCCESS);
    ASSERT_NE(info.issuer.find("Test Issuing CA"), std::string::npos);
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, leaf, valid);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_TRUE(valid);
    (void)issuing;
}

// CN 与 ecu_uid 不一致被拒绝
TEST_F(CertValidatorTest, RejectCnMismatch) {
    auto [cert, ca] = make_ca_signed_leaf_pair("OTHER-ECU", true, true);
    (void)ca;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

// 缺 EKU=clientAuth 被拒绝
TEST_F(CertValidatorTest, RejectMissingClientAuthEku) {
    auto [cert, ca] = make_ca_signed_leaf_pair(test_ecu_uid.c_str(), true, false);
    (void)ca;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

// ---- TBOX-SEC-DSN-CR-017：可信时间 fail-closed（不再有 system_clock 伪可信）----

// 可信时间 UNTRUSTED → 拒绝注入（time_untrusted，key-match/commit 不执行）
TEST_F(CertValidatorTest, TimeUntrusted_FailClosed) {
    KeyPair key_pair;
    key_engine->get_device_key(test_ecu_uid, test_ecu_uid, key_pair);
    auto [cert, ca] = make_ca_signed_leaf_pair_with_pubkey(
        test_ecu_uid.c_str(), key_pair.public_key, true, true);
    (void)ca;

    TrustedTimeSample bad;
    bad.utc_now = std::chrono::system_clock::now();
    bad.trust_state = TimeTrustState::Untrusted;   // 产线 RTC 未同步场景
    bad.source = TimeSource::HardwareRtc;
    bad.reason = TimeReason::RtcNotProvisioned;
    fake_time->set_now(bad);

    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_EXPIRED);
    EXPECT_FALSE(valid);
}

// 时间未到 notBefore（如产线时钟停在 1970，刚签发证书 notBefore 在未来）→ 拒绝
TEST_F(CertValidatorTest, NotYetValid_Rejected) {
    KeyPair key_pair;
    key_engine->get_device_key(test_ecu_uid, test_ecu_uid, key_pair);
    auto [cert, ca] = make_ca_signed_leaf_pair_with_pubkey(
        test_ecu_uid.c_str(), key_pair.public_key, true, true);
    (void)ca;

    // fixture 证书 notBefore == 当前墙钟；将 fake 拨回 2 天前 → 证书“尚未生效”
    TrustedTimeSample early = fake_time->now();
    early.utc_now -= std::chrono::hours(48);
    early.uncertainty = std::chrono::milliseconds(0);
    fake_time->set_now(early);

    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_EXPIRED);
    EXPECT_FALSE(valid);
}

// 时间越过 notAfter → 拒绝
TEST_F(CertValidatorTest, Expired_Rejected) {
    KeyPair key_pair;
    key_engine->get_device_key(test_ecu_uid, test_ecu_uid, key_pair);
    auto [cert, ca] = make_ca_signed_leaf_pair_with_pubkey(
        test_ecu_uid.c_str(), key_pair.public_key, true, true);
    (void)ca;

    // fixture 证书 notAfter == now + 365d；拨快 400 天 → 已过期
    TrustedTimeSample late = fake_time->now();
    late.utc_now += std::chrono::hours(400 * 24);
    late.uncertainty = std::chrono::milliseconds(0);
    fake_time->set_now(late);

    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_EXPIRED);
    EXPECT_FALSE(valid);
}

// uncertainty 跨越边界（CR-017 §3 闭区间）→ fail-closed
TEST_F(CertValidatorTest, UncertaintyCrossesBoundary_Rejected) {
    KeyPair key_pair;
    key_engine->get_device_key(test_ecu_uid, test_ecu_uid, key_pair);
    auto [cert, ca] = make_ca_signed_leaf_pair_with_pubkey(
        test_ecu_uid.c_str(), key_pair.public_key, true, true);
    (void)ca;

    // 正常时间，但 uncertainty 大跨 notAfter 边界（fake now == notAfter 附近）
    TrustedTimeSample near = fake_time->now();
    near.utc_now += std::chrono::hours(365 * 24) - std::chrono::milliseconds(1);
    near.uncertainty = std::chrono::seconds(2);   // 跨过 notAfter
    fake_time->set_now(near);

    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_EXPIRED);
    EXPECT_FALSE(valid);
}



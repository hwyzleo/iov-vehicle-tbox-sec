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

// 生成自签名证书（作为“伪造/无信任锚”用例）
std::vector<uint8_t> make_self_signed(const char* cn) {
    EvpUP key = gen_ec_key();
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 99);
    X509_NAME* n = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(cert.get(), n);
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

        validator = std::make_unique<CertValidator>(key_engine.get());
    }

    void TearDown() override {
        std::string cmd = "rm -rf /tmp/test_cert";
        std::system(cmd.c_str());
    }

    std::unique_ptr<KeyEngine> key_engine;
    std::unique_ptr<CertValidator> validator;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "00000000000000000000000000000001";
};

TEST_F(CertValidatorTest, ValidateCertificate_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, empty_cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_EXPIRED);
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

TEST_F(CertValidatorTest, ValidateCertificateChain_EmptyChain) {
    std::vector<std::vector<uint8_t>> empty_chain;
    bool valid = false;
    ErrorCode result = validator->validate_certificate_chain(empty_chain, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

TEST_F(CertValidatorTest, ValidateCertificateChain_InvalidCert) {
    std::vector<std::vector<uint8_t>> chain = {{0x30, 0x82, 0x01, 0x00}};
    bool valid = false;
    ErrorCode result = validator->validate_certificate_chain(chain, valid);
    EXPECT_NE(result, ErrorCode::SUCCESS);
    EXPECT_FALSE(valid);
}

// 自签名叶证书必须被拒绝（无信任锚，禁止自身公钥验签）
TEST_F(CertValidatorTest, RejectSelfSignedLeaf) {
    std::vector<uint8_t> cert = make_self_signed("00000000000000000000000000000001");
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

// 无 CA 时 CA 签名证书无法验签（fail-closed）
TEST_F(CertValidatorTest, RejectCaSignedWithoutConfiguredCa) {
    auto [cert, ca] = make_ca_signed_leaf_pair(test_ecu_uid.c_str(), true, true);
    (void)ca;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

// 合法 CA 签名 + 正确 profile（CN==ecu_uid, KU=digitalSignature, EKU=clientAuth）
// 签名/profile 通过；因叶证书公钥与设备密钥不同，最终在 key match 阶段拒绝。
TEST_F(CertValidatorTest, AcceptCaSignedValidProfile) {
    auto [cert, ca] = make_ca_signed_leaf_pair(test_ecu_uid.c_str(), true, true);
    validator->set_ca_certificate(ca);
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_KEY_MISMATCH);
    EXPECT_FALSE(valid);
}

// CN 与 ecu_uid 不一致被拒绝
TEST_F(CertValidatorTest, RejectCnMismatch) {
    auto [cert, ca] = make_ca_signed_leaf_pair("OTHER-ECU", true, true);
    validator->set_ca_certificate(ca);
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

// 缺 EKU=clientAuth 被拒绝
TEST_F(CertValidatorTest, RejectMissingClientAuthEku) {
    auto [cert, ca] = make_ca_signed_leaf_pair(test_ecu_uid.c_str(), true, false);
    validator->set_ca_certificate(ca);
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}


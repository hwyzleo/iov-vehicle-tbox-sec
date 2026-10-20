// DeviceKeyAgreementAdapter probe 单元测试（TBOX-SEC-DSN-CR-020 §2.1/§5/§11 修订）
//
// 覆盖 ECDH-ES capability 路径门禁：
//   - 逻辑 Profile TBOX_DEVICE_ECDH_ES_P256_V1 合取（P-256 + 双 KU + clientAuth-only +
//     CA=false + 关键扩展 allowlist）；
//   - leaf 原始 DER 摘要绑定（SHA-256(original bytes)，非重编码口径）；
//   - 链/证书公钥与本地句柄公钥匹配；
//   - 仅 digitalSignature 存量证书 → ECDH-ES readiness DOWN（TLS 路径不受影响，
//     该路径由通用 CertValidator 负责，本测试只验证 ECDH-ES 门禁）。
#include <gtest/gtest.h>

#include "certificate_store.h"
#include "device_key_agreement.h"
#include "soft_file_hsm.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

using namespace tbox::sec;

namespace fs = std::filesystem;

namespace {

struct X509Deleter { void operator()(X509* p) const { if (p) X509_free(p); } };
using X509UP = std::unique_ptr<X509, X509Deleter>;
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
using EvpPkeyUP = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

EvpPkeyUP gen_ec_key() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(ec)) { EC_KEY_free(ec); return {}; }
    EvpPkeyUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}

EvpPkeyUP pkey_from_raw(const std::vector<uint8_t>& raw) {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return {};
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (pt) {
        EC_POINT_oct2point(group, pt, raw.data(), raw.size(), nullptr);
        EC_KEY_set_public_key(ec, pt);
        EC_POINT_free(pt);
    }
    EvpPkeyUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}

X509UP make_root_ca() {
    EvpPkeyUP ca_key = gen_ec_key();
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_NAME* n = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("DKA Root CA"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), n);
    X509_set_pubkey(cert.get(), ca_key.get());
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 3650 * 24 * 3600L);
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new(); bc->ca = 1;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1); X509_EXTENSION_free(ext); BASIC_CONSTRAINTS_free(bc);
    X509_sign(cert.get(), ca_key.get(), EVP_sha256());
    return cert;
}

struct LeafProfile {
    bool ku_dual = true;              ///< digitalSignature + keyAgreement
    bool eku_client_auth_only = true; ///< true: 仅 clientAuth；false: clientAuth+serverAuth
    bool eku_present = true;
    bool ca_true = false;             ///< basicConstraints CA=TRUE
    bool bc_present = true;
    bool unknown_critical = false;    ///< 追加未知关键扩展 1.2.3.4.5
    bool ku_present = true;
};

// 生成由 root 签发的 leaf（CN=ecu-1；公钥为给定原始公钥；profile 可配置）。
X509UP make_leaf(const std::vector<uint8_t>& dev_pub_raw, const LeafProfile& prof,
                 EVP_PKEY* ca_key, X509* ca_cert) {
    EvpPkeyUP dev_key = pkey_from_raw(dev_pub_raw);
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 2);
    X509_NAME* n = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("ecu-1"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert));
    X509_set_pubkey(cert.get(), dev_key.get());
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 365 * 24 * 3600L);

    if (prof.bc_present) {
        BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
        bc->ca = prof.ca_true ? 1 : 0;
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
        BASIC_CONSTRAINTS_free(bc);
    }
    if (prof.ku_present) {
        ASN1_BIT_STRING* ku = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set_bit(ku, 0, 1);  // digitalSignature
        if (prof.ku_dual) ASN1_BIT_STRING_set_bit(ku, 4, 1);  // keyAgreement
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_key_usage, 1, ku);
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
        ASN1_BIT_STRING_free(ku);
    }
    if (prof.eku_present) {
        EXTENDED_KEY_USAGE* eku = EXTENDED_KEY_USAGE_new();
        sk_ASN1_OBJECT_push(eku, OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1));  // clientAuth
        if (!prof.eku_client_auth_only) {
            sk_ASN1_OBJECT_push(eku, OBJ_txt2obj("1.3.6.1.5.5.7.3.1", 1));  // serverAuth
        }
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_ext_key_usage, 1, eku);
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
        EXTENDED_KEY_USAGE_free(eku);
    }
    if (prof.unknown_critical) {
        ASN1_OBJECT* o = OBJ_txt2obj("1.2.3.4.5", 1);
        ASN1_OCTET_STRING* oct = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(oct, reinterpret_cast<const unsigned char*>("x"), 1);
        X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(nullptr, o, 1, oct);
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
        ASN1_OBJECT_free(o);
        ASN1_OCTET_STRING_free(oct);
    }
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}

std::string pem_of(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    char* buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string s(buf, static_cast<size_t>(len));
    BIO_free(bio);
    return s;
}

} // namespace

class DeviceKeyAgreementTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = "/tmp/test_dka_" + std::to_string(::getpid());
        fs::create_directories(dir_);
        store_ = std::make_unique<CertificateStore>(dir_ + "/cert_store");
        ASSERT_TRUE(store_->openAndRecover());
        hsm_ = std::make_unique<SoftFileHsm>(
            hwyz::store::Store::open("sec_hsm", dir_),
            "aes-256-gcm", dir_ + "/.hsm_kek");
        ASSERT_EQ(hsm_->initialize(), ErrorCode::SUCCESS);
        KeyPair kp;
        ASSERT_EQ(hsm_->generate_key_pair(kDeviceKeyIdDka, "ecdsa-p256", kp),
                  ErrorCode::SUCCESS);
        dev_pub_ = kp.public_key;
    }

    void TearDown() override {
        store_.reset();
        hsm_.reset();
        fs::remove_all(dir_);
    }

    // 提交 leaf 链到 store（ca + leaf PEM），结果写入 last_cap_。
    void probe_with(const LeafProfile& prof) {
        X509UP ca = make_root_ca();
        EVP_PKEY* ca_key = X509_get_pubkey(ca.get());  // 借用
        X509UP leaf = make_leaf(dev_pub_, prof, ca_key, ca.get());
        std::string pem = pem_of(leaf.get());  // 单 leaf；Root 入链由 parser 拒绝
        CertificateCommit commit;
        commit.device_cert_chain_pem = pem;
        commit.device_cert_json = R"({"profile":"test"})";
        commit.provision_state = "CERT_INSTALLED";
        commit.version = 1;
        ASSERT_EQ(store_->commit(commit), ErrorCode::SUCCESS);

        DeviceKeyAgreementAdapter adapter(store_.get(), hsm_.get(),
                                          std::string(kDeviceKeyIdDka));
        last_cap_ = adapter.probe();
    }

    static constexpr const char* kDeviceKeyIdDka = "ecu-1+ecu-1";

    std::string dir_;
    std::unique_ptr<CertificateStore> store_;
    std::unique_ptr<SoftFileHsm> hsm_;
    std::vector<uint8_t> dev_pub_;
    DeviceKeyAgreementCapability last_cap_;
};

TEST_F(DeviceKeyAgreementTest, FullEcdhEsProfile_ReadyComponents) {
    LeafProfile prof;
    probe_with(prof);
    const DeviceKeyAgreementCapability& cap = last_cap_;
    EXPECT_TRUE(cap.active_cert_present);
    EXPECT_TRUE(cap.p256);
    EXPECT_TRUE(cap.key_agreement);
    EXPECT_TRUE(cap.digital_signature);
    EXPECT_TRUE(cap.ca_false);
    EXPECT_TRUE(cap.eku_client_auth_only);
    EXPECT_TRUE(cap.critical_extensions_allowed);
    EXPECT_TRUE(cap.leaf_digest_bound);
    EXPECT_TRUE(cap.private_key_exists);
    EXPECT_TRUE(cap.private_key_can_derive);
    EXPECT_TRUE(cap.private_key_can_sign);
    EXPECT_TRUE(cap.cert_chain_key_match);
    EXPECT_TRUE(cap.profile_matched);
    // 原始 leaf DER 摘要必须非空（SHA-256(original bytes)）
    EXPECT_EQ(cap.certificate_digest.size(), 32u);
}

TEST_F(DeviceKeyAgreementTest, DigitalSignatureOnly_KeyAgreementDown) {
    // 存量仅 digitalSignature 证书（TLS 路径继续可用；ECDH-ES readiness DOWN）
    LeafProfile prof;
    prof.ku_dual = false;
    probe_with(prof);
    const DeviceKeyAgreementCapability& cap = last_cap_;
    EXPECT_TRUE(cap.digital_signature);
    EXPECT_FALSE(cap.key_agreement);
    EXPECT_FALSE(cap.profile_matched);
    EXPECT_FALSE(cap.profileOk());
}

TEST_F(DeviceKeyAgreementTest, ServerAuthInEku_ClientAuthOnlyGate) {
    LeafProfile prof;
    prof.eku_client_auth_only = false;  // clientAuth + serverAuth
    probe_with(prof);
    const DeviceKeyAgreementCapability& cap = last_cap_;
    EXPECT_FALSE(cap.eku_client_auth_only);
    EXPECT_FALSE(cap.profile_matched);
}

TEST_F(DeviceKeyAgreementTest, UnknownCriticalExtension_FailClosed) {
    LeafProfile prof;
    prof.unknown_critical = true;
    probe_with(prof);
    const DeviceKeyAgreementCapability& cap = last_cap_;
    EXPECT_FALSE(cap.critical_extensions_allowed);
    EXPECT_FALSE(cap.profile_matched);
}

TEST_F(DeviceKeyAgreementTest, CaTrueLeaf_Rejected) {
    LeafProfile prof;
    prof.ca_true = true;
    probe_with(prof);
    const DeviceKeyAgreementCapability& cap = last_cap_;
    EXPECT_FALSE(cap.ca_false);
    EXPECT_FALSE(cap.profile_matched);
}

TEST_F(DeviceKeyAgreementTest, NoBasicConstraints_EndEntityAccepted) {
    // BC 缺失按终端实体处理（不得要求扩展显式存在）
    LeafProfile prof;
    prof.bc_present = false;
    probe_with(prof);
    const DeviceKeyAgreementCapability& cap = last_cap_;
    EXPECT_TRUE(cap.ca_false);
    EXPECT_TRUE(cap.profile_matched);
}

TEST_F(DeviceKeyAgreementTest, NoCert_NotReady) {
    DeviceKeyAgreementAdapter adapter(store_.get(), hsm_.get(),
                                      std::string(kDeviceKeyIdDka));
    auto cap = adapter.probe();
    EXPECT_FALSE(cap.active_cert_present);
    EXPECT_FALSE(cap.profile_matched);
}

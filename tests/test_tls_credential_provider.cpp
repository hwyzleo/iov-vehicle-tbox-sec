// TlsCredentialProvider 单元测试（TBOX-SEC-DSN-CR-010）
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "hsm_interface.h"
#include "tbox/sec/types.h"
#include "tbox/sec/errors.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <cstdio>
#include <fstream>
#include <chrono>
#include <memory>

using namespace tbox::sec;

// gtest 打印 ErrorCode（避免默认 raw-bytes 打印在此 libc++ 上崩溃）
namespace tbox { namespace sec {
void PrintTo(ErrorCode e, std::ostream* os) {
    *os << error_code_to_string(e) << "(" << static_cast<uint32_t>(e) << ")";
}
}}

namespace {

// RAII OpenSSL 对象
struct X509Deleter { void operator()(X509* p) const { if (p) X509_free(p); } };
using X509UP = std::unique_ptr<X509, X509Deleter>;
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
using EvpPkeyUP = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
struct BioDeleter { void operator()(BIO* p) const { if (p) BIO_free(p); } };
using BioUP = std::unique_ptr<BIO, BioDeleter>;

/// 从原始未压缩 EC point (0x04||X||Y) 构造 EVP_PKEY
EvpPkeyUP pkey_from_raw_ec_point(const std::vector<uint8_t>& raw) {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return {};
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) { EC_KEY_free(ec); return {}; }
    if (!EC_POINT_oct2point(group, pt, raw.data(), raw.size(), nullptr)) {
        EC_POINT_free(pt); EC_KEY_free(ec); return {};
    }
    if (!EC_KEY_set_public_key(ec, pt)) { EC_POINT_free(pt); EC_KEY_free(ec); return {}; }
    EC_POINT_free(pt);
    EvpPkeyUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);  // takes ownership of ec
    return pkey;
}

/// 生成 EC P-256 密钥对（用于 CA）
EvpPkeyUP gen_ec_key() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return {};
    if (!EC_KEY_generate_key(ec)) { EC_KEY_free(ec); return {}; }
    EvpPkeyUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}

/// 设置证书有效期与时间
void set_cert_time(X509* cert, int days_valid) {
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days_valid * 24 * 3600L);
}

/// 写 X509 到 PEM 文件
bool write_cert_pem(const std::string& path, X509* cert) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    bool ok = PEM_write_X509(f, cert) == 1;
    fclose(f);
    return ok;
}

/// 生成自签名根 CA 证书
X509UP make_root_ca(EVP_PKEY* ca_key) {
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)"Test Root CA", -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    X509_set_pubkey(cert.get(), ca_key);
    set_cert_time(cert.get(), 3650);
    // basicConstraints CA=TRUE
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = 1;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    BASIC_CONSTRAINTS_free(bc);
    // 签名
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}

/// 生成设备叶子证书（用 CA 签名，公钥来自 HSM，EKU=clientAuth）
X509UP make_leaf_cert(EVP_PKEY* ca_key, X509* ca_cert, EVP_PKEY* dev_pubkey) {
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 2);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)"TBOX-ECU-001", -1, -1, 0);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert));
    X509_set_pubkey(cert.get(), dev_pubkey);
    set_cert_time(cert.get(), 365);
    // basicConstraints CA=FALSE
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = 0;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    BASIC_CONSTRAINTS_free(bc);
    // EKU clientAuth
    EXTENDED_KEY_USAGE* eku = EXTENDED_KEY_USAGE_new();
    ASN1_OBJECT* oa = OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1);
    sk_ASN1_OBJECT_push(eku, oa);
    X509_EXTENSION* ext2 = X509V3_EXT_i2d(NID_ext_key_usage, 0, eku);
    X509_add_ext(cert.get(), ext2, -1);
    X509_EXTENSION_free(ext2);
    EXTENDED_KEY_USAGE_free(eku);
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}

/// Mock peer credential resolver
class MockPeerResolver : public PeerCredentialResolver {
public:
    PeerIdentity identity;
    explicit MockPeerResolver(std::string service) {
        identity.valid = true;
        identity.pid = 1234;
        identity.uid = 1000;
        identity.gid = 1000;
        identity.service_name = std::move(service);
    }
    PeerIdentity resolve(int) override { return identity; }
    void set_valid(bool v) { identity.valid = v; }
    void set_service(std::string s) { identity.service_name = std::move(s); }
};

} // namespace

class TlsCredentialProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_tls_cred_provider";
        std::string cmd = "rm -rf " + test_dir_ + " && mkdir -p " + test_dir_;
        std::system(cmd.c_str());

        // 1. HSM + 设备密钥
        hsm_ = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, test_dir_);
        hsm_->initialize();
        std::string key_id = "testdev+tbox-ecu-001";
        KeyPair kp;
        ASSERT_EQ(hsm_->generate_key_pair(key_id, "ecdsa-p256", kp), ErrorCode::SUCCESS);
        dev_pub_raw_ = kp.public_key;

        // 2. CA 密钥与证书
        ca_key_ = gen_ec_key();
        ASSERT_NE(ca_key_, nullptr);
        ca_cert_ = make_root_ca(ca_key_.get());

        // 3. 设备叶子证书（公钥来自 HSM）
        dev_pkey_ = pkey_from_raw_ec_point(dev_pub_raw_);
        ASSERT_NE(dev_pkey_, nullptr);
        leaf_cert_ = make_leaf_cert(ca_key_.get(), ca_cert_.get(), dev_pkey_.get());

        // 4. 写文件
        ca_path_ = test_dir_ + "/ca_root.pem";
        chain_path_ = test_dir_ + "/device_chain.pem";
        ASSERT_TRUE(write_cert_pem(ca_path_, ca_cert_.get()));
        // chain: leaf (单证书即可，root 作为信任锚单独提供)
        ASSERT_TRUE(write_cert_pem(chain_path_, leaf_cert_.get()));

        // 5. provider
        key_id_resolver_ = [key_id]() { return key_id; };
        notify_count_ = 0;
        provider_ = std::make_unique<TlsCredentialProvider>(
            hsm_.get(), key_id_resolver_,
            [this](const std::string& profile, const TlsCredentialChangedEvent& ev) {
                (void)profile; (void)ev;
                ++notify_count_;
                last_event_ = ev;
            });

        // 6. 配置 mqtt profile
        TlsProfileConfig cfg;
        cfg.profile_name = "mqtt";
        cfg.credential_id = "mqtt-primary";
        cfg.key_usage = "clientAuth";
        cfg.allowed_signature_algorithms = {SignatureAlgorithm::ECDSA_SECP256R1_SHA256};
        cfg.peer_service = "tbox-mqtt.service";
        cfg.notify_on_change = true;
        cfg.root_ca_path = ca_path_;
        cfg.client_cert_chain_path = chain_path_;
        cfg.ref_ttl_sec = 3600;
        provider_->configureProfile(cfg);
    }

    void TearDown() override {
        provider_.reset();
        std::string cmd = "rm -rf " + test_dir_;
        std::system(cmd.c_str());
    }

    std::string test_dir_;
    std::unique_ptr<HsmInterface> hsm_;
    std::vector<uint8_t> dev_pub_raw_;
    EvpPkeyUP ca_key_;
    X509UP ca_cert_;
    EvpPkeyUP dev_pkey_;
    X509UP leaf_cert_;
    std::string ca_path_;
    std::string chain_path_;
    DeviceKeyIdResolver key_id_resolver_;
    std::unique_ptr<TlsCredentialProvider> provider_;
    int notify_count_ = 0;
    TlsCredentialChangedEvent last_event_;
    MockPeerResolver mqtt_peer_{"tbox-mqtt.service"};
};

// ---- 材料加载与状态 ----

TEST_F(TlsCredentialProviderTest, LoadMaterials_Ready) {
    EXPECT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    EXPECT_EQ(provider_->getStatus("mqtt"), TlsCredentialStatus::READY);
}

TEST_F(TlsCredentialProviderTest, LoadMaterials_MissingFiles_NotReady) {
    TlsProfileConfig bad;
    bad.profile_name = "mqtt2";
    bad.credential_id = "x";
    bad.peer_service = "tbox-mqtt.service";
    bad.root_ca_path = "/nonexistent/ca.pem";
    bad.client_cert_chain_path = "/nonexistent/chain.pem";
    provider_->configureProfile(bad);
    EXPECT_NE(provider_->loadMaterials("mqtt2"), ErrorCode::SUCCESS);
    EXPECT_EQ(provider_->getStatus("mqtt2"), TlsCredentialStatus::NOT_READY);
}

TEST_F(TlsCredentialProviderTest, LoadMaterials_UnknownProfile) {
    EXPECT_EQ(provider_->loadMaterials("nope"), ErrorCode::INVALID_PARAMETER);
}

// ---- getTlsCredential ----

TEST_F(TlsCredentialProviderTest, GetTlsCredential_Success) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle bundle;
    EXPECT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);
    EXPECT_EQ(bundle.credential_id, "mqtt-primary");
    EXPECT_EQ(bundle.version, 1u);
    EXPECT_EQ(bundle.status, TlsCredentialStatus::READY);
    EXPECT_FALSE(bundle.root_ca_bundle_der.empty());
    EXPECT_FALSE(bundle.client_cert_chain_der.empty());
    EXPECT_FALSE(bundle.private_key_ref.empty());
    EXPECT_EQ(bundle.key_algorithm, KeyAlgorithm::ECDSA_P256);
}

TEST_F(TlsCredentialProviderTest, GetTlsCredential_NotReady_Rejected) {
    // 未 loadMaterials
    TlsCredentialBundle bundle;
    EXPECT_NE(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);
}

// ---- getTlsCredentialState ----

TEST_F(TlsCredentialProviderTest, GetTlsCredentialState) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialState st;
    EXPECT_EQ(provider_->getTlsCredentialState("mqtt", st), ErrorCode::SUCCESS);
    EXPECT_EQ(st.credential_id, "mqtt-primary");
    EXPECT_EQ(st.version, 1u);
    EXPECT_EQ(st.status, TlsCredentialStatus::READY);
    EXPECT_EQ(st.reason_code, 0);
}

// ---- signTls ----

TEST_F(TlsCredentialProviderTest, SignTls_Success_And_Verify) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle bundle;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);

    // 构造摘要（32 字节随机，模拟 TLS transcript digest）
    std::vector<uint8_t> digest(32);
    RAND_bytes(digest.data(), 32);
    TlsSignRequest req;
    req.private_key_ref = bundle.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest = digest;
    req.request_id = "req-1";

    std::vector<uint8_t> sig;
    EXPECT_EQ(provider_->signTls(req, mqtt_peer_.resolve(0), sig), ErrorCode::SUCCESS);
    EXPECT_FALSE(sig.empty());

    // 用叶子证书公钥验签（ECDSA_verify 对 digest）
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY* pk = X509_get0_pubkey(leaf_cert_.get());
    EC_KEY* ec_pub = EVP_PKEY_get1_EC_KEY(pk);
    int rc = ECDSA_verify(0, digest.data(), 32, sig.data(), sig.size(), ec_pub);
    EC_KEY_free(ec_pub);
    EC_KEY_free(ec);
    EXPECT_EQ(rc, 1);
}

TEST_F(TlsCredentialProviderTest, SignTls_TamperedRef_Rejected) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle bundle;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);
    // 篡改 ref
    OpaqueKeyRef tampered = bundle.private_key_ref;
    tampered.data[10] ^= 0xFF;
    TlsSignRequest req;
    req.private_key_ref = tampered;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(32, 0xAB);
    std::vector<uint8_t> sig;
    EXPECT_EQ(provider_->signTls(req, mqtt_peer_.resolve(0), sig),
              ErrorCode::TLS_KEY_REF_INVALID);
}

TEST_F(TlsCredentialProviderTest, SignTls_WrongCaller_AclDenied) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle bundle;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);
    MockPeerResolver other{"other.service"};
    TlsSignRequest req;
    req.private_key_ref = bundle.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(32, 0xAB);
    std::vector<uint8_t> sig;
    EXPECT_EQ(provider_->signTls(req, other.resolve(0), sig), ErrorCode::ACL_DENIED);
}

TEST_F(TlsCredentialProviderTest, SignTls_DigestLengthMismatch) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle bundle;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);
    TlsSignRequest req;
    req.private_key_ref = bundle.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(16, 0xAB);  // 错误长度
    std::vector<uint8_t> sig;
    EXPECT_EQ(provider_->signTls(req, mqtt_peer_.resolve(0), sig),
              ErrorCode::TLS_SIGN_ALGORITHM_NOT_ALLOWED);
}

// ---- ACL ----

TEST_F(TlsCredentialProviderTest, IsAuthorized_MqttService_Allowed) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    EXPECT_TRUE(provider_->isAuthorized("mqtt", mqtt_peer_.resolve(0)));
}

TEST_F(TlsCredentialProviderTest, IsAuthorized_OtherService_Denied) {
    MockPeerResolver other{"diag.service"};
    EXPECT_FALSE(provider_->isAuthorized("mqtt", other.resolve(0)));
}

TEST_F(TlsCredentialProviderTest, IsAuthorized_InvalidPeer_FailClosed) {
    MockPeerResolver inv{""};
    inv.set_valid(false);
    EXPECT_FALSE(provider_->isAuthorized("mqtt", inv.resolve(0)));
}

// ---- 生命周期：轮换 / 撤销 / 旧引用失效 ----

TEST_F(TlsCredentialProviderTest, Rotate_VersionIncrement_AndOldRefInvalid) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle b1;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), b1),
              ErrorCode::SUCCESS);
    uint64_t v1 = b1.version;

    EXPECT_EQ(provider_->rotateCredential("mqtt"), ErrorCode::SUCCESS);
    EXPECT_GT(notify_count_, 0);

    // 旧引用应失效（版本不匹配）
    TlsSignRequest req;
    req.private_key_ref = b1.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(32, 0xAB);
    std::vector<uint8_t> sig;
    EXPECT_EQ(provider_->signTls(req, mqtt_peer_.resolve(0), sig),
              ErrorCode::TLS_KEY_REF_INVALID);

    // 新引用可用
    TlsCredentialBundle b2;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), b2),
              ErrorCode::SUCCESS);
    EXPECT_GT(b2.version, v1);
    req.private_key_ref = b2.private_key_ref;
    EXPECT_EQ(provider_->signTls(req, mqtt_peer_.resolve(0), sig), ErrorCode::SUCCESS);
}

TEST_F(TlsCredentialProviderTest, Revoke_StatusRevoked_AndSignRejected) {
    ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialBundle bundle;
    ASSERT_EQ(provider_->getTlsCredential("mqtt", mqtt_peer_.resolve(0), bundle),
              ErrorCode::SUCCESS);
    EXPECT_EQ(provider_->revokeCredential("mqtt"), ErrorCode::SUCCESS);
    EXPECT_EQ(provider_->getStatus("mqtt"), TlsCredentialStatus::REVOKED);

    TlsSignRequest req;
    req.private_key_ref = bundle.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(32, 0xAB);
    std::vector<uint8_t> sig;
    // REVOKED 状态拒绝签名（版本也已递增使旧引用失效）
    EXPECT_NE(provider_->signTls(req, mqtt_peer_.resolve(0), sig), ErrorCode::SUCCESS);
}

TEST_F(TlsCredentialProviderTest, BootEpoch_ChangesPerInstance) {
    uint64_t e1 = provider_->bootEpoch();
    // 新实例 boot_epoch 不同
    auto p2 = std::make_unique<TlsCredentialProvider>(
        hsm_.get(), key_id_resolver_, TlsCredentialNotifyCallback{});
    uint64_t e2 = p2->bootEpoch();
    EXPECT_NE(e1, e2);
}

// ---- 错误码映射 ----

TEST_F(TlsCredentialProviderTest, ErrorCodes_Mapping) {
    EXPECT_EQ(tls_credential_status_to_string(TlsCredentialStatus::READY), "READY");
    EXPECT_EQ(string_to_tls_credential_status("EXPIRED"), TlsCredentialStatus::EXPIRED);
    EXPECT_EQ(signature_algorithm_to_string(
        SignatureAlgorithm::ECDSA_SECP256R1_SHA256), "ecdsa_secp256r1_sha256");
    EXPECT_EQ(string_to_signature_algorithm("ecdsa_secp256r1_sha256"),
              SignatureAlgorithm::ECDSA_SECP256R1_SHA256);
    EXPECT_EQ(key_algorithm_to_string(KeyAlgorithm::ECDSA_P256), "ecdsa-p256");
    EXPECT_EQ(string_to_key_algorithm("ecdsa-p256"), KeyAlgorithm::ECDSA_P256);
}

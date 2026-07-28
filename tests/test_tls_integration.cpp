// TLS 凭据端到端集成测试（TBOX-SEC-DSN-CR-010）
// 验证 sec_client -> framework-ipc -> SecIpcDispatcher -> TlsCredentialProvider -> HSM 全链路
#include <gtest/gtest.h>

#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "ipc_protocol.h"
#include "hsm_interface.h"
#include "tbox/sec/client.h"
#include "tbox/sec/types.h"
#include "tbox/sec/errors.h"
#include "ipc.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <chrono>

using namespace tbox::sec;

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
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    EC_POINT_oct2point(group, pt, raw.data(), raw.size(), nullptr);
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);
    EvpPkeyUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}
bool write_cert_pem(const std::string& path, X509* cert) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    bool ok = PEM_write_X509(f, cert) == 1;
    fclose(f);
    return ok;
}
X509UP make_root_ca(EVP_PKEY* ca_key) {
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_NAME* n = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char*)"Root CA", -1, -1, 0);
    X509_set_issuer_name(cert.get(), n);
    X509_set_pubkey(cert.get(), ca_key);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 3650 * 24 * 3600L);
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new(); bc->ca = 1;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1); X509_EXTENSION_free(ext); BASIC_CONSTRAINTS_free(bc);
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}
X509UP make_leaf(EVP_PKEY* ca_key, X509* ca_cert, EVP_PKEY* dev_pubkey) {
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 2);
    X509_NAME* n = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char*)"ECU-1", -1, -1, 0);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert));
    X509_set_pubkey(cert.get(), dev_pubkey);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 365 * 24 * 3600L);
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new(); bc->ca = 0;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1); X509_EXTENSION_free(ext); BASIC_CONSTRAINTS_free(bc);
    EXTENDED_KEY_USAGE* eku = EXTENDED_KEY_USAGE_new();
    sk_ASN1_OBJECT_push(eku, OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1));
    X509_EXTENSION* ext2 = X509V3_EXT_i2d(NID_ext_key_usage, 0, eku);
    X509_add_ext(cert.get(), ext2, -1); X509_EXTENSION_free(ext2); EXTENDED_KEY_USAGE_free(eku);
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}

// 固定返回 tbox-mqtt.service 的 peer resolver（绕过 macOS 无 SO_PEERCRED 限制）
class FixedPeerResolver : public PeerCredentialResolver {
public:
    PeerIdentity resolve(int) override {
        PeerIdentity id;
        id.valid = true;
        id.pid = 1;
        id.service_name = "tbox-mqtt.service";
        return id;
    }
};

} // namespace

class TlsCredentialIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_tls_integration_" + std::to_string(getpid());
        std::filesystem::create_directories(test_dir_);
        socket_path_ = test_dir_ + "/sec.sock";

        hsm_ = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, test_dir_);
        hsm_->initialize();
        std::string key_id = "dev+ecu1";
        KeyPair kp;
        hsm_->generate_key_pair(key_id, "ecdsa-p256", kp);

        ca_key_ = gen_ec_key();
        ca_cert_ = make_root_ca(ca_key_.get());
        dev_pkey_ = pkey_from_raw(kp.public_key);
        leaf_ = make_leaf(ca_key_.get(), ca_cert_.get(), dev_pkey_.get());
        ca_path_ = test_dir_ + "/ca.pem";
        chain_path_ = test_dir_ + "/chain.pem";
        write_cert_pem(ca_path_, ca_cert_.get());
        write_cert_pem(chain_path_, leaf_.get());

        provider_ = std::make_unique<TlsCredentialProvider>(
            hsm_.get(), [key_id]() { return key_id; }, nullptr);
        TlsProfileConfig cfg;
        cfg.profile_name = "mqtt";
        cfg.credential_id = "mqtt-primary";
        cfg.allowed_signature_algorithms = {SignatureAlgorithm::ECDSA_SECP256R1_SHA256};
        cfg.peer_service = "tbox-mqtt.service";
        cfg.root_ca_path = ca_path_;
        cfg.client_cert_chain_path = chain_path_;
        provider_->configureProfile(cfg);
        ASSERT_EQ(provider_->loadMaterials("mqtt"), ErrorCode::SUCCESS);

        service_ = std::make_unique<SecService>();
        dispatcher_ = std::make_unique<SecIpcDispatcher>(service_.get());
        dispatcher_->setTlsCredentialProvider(provider_.get());
        dispatcher_->setPeerCredentialResolver(std::make_shared<FixedPeerResolver>());
        dispatcher_->setAddSubscriptionCallback([this](int fd, uint32_t et) {
            return server_ ? server_->add_subscription(fd, et) : false;
        });

        ::tbox::fw::ipc::IpcConfig ipc_cfg;
        ipc_cfg.connect_timeout_ms = 3000;
        ipc_cfg.receive_timeout_ms = 5000;
        server_ = std::make_unique<::tbox::fw::ipc::Server>(socket_path_, ipc_cfg);
        auto* disp = dispatcher_.get();
        ASSERT_TRUE(server_->start(
            [disp](uint32_t m, std::string_view p, int fd) { return disp->dispatch(m, p, fd); },
            [](int) {}));
        // 等待 server 就绪
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    void TearDown() override {
        server_->stop();
        std::filesystem::remove_all(test_dir_);
    }

    std::string test_dir_, socket_path_;
    std::unique_ptr<HsmInterface> hsm_;
    EvpPkeyUP ca_key_;
    X509UP ca_cert_;
    EvpPkeyUP dev_pkey_;
    X509UP leaf_;
    std::string ca_path_, chain_path_;
    std::unique_ptr<TlsCredentialProvider> provider_;
    std::unique_ptr<SecService> service_;
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
    std::unique_ptr<::tbox::fw::ipc::Server> server_;
};

// 全链路：getTlsCredential + signTls + 验签
TEST_F(TlsCredentialIntegrationTest, FullRoundTrip_GetSign_Verify) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());

    TlsCredentialBundle bundle;
    ASSERT_EQ(client.get_tls_credential("mqtt", bundle), ErrorCode::SUCCESS);
    EXPECT_EQ(bundle.credential_id, "mqtt-primary");
    EXPECT_EQ(bundle.status, TlsCredentialStatus::READY);
    EXPECT_FALSE(bundle.root_ca_bundle_der.empty());
    EXPECT_FALSE(bundle.private_key_ref.empty());

    TlsSignRequest req;
    req.private_key_ref = bundle.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(32, 0x42);
    req.request_id = "integ-1";
    std::vector<uint8_t> sig;
    EXPECT_EQ(client.sign_tls(req, sig), ErrorCode::SUCCESS);
    EXPECT_FALSE(sig.empty());

    // 用叶子证书公钥验签
    EVP_PKEY* pk = X509_get0_pubkey(leaf_.get());
    EC_KEY* ec_pub = EVP_PKEY_get1_EC_KEY(pk);
    EXPECT_EQ(ECDSA_verify(0, req.digest.data(), 32, sig.data(), sig.size(), ec_pub), 1);
    EC_KEY_free(ec_pub);
}

// 状态查询往返
TEST_F(TlsCredentialIntegrationTest, GetState_RoundTrip) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    TlsCredentialState st;
    EXPECT_EQ(client.get_tls_credential_state("mqtt", st), ErrorCode::SUCCESS);
    EXPECT_EQ(st.status, TlsCredentialStatus::READY);
    EXPECT_EQ(st.version, 1u);
}

// 轮换后旧引用经 IPC 失效
TEST_F(TlsCredentialIntegrationTest, Rotation_OldRefInvalidViaIpc) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    TlsCredentialBundle b1;
    ASSERT_EQ(client.get_tls_credential("mqtt", b1), ErrorCode::SUCCESS);

    // 服务端轮换
    ASSERT_EQ(provider_->rotateCredential("mqtt"), ErrorCode::SUCCESS);

    // 旧引用签名应失败（SEC-1012）
    TlsSignRequest req;
    req.private_key_ref = b1.private_key_ref;
    req.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    req.digest.assign(32, 0x42);
    std::vector<uint8_t> sig;
    EXPECT_EQ(client.sign_tls(req, sig), ErrorCode::TLS_KEY_REF_INVALID);

    // 新引用可用
    TlsCredentialBundle b2;
    ASSERT_EQ(client.get_tls_credential("mqtt", b2), ErrorCode::SUCCESS);
    EXPECT_GT(b2.version, b1.version);
    req.private_key_ref = b2.private_key_ref;
    EXPECT_EQ(client.sign_tls(req, sig), ErrorCode::SUCCESS);
}

// 撤销后状态为 REVOKED
TEST_F(TlsCredentialIntegrationTest, Revoke_StatusRevokedViaIpc) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    ASSERT_EQ(provider_->revokeCredential("mqtt"), ErrorCode::SUCCESS);
    TlsCredentialState st;
    EXPECT_EQ(client.get_tls_credential_state("mqtt", st), ErrorCode::SUCCESS);
    EXPECT_EQ(st.status, TlsCredentialStatus::REVOKED);
}

// TLS IPC handler 测试（TBOX-SEC-DSN-CR-010）
// 验证 SecIpcDispatcher 的 get/state/sign/subscribe 路由、ACL、错误码映射
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "ipc_protocol.h"
#include "hsm_interface.h"
#include "tbox/sec/types.h"
#include "tbox/sec/errors.h"
#include "utils.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <nlohmann/json.hpp>
#include <cstdio>
#include <memory>
#include <vector>

using namespace tbox::sec;
using json = nlohmann::json;

namespace {

struct X509Deleter { void operator()(X509* p) const { if (p) X509_free(p); } };
using X509UP = std::unique_ptr<X509, X509Deleter>;
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
using EvpPkeyUP = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

EvpPkeyUP gen_ec_key() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return {};
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
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"Root CA", -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    X509_set_pubkey(cert.get(), ca_key);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 3650 * 24 * 3600L);
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = 1;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    BASIC_CONSTRAINTS_free(bc);
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}

X509UP make_leaf(EVP_PKEY* ca_key, X509* ca_cert, EVP_PKEY* dev_pubkey) {
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 2);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"ECU-1", -1, -1, 0);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert));
    X509_set_pubkey(cert.get(), dev_pubkey);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 365 * 24 * 3600L);
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = 0;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    BASIC_CONSTRAINTS_free(bc);
    EXTENDED_KEY_USAGE* eku = EXTENDED_KEY_USAGE_new();
    sk_ASN1_OBJECT_push(eku, OBJ_txt2obj("1.3.6.1.5.5.7.3.2", 1));
    X509_EXTENSION* ext2 = X509V3_EXT_i2d(NID_ext_key_usage, 0, eku);
    X509_add_ext(cert.get(), ext2, -1);
    X509_EXTENSION_free(ext2);
    EXTENDED_KEY_USAGE_free(eku);
    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert;
}

class MockPeerResolver : public PeerCredentialResolver {
public:
    bool valid = true;
    std::string service = "tbox-mqtt.service";
    PeerIdentity resolve(int) override {
        PeerIdentity id;
        id.valid = valid;
        id.pid = 1;
        id.uid = 2;
        id.gid = 3;
        id.service_name = service;
        return id;
    }
};

} // namespace

class TlsIpcHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_tls_ipc";
        std::system(("rm -rf " + test_dir_ + " && mkdir -p " + test_dir_).c_str());

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

        // provider
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

        // dispatcher: TLS handler 不依赖 SecService，用默认实例占位
        service_ = std::make_unique<SecService>();
        dispatcher_ = std::make_unique<SecIpcDispatcher>(service_.get());
        dispatcher_->setTlsCredentialProvider(provider_.get());
        peer_resolver_ = std::make_shared<MockPeerResolver>();
        dispatcher_->setPeerCredentialResolver(peer_resolver_);
        sub_called_ = false;
        dispatcher_->setAddSubscriptionCallback(
            [this](int, uint32_t) { sub_called_ = true; return true; });
    }

    void TearDown() override {
        std::system(("rm -rf " + test_dir_).c_str());
    }

    int32_t status_of(const std::string& resp) {
        return json::parse(resp).value("status", -1);
    }

    std::string test_dir_;
    std::unique_ptr<HsmInterface> hsm_;
    EvpPkeyUP ca_key_;
    X509UP ca_cert_;
    EvpPkeyUP dev_pkey_;
    X509UP leaf_;
    std::string ca_path_, chain_path_;
    std::unique_ptr<SecService> service_;
    std::unique_ptr<TlsCredentialProvider> provider_;
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
    std::shared_ptr<MockPeerResolver> peer_resolver_;
    bool sub_called_ = false;
};

// ---- GET_TLS_CREDENTIAL ----

TEST_F(TlsIpcHandlerTest, GetTlsCredential_Success) {
    json params; params["profile"] = "mqtt";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump(), 1);
    EXPECT_EQ(status_of(resp), 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("credential_id", ""), "mqtt-primary");
    EXPECT_FALSE(j.value("root_ca_bundle", "").empty());
    EXPECT_FALSE(j.value("client_cert_chain", "").empty());
    EXPECT_FALSE(j.value("private_key_ref", "").empty());
    EXPECT_EQ(j.value("credential_status", ""), "READY");
}

TEST_F(TlsIpcHandlerTest, GetTlsCredential_AclDenied) {
    peer_resolver_->service = "other.service";
    json params; params["profile"] = "mqtt";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

TEST_F(TlsIpcHandlerTest, GetTlsCredential_AclFailClosed_InvalidPeer) {
    peer_resolver_->valid = false;
    json params; params["profile"] = "mqtt";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

// ---- GET_TLS_CREDENTIAL_STATE ----

TEST_F(TlsIpcHandlerTest, GetTlsCredentialState_Success) {
    json params; params["profile"] = "mqtt";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL_STATE), params.dump(), 1);
    EXPECT_EQ(status_of(resp), 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("credential_status", ""), "READY");
    EXPECT_EQ(j.value("version", 0), 1);
}

// ---- SIGN_TLS ----

TEST_F(TlsIpcHandlerTest, SignTls_Success) {
    // 先获取 bundle 拿到 private_key_ref
    json p; p["profile"] = "mqtt";
    auto r = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), p.dump(), 1);
    auto j = json::parse(r);
    std::string ref_b64 = j.value("private_key_ref", "");
    ASSERT_FALSE(ref_b64.empty());

    std::vector<uint8_t> digest(32);
    RAND_bytes(digest.data(), 32);
    json sp;
    sp["private_key_ref"] = ref_b64;
    sp["algorithm"] = "ecdsa_secp256r1_sha256";
    // base64 digest
    sp["digest"] = ::hwyz::Utils::base64_encode(
        std::string(reinterpret_cast<const char*>(digest.data()), digest.size()));
    sp["request_id"] = "r1";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SIGN_TLS), sp.dump(), 1);
    EXPECT_EQ(status_of(resp), 0);
    EXPECT_FALSE(json::parse(resp).value("signature", "").empty());
}

TEST_F(TlsIpcHandlerTest, SignTls_TamperedRef_1012) {
    json sp;
    sp["private_key_ref"] = "AAAAAAAAAAAA";  // 无效
    sp["algorithm"] = "ecdsa_secp256r1_sha256";
    sp["digest"] = "AAAA";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SIGN_TLS), sp.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::TLS_KEY_REF_INVALID));
}

TEST_F(TlsIpcHandlerTest, SignTls_AclDenied) {
    // 用 mqtt peer 拿到 ref，再用 other peer 签名
    json p; p["profile"] = "mqtt";
    auto r = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), p.dump(), 1);
    auto j = json::parse(r);
    std::string ref_b64 = j.value("private_key_ref", "");

    peer_resolver_->service = "other.service";
    json sp;
    sp["private_key_ref"] = ref_b64;
    sp["algorithm"] = "ecdsa_secp256r1_sha256";
    sp["digest"] = "AAAA";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SIGN_TLS), sp.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

// ---- SUBSCRIBE_TLS_CREDENTIAL_CHANGED ----

TEST_F(TlsIpcHandlerTest, Subscribe_Success) {
    json params; params["profile"] = "mqtt";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TLS_CREDENTIAL_CHANGED),
        params.dump(), 1);
    EXPECT_EQ(status_of(resp), 0);
    EXPECT_TRUE(sub_called_);
    EXPECT_EQ(json::parse(resp).value("event_type", 0),
              static_cast<int>(ipc::EventId::TLS_CREDENTIAL_CHANGED));
}

TEST_F(TlsIpcHandlerTest, Subscribe_AclDenied) {
    peer_resolver_->service = "other.service";
    json params; params["profile"] = "mqtt";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TLS_CREDENTIAL_CHANGED),
        params.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
    EXPECT_FALSE(sub_called_);
}

// ---- 错误码：未就绪 SEC-1010 ----

TEST_F(TlsIpcHandlerTest, GetTlsCredential_NotReady_1010) {
    // 重新配置一个未加载材料的 profile
    TlsProfileConfig cfg;
    cfg.profile_name = "mqtt2";
    cfg.credential_id = "x";
    cfg.peer_service = "tbox-mqtt.service";
    cfg.root_ca_path = "/nope";
    cfg.client_cert_chain_path = "/nope";
    provider_->configureProfile(cfg);
    // loadMaterials 失败
    provider_->loadMaterials("mqtt2");
    json params; params["profile"] = "mqtt2";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_NOT_READY));
}

// ---- 无 provider 时返回 NOT_IMPLEMENTED ----

TEST_F(TlsIpcHandlerTest, NoProvider_NotImplemented) {
    SecIpcDispatcher d(service_.get());  // 未注入 provider
    json params; params["profile"] = "mqtt";
    auto resp = d.dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump(), 1);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED));
}

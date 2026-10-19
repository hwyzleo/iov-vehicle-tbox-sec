//
// V2C 业务密钥 IPC handler 测试（TBOX-SEC-DSN-CR-019 §3；CR-020 §4/§7/§US-020）。
// 验证 SecIpcDispatcher 的 3 个 method 路由、ACL fail-closed、错误码映射与 JSON wire
// （含 ECDH-ES P-256 v1 信封字段与 ACK 绑定字段回传）。
//
#include <gtest/gtest.h>

#include "sec_ipc_dispatcher.h"
#include "business_key_provisioning.h"
#include "business_key_provider.h"
#include "keyprov_envelope_builder.h"
#include "soft_file_business_key_provider.h"
#include "soft_file_hsm.h"
#include "secure_metadata_ledger.h"
#include "peer_credential.h"
#include "trusted_time.h"
#include "ipc_protocol.h"
#include "store.h"
#include "utils.h"
#include "tbox/sec/business_key.h"

#include <openssl/rand.h>

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

using namespace tbox::sec;
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

const std::string kDeviceKeyId = "ecu1+ecu1";
const std::string kDeviceIdentity = "ecu1";

class MockPeerResolver : public PeerCredentialResolver {
public:
    bool valid = true;
    std::string service = "tbox-tsp.service";
    PeerIdentity resolve(int) override {
        PeerIdentity id;
        id.valid = valid;
        id.uid = 0;
        id.gid = 0;
        id.service_name = service;
        return id;
    }
};

std::string unique_dir() {
    auto p = fs::temp_directory_path() /
             ("tbox-sec-bkipc-" + std::to_string(::getpid()) + "-" +
              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(p);
    return p.string();
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::vector<uint8_t> random_key() {
    std::vector<uint8_t> k(32);
    RAND_bytes(k.data(), 32);
    return k;
}

std::string b64(const std::vector<uint8_t>& v) {
    return ::hwyz::Utils::base64_encode(
        std::string(reinterpret_cast<const char*>(v.data()), v.size()));
}

int32_t status_of(const std::string& resp) {
    return json::parse(resp).value("status", -1);
}

class BusinessKeyIpcTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = unique_dir();
        store_ = std::make_unique<hwyz::store::Store>(
            hwyz::store::Store::open("sec", dir_));
        hsm_ = std::make_unique<SoftFileHsm>(
            hwyz::store::Store::open("sec_hsm", dir_), "aes-256-gcm",
            dir_ + "/.hsm_kek");
        ASSERT_EQ(hsm_->initialize(), ErrorCode::SUCCESS);
        KeyPair kp;
        ASSERT_EQ(hsm_->generate_key_pair(kDeviceKeyId, "ecdsa-p256", kp), ErrorCode::SUCCESS);
        device_pub_ = kp.public_key;

        binding_.ready = true;
        binding_.device_identity = kDeviceIdentity;
        binding_.device_key_id = kDeviceKeyId;
        binding_.device_public_key = device_pub_;
        binding_.active_cert_p256 = true;
        binding_.active_cert_key_agreement = true;
        binding_.active_cert_digital_signature = true;
        binding_.private_key_can_derive = true;
        binding_.private_key_can_sign = true;
        binding_.active_cert_digest = std::vector<uint8_t>(32, 0xBB);

        BusinessKeyProviderConfig pcfg;
        pcfg.store_root = dir_ + "/bk";
        pcfg.kek_path = dir_ + "/bk/.kek";
        pcfg.allowed_algorithms = {kDefaultKeyAlgorithm};
        pcfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
        auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
            hsm_.get(), std::move(pcfg), [this]() { return binding_; });

        TrustedTimeSample s;
        s.utc_now = std::chrono::system_clock::now();
        s.trust_state = TimeTrustState::Trusted;
        s.source = TimeSource::FakeTest;
        s.reason = TimeReason::FakeTest;

        BusinessKeyProvisioningConfig cfg;
        cfg.enabled = true;
        cfg.is_production = false;
        cfg.allowed_algorithms = {kDefaultKeyAlgorithm};
        cfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
        cfg.allowed_envelope_formats = {kKeyEnvelopeFormatEcdhEsP256V1};
        service_ = std::make_unique<BusinessKeyProvisioningService>(
            std::move(cfg), std::move(provider), std::make_shared<FakeTrustedTimeProvider>(s),
            std::make_unique<SecureMetadataLedger>(hwyz::store::Store::open("sec", dir_)),
            [this]() { return binding_; });
        ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);

        dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
        dispatcher_->setBusinessKeyService(service_.get());
        peer_ = std::make_shared<MockPeerResolver>();
        dispatcher_->setPeerCredentialResolver(peer_);
        dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");
    }

    void TearDown() override {
        dispatcher_.reset();
        service_.reset();
        hsm_.reset();
        store_.reset();
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    json make_import_params(const std::string& request_id, uint64_t version) {
        json items = json::array();
        auto add = [&](const std::string& purpose, const std::string& key_id) {
            std::vector<uint8_t> key = random_key();
            KeyprovEnvelopeInput in;
            in.device_public_key = device_pub_;
            in.request_id = request_id;
            in.business_domain = kBusinessDomainV2c;
            in.purpose = purpose;
            in.key_id = key_id;
            in.business_key_version = version;
            in.business_key = key;
            in.root_key_version = 1;
            in.derivation_version = "v1";
            in.operation_id = "op-" + purpose;
            in.recipient_certificate_digest = binding_.active_cert_digest;
            in.wrapping_suite = kWrappingSuiteEcdhEsP256;
            in.key_algorithm = kDefaultKeyAlgorithm;
            KeyprovEnvelopeOutput out;
            EXPECT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
            json e;
            e["purpose"] = purpose;
            e["key_id"] = key_id;
            e["business_key_version"] = version;
            e["algorithm"] = kDefaultKeyAlgorithm;
            e["wrapping_suite"] = kWrappingSuiteEcdhEsP256;
            e["envelope_format"] = kKeyEnvelopeFormatEcdhEsP256V1;
            e["wrapped_key"] = b64(out.wrapped_key);
            e["parameters"] = b64(out.parameters);
            e["envelope_digest"] = b64(out.envelope_digest);
            e["key_check_value"] = b64(std::vector<uint8_t>(
                out.key_check_value.begin(), out.key_check_value.end()));
            e["valid_from_ms"] = now_ms() - 1000;
            e["valid_to_ms"] = now_ms() + 86400000;
            items.push_back(e);
        };
        add(kBusinessPurposeUplinkAead, "kid-up");
        add(kBusinessPurposeDownlinkAead, "kid-down");
        json p;
        p["request_id"] = request_id;
        p["business_domain"] = kBusinessDomainV2c;
        p["items"] = items;
        return p;
    }

    std::string dir_;
    std::unique_ptr<hwyz::store::Store> store_;
    std::unique_ptr<SoftFileHsm> hsm_;
    std::vector<uint8_t> device_pub_;
    BusinessKeyDeviceBinding binding_;
    std::unique_ptr<BusinessKeyProvisioningService> service_;
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
    std::shared_ptr<MockPeerResolver> peer_;
};

TEST_F(BusinessKeyIpcTest, Import_And_Status_RoundTrip) {
    auto params = make_import_params("ipc-req-1", 1);
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS),
        params.dump(), 0);
    EXPECT_EQ(status_of(resp), 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("state", ""), "COMMITTED");
    EXPECT_EQ(j.value("proof_algorithm", ""), kImportProofAlgorithmP1363);
    ASSERT_TRUE(j.contains("items") && j["items"].is_array());
    for (const auto& it : j["items"]) {
        // 逐 item Import Attestation（64B P1363 low-S）经 IPC 回传。
        EXPECT_FALSE(it.value("import_proof", "").empty());
        EXPECT_EQ(it.value("proof_algorithm", ""), kImportProofAlgorithmP1363);
        // CR-012 Q3：完整 key_id + 逐 item 证书摘要
        EXPECT_FALSE(it.value("key_id", "").empty());
        EXPECT_EQ(it.value("recipient_certificate_digest", ""),
                  b64(binding_.active_cert_digest));
    }

    json sp;
    sp["business_domain"] = kBusinessDomainV2c;
    sp["purposes"] = json::array({kBusinessPurposeUplinkAead, kBusinessPurposeDownlinkAead});
    auto sresp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_STATUS), sp.dump(), 0);
    EXPECT_EQ(status_of(sresp), 0);
    auto sj = json::parse(sresp);
    ASSERT_TRUE(sj.contains("items"));
    EXPECT_EQ(sj["items"].size(), 2u);
    for (const auto& it : sj["items"]) {
        EXPECT_EQ(it.value("state", ""), "ACTIVE");
        // ACK 绑定字段（§US-020）经 IPC wire 回传
        EXPECT_EQ(it.value("envelope_format", ""), kKeyEnvelopeFormatEcdhEsP256V1);
        EXPECT_FALSE(it.value("envelope_digest", "").empty());
        EXPECT_FALSE(it.value("key_check_value", "").empty());
    }
}

TEST_F(BusinessKeyIpcTest, Result_Query) {
    auto params = make_import_params("ipc-req-2", 1);
    dispatcher_->dispatch(static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS),
                          params.dump(), 0);
    json q;
    q["request_id"] = "ipc-req-2";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_IMPORT_RESULT), q.dump(), 0);
    EXPECT_EQ(status_of(resp), 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("state", ""), "COMMITTED");
    // TBOX-TSP-DSN-CR-012 Q3：结果查询返回完整 key_id 与逐 item 证书摘要，
    // 供 TSP 重启后重建原 ACK（ack.key_id == response.key_id）。
    ASSERT_TRUE(j.contains("items") && j["items"].is_array());
    ASSERT_EQ(j["items"].size(), 2u);
    EXPECT_EQ(j["items"][0].value("key_id", ""), "kid-up");
    EXPECT_EQ(j["items"][1].value("key_id", ""), "kid-down");
    for (const auto& it : j["items"]) {
        EXPECT_EQ(it.value("recipient_certificate_digest", ""),
                  b64(binding_.active_cert_digest));
        // 64B → base64 恰为 88 字符（P1363 low-S）
        EXPECT_EQ(it.value("import_proof", "").size(), 88u);
    }
}

TEST_F(BusinessKeyIpcTest, Capability_Query) {
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_V2C_KEY_PROVISIONING_CAPABILITY),
        "{}", 0);
    EXPECT_EQ(status_of(resp), 0);
    auto j = json::parse(resp);
    EXPECT_TRUE(j.value("success", false));
    EXPECT_EQ(j.value("capability_contract_version", 0u),
              V2cKeyProvisioningCapability::kContractVersion);
    // TBOX-TSP-DSN-CR-012 §8：四项显式门禁必须可区分
    EXPECT_TRUE(j.contains("envelope_v1_import_ready"));
    EXPECT_TRUE(j.contains("atomic_dual_purpose_commit_ready"));
    EXPECT_TRUE(j.contains("import_proof_sign_ecdsa_p256_v1_ready"));
    EXPECT_TRUE(j.contains("secure_journal_replay_ready"));
}

TEST_F(BusinessKeyIpcTest, Capability_AclDenied_WrongPeer) {
    peer_->service = "tbox-diag.service";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_V2C_KEY_PROVISIONING_CAPABILITY),
        "{}", 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

TEST_F(BusinessKeyIpcTest, AclDenied_WrongPeer) {
    peer_->service = "tbox-diag.service";
    auto params = make_import_params("ipc-req-3", 1);
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS),
        params.dump(), 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

TEST_F(BusinessKeyIpcTest, AclDenied_InvalidPeer) {
    peer_->valid = false;
    json sp;
    sp["business_domain"] = kBusinessDomainV2c;
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_STATUS), sp.dump(), 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

TEST_F(BusinessKeyIpcTest, NoService_NotImplemented) {
    SecIpcDispatcher d(nullptr);
    d.setPeerCredentialResolver(peer_);
    auto resp = d.dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_STATUS), "{}", 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED));
}

TEST_F(BusinessKeyIpcTest, Import_SecondFailure_ReturnsError) {
    auto params = make_import_params("ipc-req-4", 1);
    params["items"][1]["algorithm"] = "AES-999-BOGUS";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS),
        params.dump(), 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::BUSINESS_KEY_UNSUPPORTED));
}

TEST_F(BusinessKeyIpcTest, Import_UnsupportedFormat_ReturnsError) {
    auto params = make_import_params("ipc-req-5", 1);
    params["items"][0]["envelope_format"] = "ECIES-ECDH-ES-A256GCM-v1";
    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS),
        params.dump(), 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::BUSINESS_KEY_UNSUPPORTED));
}

} // namespace

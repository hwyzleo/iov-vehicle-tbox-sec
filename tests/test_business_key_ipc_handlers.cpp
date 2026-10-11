//
// V2C 业务密钥 IPC handler 测试（TBOX-SEC-DSN-CR-019 §3）。
// 验证 SecIpcDispatcher 的 3 个新 method 路由、ACL fail-closed、错误码映射与 JSON wire。
//
#include <gtest/gtest.h>

#include "sec_ipc_dispatcher.h"
#include "business_key_provisioning.h"
#include "business_key_provider.h"
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

        BusinessKeyProviderConfig pcfg;
        pcfg.store_root = dir_ + "/bk";
        pcfg.kek_path = dir_ + "/bk/.kek";
        pcfg.allowed_algorithms = {"AES-256-GCM"};
        pcfg.allowed_wrapping_suites = {
            SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm};
        auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
            hsm_.get(), std::move(pcfg), [this]() { return binding_; });

        TrustedTimeSample s;
        s.utc_now = std::chrono::system_clock::now();
        s.trust_state = TimeTrustState::Trusted;
        s.source = TimeSource::FakeTest;
        s.reason = TimeReason::FakeTest;

        BusinessKeyProvisioningConfig cfg;
        cfg.enabled = true;
        cfg.allowed_wrapping_suites = {
            SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm};
        cfg.allowed_algorithms = {"AES-256-GCM"};
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
            std::vector<uint8_t> aad = BusinessKeyProvisioningService::buildAad(
                request_id, kBusinessDomainV2c, purpose, version, kDeviceIdentity);
            std::vector<uint8_t> wrapped;
            std::string params;
            EXPECT_EQ(SoftFileBusinessKeyProvider::wrapForTest(
                          device_pub_,
                          SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm,
                          aad, random_key(), wrapped, params),
                      ErrorCode::SUCCESS);
            json e;
            e["purpose"] = purpose;
            e["key_id"] = key_id;
            e["business_key_version"] = version;
            e["algorithm"] = "AES-256-GCM";
            e["wrapped_key"] = b64(wrapped);
            e["parameters"] = b64(std::vector<uint8_t>(params.begin(), params.end()));
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
    EXPECT_FALSE(j.value("import_proof", "").empty());

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
    EXPECT_EQ(json::parse(resp).value("state", ""), "COMMITTED");
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

} // namespace

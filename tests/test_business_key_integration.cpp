//
// V2C 业务密钥开通集成测试（TBOX-SEC-DSN-CR-019；CR-020 §4/§7/§US-020）。
// 真实 framework-ipc Server + tbox::sec_client 全链路：ECDH-ES P-256 v1 信封 ->
// import -> 状态/结果查询；验证调用方从未获得明文密钥、非幂等导入不重放。
//
#include <gtest/gtest.h>

#include "tbox/sec/client.h"
#include "sec_ipc_dispatcher.h"
#include "business_key_provisioning.h"
#include "business_key_provider.h"
#include "keyprov_envelope_builder.h"
#include "soft_file_business_key_provider.h"
#include "soft_file_hsm.h"
#include "secure_metadata_ledger.h"
#include "peer_credential.h"
#include "trusted_time.h"
#include "ipc.h"
#include "store.h"
#include "utils.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

using namespace tbox::sec;
namespace fs = std::filesystem;

namespace {

const std::string kDeviceKeyId = "ecu1+ecu1";
const std::string kDeviceIdentity = "ecu1";

class TspPeerResolver : public PeerCredentialResolver {
public:
    PeerIdentity resolve(int) override {
        PeerIdentity id;
        id.valid = true;
        id.pid = 1;
        id.uid = 0;
        id.gid = 0;
        id.service_name = "tbox-tsp.service";
        return id;
    }
};

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

class BusinessKeyIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_bk_integration_" + std::to_string(getpid()) + "_" +
                    std::to_string(now_ms());
        fs::create_directories(test_dir_);
        socket_path_ = test_dir_ + "/sec.sock";

        store_ = std::make_unique<hwyz::store::Store>(
            hwyz::store::Store::open("sec", test_dir_));
        hsm_ = std::make_unique<SoftFileHsm>(
            hwyz::store::Store::open("sec_hsm", test_dir_), "aes-256-gcm",
            test_dir_ + "/.hsm_kek");
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
        binding_.private_key_can_derive = true;
        binding_.active_cert_digest = std::vector<uint8_t>(32, 0xBB);

        BusinessKeyProviderConfig pcfg;
        pcfg.store_root = test_dir_ + "/bk";
        pcfg.kek_path = test_dir_ + "/bk/.kek";
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
            std::make_unique<SecureMetadataLedger>(hwyz::store::Store::open("sec", test_dir_)),
            [this]() { return binding_; });
        ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);

        dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
        dispatcher_->setBusinessKeyService(service_.get());
        dispatcher_->setPeerCredentialResolver(std::make_shared<TspPeerResolver>());
        dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");

        ::tbox::fw::ipc::IpcConfig ipc_cfg;
        ipc_cfg.connect_timeout_ms = 3000;
        ipc_cfg.receive_timeout_ms = 5000;
        server_ = std::make_unique<::tbox::fw::ipc::Server>(socket_path_, ipc_cfg);
        auto* disp = dispatcher_.get();
        ASSERT_TRUE(server_->start(
            [disp](uint32_t m, std::string_view p, int fd) { return disp->dispatch(m, p, fd); },
            [](int) {}));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    void TearDown() override {
        if (server_) server_->stop();
        service_.reset();
        hsm_.reset();
        store_.reset();
        std::error_code ec;
        fs::remove_all(test_dir_, ec);
    }

    WrappedKeyItem make_item(const std::string& request_id, const std::string& purpose,
                             const std::string& key_id, uint64_t version) {
        std::vector<uint8_t> key(32);
        RAND_bytes(key.data(), 32);
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
        OPENSSL_cleanse(key.data(), key.size());

        WrappedKeyItem item;
        item.purpose = purpose;
        item.key_id = key_id;
        item.business_key_version = version;
        item.algorithm = kDefaultKeyAlgorithm;
        item.wrapping_suite = kWrappingSuiteEcdhEsP256;
        item.envelope_format = KeyEnvelopeFormat::ECDH_ES_P256_V1;
        item.wrapped_key.assign(out.wrapped_key);
        item.parameters.assign(out.parameters);
        item.envelope_digest = out.envelope_digest;
        item.key_check_value = out.key_check_value;
        item.key_check_value_present = true;
        item.valid_from_ms = now_ms() - 1000;
        item.valid_to_ms = now_ms() + 86400000;
        return item;
    }

    std::vector<WrappedKeyItem> make_batch(const std::string& request_id, uint64_t version) {
        std::vector<WrappedKeyItem> items;
        items.push_back(make_item(request_id, kBusinessPurposeUplinkAead, "kid-up", version));
        items.push_back(make_item(request_id, kBusinessPurposeDownlinkAead, "kid-down", version));
        return items;
    }

    std::string test_dir_, socket_path_;
    std::unique_ptr<hwyz::store::Store> store_;
    std::unique_ptr<SoftFileHsm> hsm_;
    std::vector<uint8_t> device_pub_;
    BusinessKeyDeviceBinding binding_;
    std::unique_ptr<BusinessKeyProvisioningService> service_;
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
    std::unique_ptr<::tbox::fw::ipc::Server> server_;
};

TEST_F(BusinessKeyIntegrationTest, FullRoundTrip_Import_Status_Result) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());

    auto items = make_batch("int-req-1", 1);
    ImportResult result;
    ASSERT_EQ(client.import_wrapped_business_keys("int-req-1", kBusinessDomainV2c, items, result),
              ErrorCode::SUCCESS);
    EXPECT_EQ(result.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(result.items.size(), 2u);
    EXPECT_FALSE(result.import_proof.empty());
    EXPECT_EQ(result.proof_algorithm, "HMAC-SHA256");

    BusinessKeyStatusSet status;
    ASSERT_EQ(client.get_business_key_status(
                  kBusinessDomainV2c,
                  {kBusinessPurposeUplinkAead, kBusinessPurposeDownlinkAead}, status),
              ErrorCode::SUCCESS);
    ASSERT_EQ(status.items.size(), 2u);
    for (const auto& s : status.items) {
        EXPECT_EQ(s.state, BusinessKeyState::ACTIVE);
        // ACK 绑定字段经 IPC 全链路回传（§US-020）
        EXPECT_EQ(s.envelope_format, KeyEnvelopeFormat::ECDH_ES_P256_V1);
        EXPECT_EQ(s.envelope_digest.size(), 32u);
        EXPECT_TRUE(s.key_check_value_present);
    }

    ImportResult queried;
    ASSERT_EQ(client.get_business_key_import_result("int-req-1", queried), ErrorCode::SUCCESS);
    EXPECT_EQ(queried.state, BusinessKeyImportState::COMMITTED);
}

TEST_F(BusinessKeyIntegrationTest, Idempotent_Reimport_SameItems) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    auto items = make_batch("int-req-2", 1);
    ImportResult r1;
    ASSERT_EQ(client.import_wrapped_business_keys("int-req-2", kBusinessDomainV2c, items, r1),
              ErrorCode::SUCCESS);
    // 同一批次重复导入：服务端幂等，返回原结果
    ImportResult r2;
    ASSERT_EQ(client.import_wrapped_business_keys("int-req-2", kBusinessDomainV2c, items, r2),
              ErrorCode::SUCCESS);
    EXPECT_EQ(r2.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(r1.items[0].key_id_digest, r2.items[0].key_id_digest);
}

TEST_F(BusinessKeyIntegrationTest, ImportResult_UnknownRequest) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    ImportResult r;
    ASSERT_EQ(client.get_business_key_import_result("no-such-request", r), ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::UNKNOWN);
}

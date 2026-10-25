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
#include "ipc_protocol.h"
#include "store.h"
#include "utils.h"

#include <nlohmann/json.hpp>

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
        binding_.active_cert_digital_signature = true;
        binding_.private_key_can_derive = true;
        binding_.private_key_can_sign = true;
        binding_.active_cert_digest = std::vector<uint8_t>(32, 0xBB);
        binding_.active_cert_ca_false = true;
        binding_.active_cert_eku_client_auth_only = true;
        binding_.active_cert_critical_extensions_allowed = true;
        binding_.active_cert_leaf_digest_bound = true;
        binding_.active_cert_chain_key_match = true;
        binding_.identity_template_sign_derive = true;
        // KL1 准入：证书有效期须覆盖租约 E（默认长有效；CR-023）。
        binding_.active_cert_valid_from_ms = now_ms() - 86400000;
        binding_.active_cert_valid_to_ms = now_ms() + 86400000;

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
    EXPECT_EQ(result.proof_algorithm, kImportProofAlgorithmP1363);
    EXPECT_EQ(result.binding_certificate_digest, binding_.active_cert_digest);
    for (const auto& it : result.items) {
        EXPECT_EQ(it.import_proof.size(), kImportProofSizeP1363);
        EXPECT_EQ(it.proof_algorithm, kImportProofAlgorithmP1363);
    }

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

TEST_F(BusinessKeyIntegrationTest, ImportResult_NotFound_FreshNoResidue) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    ImportResult r;
    ASSERT_EQ(client.get_business_key_import_result("no-such-request", r), ErrorCode::SUCCESS);
    // TBOX-SEC-DSN-CR-021：fresh 设备无记录 + 无残留 → NOT_FOUND（区别于 UNKNOWN）
    EXPECT_EQ(r.state, BusinessKeyImportState::NOT_FOUND);
}

// 确定性拒绝（validate_structure 校验失败）时 client 必须解析权威 result：
// status=BUSINESS_KEY_UNSUPPORTED（非 0）同样携带 state=FAILED，调用方据此
// 分类为 fail-closed，而不是被误判为“结果未知可重试”（现场：key_algorithm 不符
// 导致 30s 无限重发）。
TEST_F(BusinessKeyIntegrationTest, DeterministicReject_ParsesFailedState) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());

    // 构造算法为 "AES"（非协议 canonical AES-256）的批次 → validate_structure 拒绝
    auto items = make_batch("det-rej-1", 1);
    for (auto& it : items) {
        it.algorithm = "AES";
    }
    ImportResult result;
    ASSERT_EQ(client.import_wrapped_business_keys("det-rej-1", kBusinessDomainV2c, items, result),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);
    // 修复后：错误 status 也解析响应体，state=FAILED 可见（此前保持 UNKNOWN）
    EXPECT_EQ(result.state, BusinessKeyImportState::FAILED);
    // 未受理：不得留下 journal / 副作用
    ImportResult queried;
    ASSERT_EQ(client.get_business_key_import_result("det-rej-1", queried), ErrorCode::SUCCESS);
    EXPECT_EQ(queried.state, BusinessKeyImportState::NOT_FOUND);
}

// TBOX-SEC-DSN-CR-021 §4：client parser 兼容矩阵（数值+稳定字符串 additive 编码）。
// 用固定响应的 stub server 验证：旧 SEC（无 state_code）、未知数值、数值/字符串冲突、
// 缺失 state 均映射 UNKNOWN；已知 NOT_FOUND 正常映射。
TEST_F(BusinessKeyIntegrationTest, ClientParser_CompatMatrix) {
    const std::string stub_sock = test_dir_ + "/stub.sock";
    ::tbox::fw::ipc::IpcConfig cfg;
    cfg.connect_timeout_ms = 3000;
    cfg.receive_timeout_ms = 5000;
    auto stub = std::make_unique<::tbox::fw::ipc::Server>(stub_sock, cfg);
    std::string stub_response;
    ASSERT_TRUE(stub->start(
        [&](uint32_t m, std::string_view, int) -> std::string {
            if (m != static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_IMPORT_RESULT)) {
                return "{\"status\":306}";
            }
            return stub_response;
        },
        [](int) {}));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    SecClient client(stub_sock);
    ASSERT_TRUE(client.connect());

    // 旧 SEC 响应（无 state_code）：仅按稳定字符串映射；新 client 不得推断 NOT_FOUND
    stub_response =
        "{\"status\":0,\"request_id\":\"x\",\"business_domain\":\"V2C_COMM\","
        "\"state\":\"UNKNOWN\",\"items\":[]}";
    ImportResult r1;
    ASSERT_EQ(client.get_business_key_import_result("x", r1), ErrorCode::SUCCESS);
    EXPECT_EQ(r1.state, BusinessKeyImportState::UNKNOWN);

    // 已知 NOT_FOUND（数值 5 + 稳定字符串）→ 正常映射
    stub_response =
        "{\"status\":0,\"request_id\":\"x\",\"business_domain\":\"V2C_COMM\","
        "\"state\":\"NOT_FOUND\",\"state_code\":5,\"items\":[]}";
    ImportResult r2;
    ASSERT_EQ(client.get_business_key_import_result("x", r2), ErrorCode::SUCCESS);
    EXPECT_EQ(r2.state, BusinessKeyImportState::NOT_FOUND);

    // 未知数值 → UNKNOWN（禁止默认零值）
    stub_response =
        "{\"status\":0,\"request_id\":\"x\",\"business_domain\":\"V2C_COMM\","
        "\"state\":\"UNKNOWN\",\"state_code\":99,\"items\":[]}";
    ImportResult r3;
    ASSERT_EQ(client.get_business_key_import_result("x", r3), ErrorCode::SUCCESS);
    EXPECT_EQ(r3.state, BusinessKeyImportState::UNKNOWN);

    // 数值/字符串冲突 → UNKNOWN（fail-closed）
    stub_response =
        "{\"status\":0,\"request_id\":\"x\",\"business_domain\":\"V2C_COMM\","
        "\"state\":\"COMMITTED\",\"state_code\":5,\"items\":[]}";
    ImportResult r4;
    ASSERT_EQ(client.get_business_key_import_result("x", r4), ErrorCode::SUCCESS);
    EXPECT_EQ(r4.state, BusinessKeyImportState::UNKNOWN);

    // 缺失 state（仅数值）→ UNKNOWN
    stub_response =
        "{\"status\":0,\"request_id\":\"x\",\"business_domain\":\"V2C_COMM\","
        "\"state_code\":2,\"items\":[]}";
    ImportResult r5;
    ASSERT_EQ(client.get_business_key_import_result("x", r5), ErrorCode::SUCCESS);
    EXPECT_EQ(r5.state, BusinessKeyImportState::UNKNOWN);

    // 旧 SEC 返回已知确定结果（无 state_code）→ 按字符串正常映射
    stub_response =
        "{\"status\":0,\"request_id\":\"x\",\"business_domain\":\"V2C_COMM\","
        "\"state\":\"REQUESTED\",\"items\":[]}";
    ImportResult r6;
    ASSERT_EQ(client.get_business_key_import_result("x", r6), ErrorCode::SUCCESS);
    EXPECT_EQ(r6.state, BusinessKeyImportState::REQUESTED);

    stub->stop();
}

// 冻结旧 client parser 语义（TBOX-SEC-DSN-CR-021 §4：旧 client 不识别 NOT_FOUND
// 时必须经 default 分支得到 UNKNOWN）。此处复刻 CR-021 前的 parser：仅按稳定字符串
// 映射、未知字符串 → UNKNOWN，不读取 state_code。
namespace {
BusinessKeyImportState legacy_client_import_state(const nlohmann::json& j) {
    std::string s = j.value("state", "UNKNOWN");
    if (s == "REQUESTED") return BusinessKeyImportState::REQUESTED;
    if (s == "STAGED") return BusinessKeyImportState::STAGED;
    if (s == "COMMITTED") return BusinessKeyImportState::COMMITTED;
    if (s == "FAILED") return BusinessKeyImportState::FAILED;
    return BusinessKeyImportState::UNKNOWN;  // "NOT_FOUND"/未知 → default → UNKNOWN
}
} // namespace

TEST_F(BusinessKeyIntegrationTest, OldClientFixture_NewSecResponse_FailClosed) {
    // 冻结旧 client 读取新 SEC 响应：识别 REQUESTED/STAGED/COMMITTED/FAILED，
    // 不识别 "NOT_FOUND" → 经 default 分支得到 UNKNOWN（fail-closed，不误建 attempt）。
    auto j = nlohmann::json::parse(
        "{\"state\":\"NOT_FOUND\",\"state_code\":5,\"items\":[]}");
    EXPECT_EQ(legacy_client_import_state(j), BusinessKeyImportState::UNKNOWN);
    auto j2 = nlohmann::json::parse(
        "{\"state\":\"COMMITTED\",\"state_code\":2,\"items\":[]}");
    EXPECT_EQ(legacy_client_import_state(j2), BusinessKeyImportState::COMMITTED);
}

// ---------------- KL1 客户端级（TBOX-SEC-DSN-CR-023；真实 socket） ----------------

TEST_F(BusinessKeyIntegrationTest, Kl1_ProbeSnapshot_ClientPassthrough) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    KeyprovContractSnapshot snap;
    ASSERT_EQ(client.get_keyprov_contract_snapshot(snap), ErrorCode::SUCCESS);
    // typed 原值透传：缺省 = UNAVAILABLE，不是支持；epoch 非 0、存储健康、租约准入就绪。
    EXPECT_NE(snap.capability_epoch, 0ULL);
    EXPECT_EQ(snap.result_contract_version, V2cKeyProvisioningCapability::kContractVersion);
    EXPECT_EQ(snap.query_semantics_version, 1u);
    EXPECT_TRUE(snap.storage_ready);
    EXPECT_TRUE(snap.supports_atomic_dual_commit);
    EXPECT_TRUE(snap.supports_lease_admission);
    EXPECT_EQ(snap.kl1_profile_version, kKeyprovKl1ProfileVersion);
    // 构建 ID 可观测（daemon 来自服务端、SDK 来自客户端自身）。
    EXPECT_FALSE(snap.daemon_build_id.empty());
    EXPECT_FALSE(snap.sdk_build_id.empty());
}

TEST_F(BusinessKeyIntegrationTest, Kl1_ImportAndQuery_ClientRoundTrip) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    KeyprovContractSnapshot snap;
    ASSERT_EQ(client.get_keyprov_contract_snapshot(snap), ErrorCode::SUCCESS);
    ASSERT_TRUE(snap.supports_lease_admission);

    KeyprovImportContext ctx;
    ctx.admission_expire_at_ms = now_ms() + 60000;  // U=now < E
    ctx.capability_epoch = snap.capability_epoch;
    ctx.kl1_profile_version = kKeyprovKl1ProfileVersion;
    auto items = make_batch("kl1-ipc-1", 1);
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(client.import_wrapped_business_keys_kl1("kl1-ipc-1", kBusinessDomainV2c, items,
                                                      ctx, r, a),
              ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::COMMITTED);
    ASSERT_EQ(r.items.size(), 2u);
    ASSERT_EQ(r.items[0].import_proof.size(), kImportProofSizeP1363);
    // 同快照 epoch + 证据摘要随结果回传（非 SDK 硬编码 version 2）。
    EXPECT_EQ(a.snapshot.capability_epoch, snap.capability_epoch);
    EXPECT_FALSE(a.request_identity_digest.empty());

    // 同 epoch 查询：返回原 proof 与证据摘要。
    ImportResult q;
    KeyprovResultAttachment qa;
    ASSERT_EQ(client.get_business_key_import_result_kl1("kl1-ipc-1", q, qa),
              ErrorCode::SUCCESS);
    EXPECT_EQ(q.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(q.items[0].import_proof, r.items[0].import_proof);
    EXPECT_EQ(qa.snapshot.capability_epoch, snap.capability_epoch);
    EXPECT_EQ(qa.request_identity_digest, a.request_identity_digest);
}

TEST_F(BusinessKeyIntegrationTest, Kl1_SdkFailClosed_EpochOrProfileMissing_NotReady) {
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    auto items = make_batch("kl1-sdk-1", 1);
    ImportResult r;
    KeyprovResultAttachment a;
    // epoch 缺失（0）→ SDK 直接 NOT_READY，不发起 IPC、不降级旧 import。
    KeyprovImportContext ctx0;
    ctx0.admission_expire_at_ms = now_ms() + 60000;
    ctx0.capability_epoch = 0;
    ctx0.kl1_profile_version = kKeyprovKl1ProfileVersion;
    EXPECT_EQ(client.import_wrapped_business_keys_kl1("kl1-sdk-1", kBusinessDomainV2c, items,
                                                      ctx0, r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    // profile 未知 → NOT_READY。
    KeyprovImportContext ctx1;
    ctx1.admission_expire_at_ms = now_ms() + 60000;
    ctx1.capability_epoch = 1;
    ctx1.kl1_profile_version = 99;
    EXPECT_EQ(client.import_wrapped_business_keys_kl1("kl1-sdk-1", kBusinessDomainV2c, items,
                                                      ctx1, r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
}

TEST_F(BusinessKeyIntegrationTest, Kl1_EpochSwitch_OldEpochRejected_1030) {
    // daemon 重启/恢复 → 新 epoch；携带旧 epoch 的新 import 必须 1030 且无副作用。
    SecClient client(socket_path_);
    ASSERT_TRUE(client.connect());
    KeyprovContractSnapshot s1;
    ASSERT_EQ(client.get_keyprov_contract_snapshot(s1), ErrorCode::SUCCESS);
    const uint64_t e1 = s1.capability_epoch;

    // 停止旧 server，重建服务/dispatcher/server（模拟 daemon 重启）。
    server_->stop();
    auto provider2 = std::make_unique<SoftFileBusinessKeyProvider>(
        hsm_.get(),
        [&]() {
            BusinessKeyProviderConfig pcfg;
            pcfg.store_root = test_dir_ + "/bk";
            pcfg.kek_path = test_dir_ + "/bk/.kek";
            pcfg.allowed_algorithms = {kDefaultKeyAlgorithm};
            pcfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
            return pcfg;
        }(),
        [this]() { return binding_; });
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
    service_.reset();
    service_ = std::make_unique<BusinessKeyProvisioningService>(
        std::move(cfg), std::move(provider2), std::make_shared<FakeTrustedTimeProvider>(s),
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

    SecClient client2(socket_path_);
    ASSERT_TRUE(client2.connect());
    KeyprovContractSnapshot s2;
    ASSERT_EQ(client2.get_keyprov_contract_snapshot(s2), ErrorCode::SUCCESS);
    EXPECT_NE(s2.capability_epoch, e1);  // epoch 随 daemon 重启更换

    // 携带旧 epoch（e1）的新 import → 1030，且未建 journal（无副作用）。
    KeyprovImportContext ctx;
    ctx.admission_expire_at_ms = now_ms() + 60000;
    ctx.capability_epoch = e1;
    ctx.kl1_profile_version = kKeyprovKl1ProfileVersion;
    auto items = make_batch("kl1-epoch-switch-1", 1);
    ImportResult r;
    KeyprovResultAttachment a;
    EXPECT_EQ(client2.import_wrapped_business_keys_kl1(
                  "kl1-epoch-switch-1", kBusinessDomainV2c, items, ctx, r, a),
              ErrorCode::KL1_CAPABILITY_EPOCH_MISMATCH);
    ImportResult q;
    EXPECT_EQ(client2.get_business_key_import_result("kl1-epoch-switch-1", q),
              ErrorCode::SUCCESS);
    EXPECT_EQ(q.state, BusinessKeyImportState::NOT_FOUND);  // 未启动，无副作用
}

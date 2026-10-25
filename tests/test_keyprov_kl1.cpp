//
// KL1 契约快照/租约准入/同 epoch 查询测试（TBOX-SEC-DSN-CR-023）。
//
// 覆盖 SEC-KL1-01..30 派生用例（本地 manifest tests/fixtures/keyprov-kl1-v1/
// keyprov_kl1_manifest.json 中登记；与 PAR-PROTO lifecycle-vectors.json
// case_set=keyprov-lifecycle-kl1-v1 语义对齐）：
//   - 契约快照 typed 原值透传（LC23 CONTRACT_UNKNOWN 语义，SEC-KL1-23）
//   - capability_epoch 稳定性/重启/存储更换（LC12/LC13.EPOCH，SEC-KL1-13）
//   - 租约准入 U<E、U==E/U>E 拒绝（LC02.0/.1，SEC-KL1-02）与锁内重检
//   - epoch 不匹配 1030（SEC-KL1-30）
//   - 可信时间门禁 1000ms/300000ms/回拨边界（LC21.*，SEC-KL1-21）
//   - item/cert 有效期覆盖 E（LC20 派生，SEC-KL1-20）
//   - 同 rid 同 digest + 新 E 恢复原 proof、E 不进业务 digest（LC07 派生，SEC-KL1-07）
//   - 同 rid 不同 digest → 1022（LC08 派生，SEC-KL1-08）
//   - COMMITTED 旧 E 过期仍恢复原结果（LC14 派生，SEC-KL1-14）
//   - STAGED 走恢复不建第二 operation（SEC-KL1-15）
//   - 存储被清空/更换 → storage_ready=false、强 NF 不成立（LC24 派生，SEC-KL1-24C/13）
//   - IPC additive 方法 22/23 round-trip、未知方法 fail-closed
//
// 1029/1030 均不是强 NOT_FOUND：只证明本次未启动新操作，不能解释为
// “该 rid 历史无副作用”（错误码注释与下述测试共同约束）。
//
#include <gtest/gtest.h>

#include "business_key_provisioning.h"
#include "business_key_provider.h"
#include "canonical_encoding.h"
#include "keyprov_envelope_builder.h"
#include "sec_ipc_dispatcher.h"
#include "secure_metadata_ledger.h"
#include "soft_file_business_key_provider.h"
#include "soft_file_hsm.h"
#include "store.h"
#include "trusted_time.h"
#include "peer_credential.h"
#include "ipc_protocol.h"
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
// 与 PAR-PROTO lifecycle-vectors.json 的固定时间输入 T0 一致。
constexpr int64_t kT0Ms = 1800000000000LL;

std::string unique_dir() {
    auto p = fs::temp_directory_path() /
             ("tbox-sec-kl1-" + std::to_string(::getpid()) + "-" +
              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(p);
    return p.string();
}

std::vector<uint8_t> random_key(size_t n = 32) {
    std::vector<uint8_t> k(n);
    RAND_bytes(k.data(), static_cast<int>(n));
    return k;
}

/// 可控可信时间：测试持 shared_ptr，可随时 set_now（fake clock；LC21 边界/回拨）。
std::shared_ptr<FakeTrustedTimeProvider> make_time(int64_t utc_ms, int64_t unc_ms = 0,
                                                   int64_t age_ms = 0,
                                                   TimeTrustState trust = TimeTrustState::Trusted) {
    TrustedTimeSample s;
    s.utc_now = std::chrono::system_clock::time_point(std::chrono::milliseconds(utc_ms));
    s.trust_state = trust;
    s.source = TimeSource::FakeTest;
    s.reason = TimeReason::FakeTest;
    s.uncertainty = std::chrono::milliseconds(unc_ms);
    s.freshness_age = std::chrono::milliseconds(age_ms);
    return std::make_shared<FakeTrustedTimeProvider>(s);
}

/// 按步进返回时间的 provider（用于锁内重检：入口 U<E、重检时 U≥E）。
class StepTimeProvider : public TrustedTimeProvider {
public:
    explicit StepTimeProvider(std::vector<TrustedTimeSample> steps) : steps_(std::move(steps)) {}
    TrustedTimeSample now() noexcept override {
        TrustedTimeSample s = steps_[std::min(idx_, static_cast<int>(steps_.size()) - 1)];
        ++idx_;
        return s;
    }
    int calls() const { return idx_; }

private:
    std::vector<TrustedTimeSample> steps_;
    int idx_ = 0;
};

TrustedTimeSample step_sample(int64_t utc_ms, int64_t unc_ms = 0, int64_t age_ms = 0) {
    TrustedTimeSample s;
    s.utc_now = std::chrono::system_clock::time_point(std::chrono::milliseconds(utc_ms));
    s.trust_state = TimeTrustState::Trusted;
    s.source = TimeSource::FakeTest;
    s.reason = TimeReason::FakeTest;
    s.uncertainty = std::chrono::milliseconds(unc_ms);
    s.freshness_age = std::chrono::milliseconds(age_ms);
    return s;
}

/// 统计安全原语调用的 HSM 装饰器（provider_calls 语义：业务密钥密码操作计数）。
class CountingHsmKl1 : public SoftFileHsm {
public:
    CountingHsmKl1(hwyz::store::Store store, const std::string& alg, const std::string& kek)
        : SoftFileHsm(std::move(store), alg, kek) {}
    ErrorCode unwrap_ecdh_es_v1(const std::string& key_id, const std::vector<uint8_t>& eph,
                                const std::vector<uint8_t>& salt, const std::vector<uint8_t>& info,
                                const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ct,
                                const std::vector<uint8_t>& tag, const std::vector<uint8_t>& aad,
                                std::vector<uint8_t>& plain) override {
        ++unwrap_calls;
        return SoftFileHsm::unwrap_ecdh_es_v1(key_id, eph, salt, info, nonce, ct, tag, aad,
                                              plain);
    }
    ErrorCode sign_digest_p1363(const std::string& key_id, const std::vector<uint8_t>& digest,
                                std::vector<uint8_t>& signature) override {
        ++sign_calls;
        return SoftFileHsm::sign_digest_p1363(key_id, digest, signature);
    }
    int unwrap_calls = 0;
    int sign_calls = 0;
};

/// storageReplaced()=true 的装饰 provider（模拟存储被清空/更换 → 治理）。
class StorageReplacedProvider : public BusinessKeyProvider {
public:
    explicit StorageReplacedProvider(std::unique_ptr<BusinessKeyProvider> inner)
        : inner_(std::move(inner)) {}
    ErrorCode initialize() override { return inner_->initialize(); }
    bool isReady() const override { return inner_->isReady(); }
    std::string providerVersionDigest() const override { return inner_->providerVersionDigest(); }
    BusinessKeyProviderCapability capability() const override { return inner_->capability(); }
    ErrorCode unwrapToStaging(const std::string& d, const WrappedKeyItem& i,
                              const EcdhEsP256EnvelopeParameters& p,
                              const std::vector<uint8_t>& aad, const std::vector<uint8_t>& info,
                              const BusinessKeyDeviceBinding& b, uint64_t g,
                              std::array<uint8_t, 3>& kcv) override {
        return inner_->unwrapToStaging(d, i, p, aad, info, b, g, kcv);
    }
    ErrorCode verifyStaging(const std::string& d, const std::string& p) override {
        return inner_->verifyStaging(d, p);
    }
    ErrorCode commitBatch(const std::string& d, uint64_t g) override {
        return inner_->commitBatch(d, g);
    }
    ErrorCode rollbackStaging(const std::string& d, uint64_t g) override {
        return inner_->rollbackStaging(d, g);
    }
    ErrorCode querySlot(const std::string& d, const std::string& p,
                        BusinessKeySlotInfo& o) override {
        return inner_->querySlot(d, p, o);
    }
    ErrorCode generateProof(const std::string& d, const std::string& p, uint64_t v,
                            const std::string& r, const std::string& k,
                            const std::vector<uint8_t>& ed, const std::vector<uint8_t>& kcv,
                            std::vector<uint8_t>& proof, std::string& alg) override {
        return inner_->generateProof(d, p, v, r, k, ed, kcv, proof, alg);
    }
    JournalLoadResult loadJournalEx(const std::string& r) override {
        return inner_->loadJournalEx(r);
    }
    bool hasTransactionResidue(const std::string& r) const override {
        return inner_->hasTransactionResidue(r);
    }
    ErrorCode saveJournal(const BusinessKeyJournalEntry& e) override {
        return inner_->saveJournal(e);
    }
    std::vector<BusinessKeyJournalEntry> listJournal() override { return inner_->listJournal(); }
    bool hasPendingStaging() const override { return inner_->hasPendingStaging(); }
    bool storageReplaced() const override { return true; }

private:
    std::unique_ptr<BusinessKeyProvider> inner_;
};

/// commit 阶段恒返回未知错误的 provider（OUTCOME_UNKNOWN → 恢复/对账路径）。
class FailingCommitProviderKl1 : public BusinessKeyProvider {
public:
    explicit FailingCommitProviderKl1(std::unique_ptr<BusinessKeyProvider> inner)
        : inner_(std::move(inner)) {}
    ErrorCode initialize() override { return inner_->initialize(); }
    bool isReady() const override { return inner_->isReady(); }
    std::string providerVersionDigest() const override { return inner_->providerVersionDigest(); }
    BusinessKeyProviderCapability capability() const override { return inner_->capability(); }
    ErrorCode unwrapToStaging(const std::string& d, const WrappedKeyItem& i,
                              const EcdhEsP256EnvelopeParameters& p,
                              const std::vector<uint8_t>& aad, const std::vector<uint8_t>& info,
                              const BusinessKeyDeviceBinding& b, uint64_t g,
                              std::array<uint8_t, 3>& kcv) override {
        return inner_->unwrapToStaging(d, i, p, aad, info, b, g, kcv);
    }
    ErrorCode verifyStaging(const std::string& d, const std::string& p) override {
        return inner_->verifyStaging(d, p);
    }
    ErrorCode commitBatch(const std::string&, uint64_t) override {
        return ErrorCode::INTERNAL_ERROR;
    }
    ErrorCode rollbackStaging(const std::string& d, uint64_t g) override {
        return inner_->rollbackStaging(d, g);
    }
    ErrorCode querySlot(const std::string& d, const std::string& p,
                        BusinessKeySlotInfo& o) override {
        return inner_->querySlot(d, p, o);
    }
    ErrorCode generateProof(const std::string& d, const std::string& p, uint64_t v,
                            const std::string& r, const std::string& k,
                            const std::vector<uint8_t>& ed, const std::vector<uint8_t>& kcv,
                            std::vector<uint8_t>& proof, std::string& alg) override {
        return inner_->generateProof(d, p, v, r, k, ed, kcv, proof, alg);
    }
    JournalLoadResult loadJournalEx(const std::string& r) override {
        return inner_->loadJournalEx(r);
    }
    bool hasTransactionResidue(const std::string& r) const override {
        return inner_->hasTransactionResidue(r);
    }
    ErrorCode saveJournal(const BusinessKeyJournalEntry& e) override {
        return inner_->saveJournal(e);
    }
    std::vector<BusinessKeyJournalEntry> listJournal() override { return inner_->listJournal(); }
    bool hasPendingStaging() const override { return inner_->hasPendingStaging(); }

private:
    std::unique_ptr<BusinessKeyProvider> inner_;
};

class MockPeerResolverKl1 : public PeerCredentialResolver {
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

int32_t status_of(const std::string& resp) {
    return json::parse(resp).value("status", -1);
}

class KeyprovKl1Test : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = unique_dir();
        store_ = std::make_unique<hwyz::store::Store>(hwyz::store::Store::open("sec", dir_));
        hsm_ = std::make_unique<CountingHsmKl1>(hwyz::store::Store::open("sec_hsm", dir_),
                                                "aes-256-gcm", dir_ + "/.hsm_kek");
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
        // KL1 准入：证书有效期须覆盖租约 E（默认长有效）。
        binding_.active_cert_valid_from_ms = kT0Ms - 86400000LL;
        binding_.active_cert_valid_to_ms = kT0Ms + 86400000LL;
    }

    void TearDown() override {
        dispatcher_.reset();
        service_.reset();
        hsm_.reset();
        store_.reset();
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    BusinessKeyProviderConfig provider_config() {
        BusinessKeyProviderConfig pcfg;
        pcfg.store_root = dir_ + "/bk";
        pcfg.kek_path = dir_ + "/bk/.kek";
        pcfg.allowed_algorithms = {kDefaultKeyAlgorithm};
        pcfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
        return pcfg;
    }

    BusinessKeyProvisioningConfig service_config() {
        BusinessKeyProvisioningConfig cfg;
        cfg.enabled = true;
        cfg.is_production = false;
        cfg.allowed_algorithms = {kDefaultKeyAlgorithm};
        cfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
        cfg.allowed_envelope_formats = {kKeyEnvelopeFormatEcdhEsP256V1};
        return cfg;
    }

    /// 装配服务（时间 provider 可注入；绑定固定为 binding_）。
    void make_service(std::shared_ptr<TrustedTimeProvider> time,
                      std::unique_ptr<BusinessKeyProvider> provider = nullptr) {
        if (!provider) {
            provider = std::make_unique<SoftFileBusinessKeyProvider>(
                hsm_.get(), provider_config(), [this]() { return binding_; });
        }
        service_ = std::make_unique<BusinessKeyProvisioningService>(
            service_config(), std::move(provider), time,
            std::make_unique<SecureMetadataLedger>(hwyz::store::Store::open("sec", dir_)),
            [this]() { return binding_; });
        ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);
    }

    /// 带可控时间的默认服务（U = utc，unc=0）。
    void make_default_service(int64_t utc_ms = kT0Ms) {
        time_ = make_time(utc_ms);
        make_service(time_);
    }

    /// 重建服务（模拟 daemon 重启：新 boot nonce → 新 epoch）。
    void restart_service() {
        service_.reset();
        make_service(time_);
    }

    std::vector<uint8_t> build_envelope(const std::string& request_id,
                                        const std::string& purpose, const std::string& key_id,
                                        uint64_t version, const std::vector<uint8_t>& key) {
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
        return out.wrapped_key;
    }

    WrappedKeyItem make_item(const std::string& request_id, const std::string& purpose,
                             const std::string& key_id, uint64_t version,
                             const std::vector<uint8_t>& key, int64_t from_ms,
                             int64_t to_ms) {
        KeyprovEnvelopeOutput out;
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
        EXPECT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
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
        item.valid_from_ms = from_ms;
        item.valid_to_ms = to_ms;
        return item;
    }

    /// 两用途批次（有效期覆盖 [from, to]）。
    std::vector<WrappedKeyItem> make_batch(const std::string& request_id, uint64_t version,
                                           int64_t from_ms, int64_t to_ms) {
        std::vector<WrappedKeyItem> items;
        items.push_back(make_item(request_id, kBusinessPurposeUplinkAead,
                                  "kid-up-" + std::to_string(version), version, random_key(),
                                  from_ms, to_ms));
        items.push_back(make_item(request_id, kBusinessPurposeDownlinkAead,
                                  "kid-down-" + std::to_string(version), version, random_key(),
                                  from_ms, to_ms));
        return items;
    }

    KeyprovImportContext kl1_context(int64_t e_ms, uint64_t epoch = 0) {
        KeyprovImportContext ctx;
        ctx.admission_expire_at_ms = e_ms;
        ctx.capability_epoch = epoch ? epoch : service_->contractSnapshot().capability_epoch;
        ctx.kl1_profile_version = kKeyprovKl1ProfileVersion;
        return ctx;
    }

    /// 默认新批次：有效期覆盖 [kT0-1d, kT0+1d]；U=kT0、E=kT0+60000。
    std::vector<WrappedKeyItem> fresh_batch(const std::string& request_id, uint64_t version = 1) {
        return make_batch(request_id, version, kT0Ms - 86400000LL, kT0Ms + 86400000LL);
    }

    std::string dir_;
    std::unique_ptr<hwyz::store::Store> store_;
    std::unique_ptr<CountingHsmKl1> hsm_;
    std::vector<uint8_t> device_pub_;
    BusinessKeyDeviceBinding binding_;
    std::shared_ptr<FakeTrustedTimeProvider> time_;
    std::unique_ptr<BusinessKeyProvisioningService> service_;
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
};

// ---------------- 契约快照（SEC-KL1-23 / LC23） ----------------

TEST_F(KeyprovKl1Test, Snapshot_FullReady_TypedPassthrough) {
    make_default_service();
    KeyprovContractSnapshot s = service_->contractSnapshot();
    EXPECT_EQ(s.result_contract_version, V2cKeyProvisioningCapability::kContractVersion);
    EXPECT_EQ(s.query_semantics_version, 1u);
    EXPECT_NE(s.capability_epoch, 0ULL);
    EXPECT_TRUE(s.storage_ready);
    EXPECT_TRUE(s.supports_atomic_dual_commit);
    EXPECT_TRUE(s.supports_lease_admission);
    EXPECT_EQ(s.kl1_profile_version, kKeyprovKl1ProfileVersion);
    EXPECT_FALSE(s.daemon_build_id.empty());
    EXPECT_FALSE(s.sdk_build_id.empty());
}

TEST_F(KeyprovKl1Test, Snapshot_NotReady_LeaseAdmissionFalse) {
    // 能力未就绪（binding 未就绪）→ supports_lease_admission=false、profile=0。
    binding_.ready = false;
    make_default_service();
    KeyprovContractSnapshot s = service_->contractSnapshot();
    EXPECT_FALSE(s.supports_lease_admission);
    EXPECT_EQ(s.kl1_profile_version, 0u);
    EXPECT_FALSE(service_->isReady());
}

// ---------------- epoch（SEC-KL1-13 / LC12·LC13.EPOCH） ----------------

TEST_F(KeyprovKl1Test, Epoch_StableWithinInstance_ChangesAcrossRestart) {
    make_default_service();
    const uint64_t e1 = service_->contractSnapshot().capability_epoch;
    const uint64_t e2 = service_->contractSnapshot().capability_epoch;
    EXPECT_EQ(e1, e2);
    restart_service();  // daemon 重启 → 新 boot nonce → 新 epoch
    const uint64_t e3 = service_->contractSnapshot().capability_epoch;
    EXPECT_NE(e1, e3);
    // 查询结果携带同一快照 epoch。
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->getImportResultKl1("no-such-rid", r, a), ErrorCode::SUCCESS);
    EXPECT_EQ(a.snapshot.capability_epoch, service_->contractSnapshot().capability_epoch);
    EXPECT_EQ(r.state, BusinessKeyImportState::NOT_FOUND);
}

// ---------------- 租约准入（SEC-KL1-02 / LC02.0·LC02.1） ----------------

TEST_F(KeyprovKl1Test, ImportKl1_FreshLease_Commits) {
    make_default_service();
    auto items = fresh_batch("kl1-ok-1");
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-ok-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::COMMITTED);
    ASSERT_EQ(r.items.size(), 2u);
    ASSERT_EQ(r.items[0].import_proof.size(), kImportProofSizeP1363);
    // attach：同一快照 epoch + 证据摘要。
    EXPECT_EQ(a.snapshot.capability_epoch, service_->contractSnapshot().capability_epoch);
    EXPECT_FALSE(a.request_identity_digest.empty());
}

TEST_F(KeyprovKl1Test, ImportKl1_UeqE_Rejected1029_NoSideEffects) {
    make_default_service();
    auto items = fresh_batch("kl1-exp-0");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    // U==E：必拒绝（LC02.0：RESPONSE_EXPIRED）。
    ASSERT_EQ(service_->importKl1("kl1-exp-0", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms), r, a),
              ErrorCode::KL1_ADMISSION_REJECTED);
    EXPECT_EQ(r.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);  // 未启动密码操作
    EXPECT_TRUE(service_->getImportResult("kl1-exp-0", r) == ErrorCode::SUCCESS &&
                r.state == BusinessKeyImportState::NOT_FOUND);  // 未建 journal
}

TEST_F(KeyprovKl1Test, ImportKl1_UgtE_Rejected1029_NoSideEffects) {
    make_default_service();
    auto items = fresh_batch("kl1-exp-1");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    // U>E：拒绝（LC02.1）。
    ASSERT_EQ(service_->importKl1("kl1-exp-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms - 1), r, a),
              ErrorCode::KL1_ADMISSION_REJECTED);
    EXPECT_EQ(r.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
    EXPECT_TRUE(service_->getImportResult("kl1-exp-1", r) == ErrorCode::SUCCESS &&
                r.state == BusinessKeyImportState::NOT_FOUND);
}

TEST_F(KeyprovKl1Test, ImportKl1_InLockRecheck_LeaseCrossed_1029) {
    // 入口 U< E，锁内重检时 U≥E（排队越界语义）→ 1029，未建 journal。
    std::vector<TrustedTimeSample> steps;
    steps.push_back(step_sample(kT0Ms, 0, 0));              // 入口：U=kT0 < E=kT0+60000
    steps.push_back(step_sample(kT0Ms + 60000, 0, 0));     // 重检：U==E → 拒绝
    auto stp = std::make_shared<StepTimeProvider>(steps);
    make_service(stp);
    auto items = fresh_batch("kl1-queue-1");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-queue-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::KL1_ADMISSION_REJECTED);
    EXPECT_EQ(r.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
    EXPECT_TRUE(service_->getImportResult("kl1-queue-1", r) == ErrorCode::SUCCESS &&
                r.state == BusinessKeyImportState::NOT_FOUND);
}

// ---------------- epoch 不匹配（SEC-KL1-30） ----------------

TEST_F(KeyprovKl1Test, ImportKl1_EpochMismatch_1030_NoSideEffects) {
    make_default_service();
    auto items = fresh_batch("kl1-epoch-1");
    const uint64_t current = service_->contractSnapshot().capability_epoch;
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    KeyprovImportContext ctx;
    ctx.admission_expire_at_ms = kT0Ms + 60000;
    ctx.capability_epoch = current + 1;  // 调用方所见 epoch 已过期
    ctx.kl1_profile_version = kKeyprovKl1ProfileVersion;
    ASSERT_EQ(service_->importKl1("kl1-epoch-1", kBusinessDomainV2c, items, ctx, r, a),
              ErrorCode::KL1_CAPABILITY_EPOCH_MISMATCH);
    EXPECT_EQ(r.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
    EXPECT_TRUE(service_->getImportResult("kl1-epoch-1", r) == ErrorCode::SUCCESS &&
                r.state == BusinessKeyImportState::NOT_FOUND);
    // attach 携带当前 epoch 供诊断（不是“无副作用证明”）。
    EXPECT_NE(a.snapshot.capability_epoch, 0ULL);
}

TEST_F(KeyprovKl1Test, ImportKl1_EpochZero_1025_NotStarted) {
    make_default_service();
    auto items = fresh_batch("kl1-epoch-0");
    ImportResult r;
    KeyprovResultAttachment a;
    KeyprovImportContext ctx;
    ctx.admission_expire_at_ms = kT0Ms + 60000;
    ctx.capability_epoch = 0;  // 未 probe：epoch 缺失不得当可用
    ctx.kl1_profile_version = kKeyprovKl1ProfileVersion;
    ASSERT_EQ(service_->importKl1("kl1-epoch-0", kBusinessDomainV2c, items, ctx, r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_TRUE(service_->getImportResult("kl1-epoch-0", r) == ErrorCode::SUCCESS &&
                r.state == BusinessKeyImportState::NOT_FOUND);
}

TEST_F(KeyprovKl1Test, ImportKl1_ProfileUnknown_1025) {
    make_default_service();
    auto items = fresh_batch("kl1-prof-0");
    ImportResult r;
    KeyprovResultAttachment a;
    KeyprovImportContext ctx;
    ctx.admission_expire_at_ms = kT0Ms + 60000;
    ctx.capability_epoch = service_->contractSnapshot().capability_epoch;
    ctx.kl1_profile_version = 0;  // profile 未知/缺失
    ASSERT_EQ(service_->importKl1("kl1-prof-0", kBusinessDomainV2c, items, ctx, r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
}

// ---------------- 可信时间门禁（SEC-KL1-21 / LC21.*） ----------------

TEST_F(KeyprovKl1Test, ImportKl1_TimeUnhealthy_Uncertainty1025) {
    // LC21.uncertainty：uncertainty=1001ms > 1000ms → TIME_UNTRUSTED。
    make_service(make_time(kT0Ms, /*unc_ms=*/1001, /*age_ms=*/0));
    auto items = fresh_batch("kl1-t-unc");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-t-unc", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
}

TEST_F(KeyprovKl1Test, ImportKl1_TimeUnhealthy_Stale1025) {
    // LC21.stale：freshness=300001ms > 300000ms → TIME_UNTRUSTED。
    make_service(make_time(kT0Ms, /*unc_ms=*/0, /*age_ms=*/300001));
    auto items = fresh_batch("kl1-t-stale");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-t-stale", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
}

TEST_F(KeyprovKl1Test, ImportKl1_TimeUnhealthy_Rollback1025) {
    // LC21.rollback：来源回拨 → 不健康（Composite 返回 Untrusted；此处模拟）。
    make_service(make_time(kT0Ms, 0, 0, TimeTrustState::Untrusted));
    auto items = fresh_batch("kl1-t-roll");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-t-roll", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
}

TEST_F(KeyprovKl1Test, ImportKl1_TimeBoundaryHealthy_Uncertainty1000_Age300000) {
    // LC21.healthy 边界：uncertainty=1000、freshness=300000 → 健康；U=kT0+1000。
    make_service(make_time(kT0Ms, /*unc_ms=*/1000, /*age_ms=*/300000));
    auto items = fresh_batch("kl1-t-boundary");
    ImportResult r;
    KeyprovResultAttachment a;
    // U=kT0+1000 < E=kT0+60000 → 准入成功。
    ASSERT_EQ(service_->importKl1("kl1-t-boundary", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::COMMITTED);
}

// ---------------- item/cert 有效期覆盖 E（SEC-KL1-20 / LC20 派生） ----------------

TEST_F(KeyprovKl1Test, ImportKl1_ItemValidityNotThroughE_1023_NoProviderCalls) {
    make_default_service();
    // item valid_to = E-1 < E → 1023（LC20.item 派生：provider_calls=0）。
    auto items = make_batch("kl1-20-item", 1, kT0Ms - 86400000LL, kT0Ms + 60000 - 1);
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-20-item", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::WRAPPED_KEY_INVALID);
    EXPECT_EQ(r.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
}

TEST_F(KeyprovKl1Test, ImportKl1_CertValidityNotThroughE_1023_NoProviderCalls) {
    make_default_service();
    binding_.active_cert_valid_to_ms = kT0Ms + 60000 - 1;  // 证书在 E 前到期
    auto items = fresh_batch("kl1-20-cert");
    const int unwrap_before = hsm_->unwrap_calls;
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->importKl1("kl1-20-cert", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r, a),
              ErrorCode::WRAPPED_KEY_INVALID);
    EXPECT_EQ(r.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_before);
}

// ---------------- 幂等/恢复（SEC-KL1-07/08/14/15） ----------------

TEST_F(KeyprovKl1Test, ImportKl1_SameDigest_NewE_RestoresOriginal_NoResign) {
    make_default_service();
    auto items = fresh_batch("kl1-dedupe-1");
    ImportResult r1;
    KeyprovResultAttachment a1;
    ASSERT_EQ(service_->importKl1("kl1-dedupe-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r1, a1),
              ErrorCode::SUCCESS);
    const int unwrap_after_first = hsm_->unwrap_calls;
    const int sign_after_first = hsm_->sign_calls;

    // 同 rid 同业务 digest + 新 E（续签）：恢复原 proof，不重签、不新增解封。
    ImportResult r2;
    KeyprovResultAttachment a2;
    ASSERT_EQ(service_->importKl1("kl1-dedupe-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 120000), r2, a2),
              ErrorCode::SUCCESS);
    EXPECT_EQ(r2.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(r2.items[0].import_proof, r1.items[0].import_proof);  // 原 proof bytes
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_after_first);              // 不新增解封
    EXPECT_EQ(hsm_->sign_calls, sign_after_first);                  // 不重签
    // E 不进业务 requestDigest：证据摘要一致（续签不触发冲突）。
    EXPECT_EQ(a2.request_identity_digest, a1.request_identity_digest);
}

TEST_F(KeyprovKl1Test, ImportKl1_DifferentDigest_Conflict1022_NoOverwrite) {
    make_default_service();
    auto items = fresh_batch("kl1-conflict-1");
    ImportResult r1;
    KeyprovResultAttachment a1;
    ASSERT_EQ(service_->importKl1("kl1-conflict-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r1, a1),
              ErrorCode::SUCCESS);
    // 同 rid、不同 key 材料 → 不同业务 digest → 1022（LC08：CONFLICT）。
    auto items2 = fresh_batch("kl1-conflict-1", /*version=*/2);
    ImportResult r2;
    KeyprovResultAttachment a2;
    ASSERT_EQ(service_->importKl1("kl1-conflict-1", kBusinessDomainV2c, items2,
                                  kl1_context(kT0Ms + 60000), r2, a2),
              ErrorCode::BUSINESS_KEY_CONFLICT);
    // 原证据不被覆盖：查询仍返回第一次的 COMMITTED 结果。
    ImportResult q;
    ASSERT_EQ(service_->getImportResult("kl1-conflict-1", q), ErrorCode::SUCCESS);
    EXPECT_EQ(q.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(q.items[0].import_proof, r1.items[0].import_proof);
}

TEST_F(KeyprovKl1Test, ImportKl1_CommittedRestore_ExpiredE_NotNegated) {
    make_default_service();
    auto items = fresh_batch("kl1-restore-1");
    ImportResult r1;
    KeyprovResultAttachment a1;
    ASSERT_EQ(service_->importKl1("kl1-restore-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r1, a1),
              ErrorCode::SUCCESS);
    // 旧 E 已过期（E 在过去）：已 COMMITTED 事实不被否定 → 恢复原结果，非 1029。
    ImportResult r2;
    KeyprovResultAttachment a2;
    ASSERT_EQ(service_->importKl1("kl1-restore-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms - 1000), r2, a2),
              ErrorCode::SUCCESS);
    EXPECT_EQ(r2.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(r2.items[0].import_proof, r1.items[0].import_proof);
}

TEST_F(KeyprovKl1Test, ImportKl1_UnTerminalizedJournal_Recover_NoSecondOperation) {
    // commit 阶段结果未知 → OUTCOME_UNKNOWN；重入走恢复/对账，不建第二 operation。
    auto inner = std::make_unique<SoftFileBusinessKeyProvider>(
        hsm_.get(), provider_config(), [this]() { return binding_; });
    auto failing = std::make_unique<FailingCommitProviderKl1>(std::move(inner));
    make_service(make_time(kT0Ms), std::move(failing));

    auto items = fresh_batch("kl1-unknown-1");
    ImportResult r1;
    KeyprovResultAttachment a1;
    ASSERT_EQ(service_->importKl1("kl1-unknown-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), r1, a1),
              ErrorCode::BUSINESS_KEY_OUTCOME_UNKNOWN);
    EXPECT_EQ(r1.state, BusinessKeyImportState::UNKNOWN);
    const int unwrap_after_first = hsm_->unwrap_calls;

    // 重入：FOUND + 未终结（OUTCOME_UNKNOWN）→ 恢复/回滚，不建立第二 operation、
    // 不新增解封；原 journal 证据保留（FAILED），不是 NF。
    ImportResult r2;
    KeyprovResultAttachment a2;
    ErrorCode rc2 = service_->importKl1("kl1-unknown-1", kBusinessDomainV2c, items,
                                        kl1_context(kT0Ms + 60000), r2, a2);
    EXPECT_EQ(rc2, ErrorCode::BUSINESS_KEY_PARTIAL_ROLLBACK);  // 1026：交对账
    EXPECT_EQ(r2.state, BusinessKeyImportState::FAILED);
    EXPECT_EQ(hsm_->unwrap_calls, unwrap_after_first);
    ImportResult q;
    ASSERT_EQ(service_->getImportResult("kl1-unknown-1", q), ErrorCode::SUCCESS);
    EXPECT_EQ(q.state, BusinessKeyImportState::FAILED);
}

// ---------------- 存储治理（SEC-KL1-24C / 13；LC24 派生） ----------------

TEST_F(KeyprovKl1Test, StorageReplaced_Governance_NoNf_LeaseAdmissionFalse) {
    // 存储被清空/更换：epoch 变化不是洗白；storage_ready=false、强 NF 不成立。
    auto inner = std::make_unique<SoftFileBusinessKeyProvider>(
        hsm_.get(), provider_config(), [this]() { return binding_; });
    auto replaced = std::make_unique<StorageReplacedProvider>(std::move(inner));
    make_service(make_time(kT0Ms), std::move(replaced));

    KeyprovContractSnapshot s = service_->contractSnapshot();
    EXPECT_FALSE(s.storage_ready);
    EXPECT_FALSE(s.supports_lease_admission);
    EXPECT_EQ(s.kl1_profile_version, 0u);
    EXPECT_FALSE(service_->isReady());

    // 查询未知 rid：存储不健康/治理下不得上报 NOT_FOUND。
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->getImportResultKl1("unknown-rid", r, a), ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::UNKNOWN);
    EXPECT_FALSE(a.snapshot.storage_ready);
}

// ---------------- 查询附加（SEC-KL1-23/14） ----------------

TEST_F(KeyprovKl1Test, QueryKl1_Committed_AttachesDigestAndEpoch) {
    make_default_service();
    auto items = fresh_batch("kl1-query-1");
    ImportResult ri;
    KeyprovResultAttachment ai;
    ASSERT_EQ(service_->importKl1("kl1-query-1", kBusinessDomainV2c, items,
                                  kl1_context(kT0Ms + 60000), ri, ai),
              ErrorCode::SUCCESS);
    ImportResult r;
    KeyprovResultAttachment a;
    ASSERT_EQ(service_->getImportResultKl1("kl1-query-1", r, a), ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(r.items[0].import_proof, ri.items[0].import_proof);  // 原 proof
    EXPECT_EQ(a.request_identity_digest, ai.request_identity_digest);
    EXPECT_EQ(a.snapshot.capability_epoch, service_->contractSnapshot().capability_epoch);
    EXPECT_TRUE(a.snapshot.storage_ready);
}

// ---------------- IPC（additive 方法 22/23；未知方法 fail-closed） ----------------

TEST_F(KeyprovKl1Test, Dispatch_Snapshot_RoundTrip) {
    make_default_service();
    dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
    dispatcher_->setBusinessKeyService(service_.get());
    auto peer = std::make_shared<MockPeerResolverKl1>();
    dispatcher_->setPeerCredentialResolver(peer);
    dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");

    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_KEYPROV_CONTRACT_SNAPSHOT), "{}", 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("status", -1), 0);
    EXPECT_EQ(j.value("success", false), true);
    EXPECT_NE(j.value("capability_epoch", 0ULL), 0ULL);
    EXPECT_EQ(j.value("result_contract_version", 0u),
              V2cKeyProvisioningCapability::kContractVersion);
    EXPECT_EQ(j.value("supports_lease_admission", false), true);
    EXPECT_FALSE(j.value("daemon_build_id", "").empty());
}

TEST_F(KeyprovKl1Test, Dispatch_Kl1Import_RoundTrip) {
    make_default_service();
    dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
    dispatcher_->setBusinessKeyService(service_.get());
    auto peer = std::make_shared<MockPeerResolverKl1>();
    dispatcher_->setPeerCredentialResolver(peer);
    dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");

    json params;
    params["request_id"] = "ipc-kl1-1";
    params["business_domain"] = kBusinessDomainV2c;
    params["admission_expire_at_ms"] = kT0Ms + 60000;
    params["capability_epoch"] = service_->contractSnapshot().capability_epoch;
    params["kl1_profile_version"] = kKeyprovKl1ProfileVersion;
    json items = json::array();
    auto add = [&](const std::string& purpose, const std::string& key_id) {
        KeyprovEnvelopeInput in;
        in.device_public_key = device_pub_;
        in.request_id = "ipc-kl1-1";
        in.business_domain = kBusinessDomainV2c;
        in.purpose = purpose;
        in.key_id = key_id;
        in.business_key_version = 1;
        in.business_key = random_key();
        in.root_key_version = 1;
        in.derivation_version = "v1";
        in.operation_id = "op-" + purpose;
        in.recipient_certificate_digest = binding_.active_cert_digest;
        in.wrapping_suite = kWrappingSuiteEcdhEsP256;
        in.key_algorithm = kDefaultKeyAlgorithm;
        KeyprovEnvelopeOutput out;
        ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
        json e;
        e["purpose"] = purpose;
        e["key_id"] = key_id;
        e["business_key_version"] = 1;
        e["algorithm"] = kDefaultKeyAlgorithm;
        e["wrapping_suite"] = kWrappingSuiteEcdhEsP256;
        e["envelope_format"] = kKeyEnvelopeFormatEcdhEsP256V1;
        e["wrapped_key"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.wrapped_key.data()),
                        out.wrapped_key.size()));
        e["parameters"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.parameters.data()),
                        out.parameters.size()));
        e["envelope_digest"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.envelope_digest.data()),
                        out.envelope_digest.size()));
        e["key_check_value"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.key_check_value.data()), 3));
        e["valid_from_ms"] = kT0Ms - 86400000LL;
        e["valid_to_ms"] = kT0Ms + 86400000LL;
        items.push_back(e);
    };
    add(kBusinessPurposeUplinkAead, "kid-up");
    add(kBusinessPurposeDownlinkAead, "kid-down");
    params["items"] = items;

    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS_KL1), params.dump(), 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("status", -1), 0);
    EXPECT_EQ(j.value("state", ""), "COMMITTED");
    // additive 快照字段随响应回传（同一 epoch）。
    EXPECT_EQ(j.value("capability_epoch", 0ULL), service_->contractSnapshot().capability_epoch);
    EXPECT_EQ(j.value("result_contract_version", 0u),
              V2cKeyProvisioningCapability::kContractVersion);
}

TEST_F(KeyprovKl1Test, Dispatch_Kl1Import_Expired_1029) {
    make_default_service();
    dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
    dispatcher_->setBusinessKeyService(service_.get());
    auto peer = std::make_shared<MockPeerResolverKl1>();
    dispatcher_->setPeerCredentialResolver(peer);
    dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");

    json params;
    params["request_id"] = "ipc-kl1-exp";
    params["business_domain"] = kBusinessDomainV2c;
    params["admission_expire_at_ms"] = kT0Ms;  // U==E
    params["capability_epoch"] = service_->contractSnapshot().capability_epoch;
    params["kl1_profile_version"] = kKeyprovKl1ProfileVersion;
    json items = json::array();
    auto add = [&](const std::string& purpose, const std::string& key_id) {
        KeyprovEnvelopeInput in;
        in.device_public_key = device_pub_;
        in.request_id = "ipc-kl1-exp";
        in.business_domain = kBusinessDomainV2c;
        in.purpose = purpose;
        in.key_id = key_id;
        in.business_key_version = 1;
        in.business_key = random_key();
        in.root_key_version = 1;
        in.derivation_version = "v1";
        in.operation_id = "op-" + purpose;
        in.recipient_certificate_digest = binding_.active_cert_digest;
        in.wrapping_suite = kWrappingSuiteEcdhEsP256;
        in.key_algorithm = kDefaultKeyAlgorithm;
        KeyprovEnvelopeOutput out;
        ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
        json e;
        e["purpose"] = purpose;
        e["key_id"] = key_id;
        e["business_key_version"] = 1;
        e["algorithm"] = kDefaultKeyAlgorithm;
        e["wrapping_suite"] = kWrappingSuiteEcdhEsP256;
        e["envelope_format"] = kKeyEnvelopeFormatEcdhEsP256V1;
        e["wrapped_key"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.wrapped_key.data()),
                        out.wrapped_key.size()));
        e["parameters"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.parameters.data()),
                        out.parameters.size()));
        e["envelope_digest"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.envelope_digest.data()),
                        out.envelope_digest.size()));
        e["key_check_value"] = ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(out.key_check_value.data()), 3));
        e["valid_from_ms"] = kT0Ms - 86400000LL;
        e["valid_to_ms"] = kT0Ms + 86400000LL;
        items.push_back(e);
    };
    add(kBusinessPurposeUplinkAead, "kid-up");
    add(kBusinessPurposeDownlinkAead, "kid-down");
    params["items"] = items;

    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS_KL1), params.dump(), 0);
    auto j = json::parse(resp);
    EXPECT_EQ(j.value("status", -1),
              static_cast<int32_t>(ErrorCode::KL1_ADMISSION_REJECTED));
    EXPECT_EQ(j.value("success", false), false);
    EXPECT_EQ(j.value("state", ""), "FAILED");
}

TEST_F(KeyprovKl1Test, Dispatch_UnknownMethod_FailClosed) {
    make_default_service();
    dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
    dispatcher_->setBusinessKeyService(service_.get());
    auto peer = std::make_shared<MockPeerResolverKl1>();
    dispatcher_->setPeerCredentialResolver(peer);
    dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");

    // 未知方法号（未登记）→ 传输失败状态；新 SDK 侧将其判为“不支持”，不降级旧接口。
    auto resp = dispatcher_->dispatch(99u, "{}", 0);
    auto j = json::parse(resp);
    EXPECT_NE(j.value("status", 0), 0);
}

TEST_F(KeyprovKl1Test, Dispatch_Snapshot_AclDenied_WrongPeer) {
    make_default_service();
    dispatcher_ = std::make_unique<SecIpcDispatcher>(nullptr);
    dispatcher_->setBusinessKeyService(service_.get());
    auto peer = std::make_shared<MockPeerResolverKl1>();
    peer->service = "tbox-diag.service";  // 非授权调用方
    dispatcher_->setPeerCredentialResolver(peer);
    dispatcher_->setBusinessKeyPeerService("tbox-tsp.service");

    auto resp = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_KEYPROV_CONTRACT_SNAPSHOT), "{}", 0);
    EXPECT_EQ(status_of(resp), static_cast<int32_t>(ErrorCode::ACL_DENIED));
}

} // namespace

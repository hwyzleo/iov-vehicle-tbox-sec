//
// V2C 业务密钥开通单元测试（TBOX-SEC-DSN-CR-019）。
//
#include <gtest/gtest.h>

#include "business_key_provisioning.h"
#include "business_key_provider.h"
#include "soft_file_business_key_provider.h"
#include "secure_metadata_ledger.h"
#include "soft_file_hsm.h"
#include "trusted_time.h"
#include "store.h"
#include "sec_log_adapter.h"
#include "tbox/sec/business_key.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

using namespace tbox::sec;
namespace fs = std::filesystem;

namespace {

std::string unique_dir() {
    auto p = fs::temp_directory_path() /
             ("tbox-sec-bk-" + std::to_string(::getpid()) + "-" +
              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(p);
    return p.string();
}

std::shared_ptr<TrustedTimeProvider> fake_time() {
    TrustedTimeSample s;
    s.utc_now = std::chrono::system_clock::now();
    s.trust_state = TimeTrustState::Trusted;
    s.source = TimeSource::FakeTest;
    s.reason = TimeReason::FakeTest;
    return std::make_shared<FakeTrustedTimeProvider>(s);
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::vector<uint8_t> random_key(size_t n = 32) {
    std::vector<uint8_t> k(n);
    RAND_bytes(k.data(), static_cast<int>(n));
    return k;
}

std::string sha256_hex_for_test(const std::string& s) {
    std::vector<uint8_t> d(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), d.data());
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (uint8_t b : d) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

class BusinessKeyTest : public ::testing::Test {
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
    }

    void TearDown() override {
        service_.reset();
        hsm_.reset();
        store_.reset();
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    void make_provider(bool enabled = true) {
        BusinessKeyProviderConfig pcfg;
        pcfg.store_root = dir_ + "/bk";
        pcfg.kek_path = dir_ + "/bk/.kek";
        pcfg.allowed_algorithms = {"AES-256-GCM"};
        pcfg.allowed_wrapping_suites = {
            SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm};
        auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
            hsm_.get(), std::move(pcfg),
            [this]() { return binding_; });
        provider_ = provider.get();

        auto ledger = std::make_unique<SecureMetadataLedger>(
            hwyz::store::Store::open("sec", dir_));

        BusinessKeyProvisioningConfig cfg;
        cfg.enabled = enabled;
        cfg.is_production = false;
        cfg.allowed_wrapping_suites = {
            SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm};
        cfg.allowed_algorithms = {"AES-256-GCM"};
        service_ = std::make_unique<BusinessKeyProvisioningService>(
            std::move(cfg), std::move(provider), fake_time(), std::move(ledger),
            [this]() { return binding_; });
        ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);
    }

    WrappedKeyItem make_item(const std::string& request_id, const std::string& purpose,
                             const std::string& key_id, uint64_t version,
                             const std::vector<uint8_t>& key,
                             int64_t from_ms = 0, int64_t to_ms = 0,
                             const std::string& algorithm = "AES-256-GCM") {
        if (from_ms == 0) from_ms = now_ms() - 1000;
        if (to_ms == 0) to_ms = now_ms() + 86400000;
        std::vector<uint8_t> aad = BusinessKeyProvisioningService::buildAad(
            request_id, kBusinessDomainV2c, purpose, version, kDeviceIdentity);
        std::vector<uint8_t> wrapped;
        std::string params;
        EXPECT_EQ(SoftFileBusinessKeyProvider::wrapForTest(
                      device_pub_,
                      SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm, aad, key,
                      wrapped, params),
                  ErrorCode::SUCCESS);
        WrappedKeyItem item;
        item.purpose = purpose;
        item.key_id = key_id;
        item.business_key_version = version;
        item.algorithm = algorithm;
        item.wrapped_key.assign(wrapped);
        item.parameters.assign(std::vector<uint8_t>(params.begin(), params.end()));
        item.valid_from_ms = from_ms;
        item.valid_to_ms = to_ms;
        return item;
    }

    std::vector<WrappedKeyItem> make_batch(const std::string& request_id, uint64_t version) {
        std::vector<WrappedKeyItem> items;
        items.push_back(make_item(request_id, kBusinessPurposeUplinkAead,
                                  "kid-up-" + std::to_string(version), version,
                                  random_key()));
        items.push_back(make_item(request_id, kBusinessPurposeDownlinkAead,
                                  "kid-down-" + std::to_string(version), version,
                                  random_key()));
        return items;
    }

    const std::string kDeviceKeyId = "ecu1+ecu1";
    const std::string kDeviceIdentity = "ecu1";

    std::string dir_;
    std::unique_ptr<hwyz::store::Store> store_;
    std::unique_ptr<SoftFileHsm> hsm_;
    std::vector<uint8_t> device_pub_;
    BusinessKeyDeviceBinding binding_;
    SoftFileBusinessKeyProvider* provider_ = nullptr;  // 归 service_ 所有
    std::unique_ptr<BusinessKeyProvisioningService> service_;
};

// ---------------- 正常导入与状态 ----------------

TEST_F(BusinessKeyTest, Import_TwoItems_ActiveAndProof) {
    make_provider();
    auto items = make_batch("req-1", 1);
    ImportResult result;
    ASSERT_EQ(service_->import("req-1", kBusinessDomainV2c, items, result), ErrorCode::SUCCESS);
    EXPECT_EQ(result.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(result.items.size(), 2u);
    EXPECT_FALSE(result.import_proof.empty());
    EXPECT_EQ(result.proof_algorithm, "HMAC-SHA256");

    BusinessKeyStatusSet set;
    ASSERT_EQ(service_->getStatus(kBusinessDomainV2c,
                                  {kBusinessPurposeUplinkAead, kBusinessPurposeDownlinkAead},
                                  set),
              ErrorCode::SUCCESS);
    ASSERT_EQ(set.items.size(), 2u);
    for (const auto& s : set.items) {
        EXPECT_EQ(s.state, BusinessKeyState::ACTIVE);
        EXPECT_EQ(s.business_key_version, 1u);
        EXPECT_FALSE(s.key_id_digest.empty());
    }
}

TEST_F(BusinessKeyTest, Import_Idempotent_SameDigest) {
    make_provider();
    auto items = make_batch("req-2", 1);
    ImportResult r1;
    ASSERT_EQ(service_->import("req-2", kBusinessDomainV2c, items, r1), ErrorCode::SUCCESS);
    // 同 requestId + 同摘要：返回原结果，不重复建槽（复用同一 items）
    ImportResult r2;
    ASSERT_EQ(service_->import("req-2", kBusinessDomainV2c, items, r2), ErrorCode::SUCCESS);
    EXPECT_EQ(r2.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(r1.items[0].key_id_digest, r2.items[0].key_id_digest);
}

TEST_F(BusinessKeyTest, Import_Conflict_DifferentDigest) {
    make_provider();
    auto items = make_batch("req-3", 1);
    ImportResult r1;
    ASSERT_EQ(service_->import("req-3", kBusinessDomainV2c, items, r1), ErrorCode::SUCCESS);
    // 同 requestId 不同摘要 -> CONFLICT
    auto items2 = make_batch("req-3", 2);
    ImportResult r2;
    EXPECT_EQ(service_->import("req-3", kBusinessDomainV2c, items2, r2),
              ErrorCode::BUSINESS_KEY_CONFLICT);
}

TEST_F(BusinessKeyTest, Import_VersionRegression_Conflict) {
    make_provider();
    auto items2 = make_batch("req-4", 2);
    ImportResult r;
    ASSERT_EQ(service_->import("req-4", kBusinessDomainV2c, items2, r), ErrorCode::SUCCESS);
    auto items1 = make_batch("req-5", 1);
    ImportResult r2;
    EXPECT_EQ(service_->import("req-5", kBusinessDomainV2c, items1, r2),
              ErrorCode::BUSINESS_KEY_CONFLICT);
}

// ---------------- 校验 ----------------

TEST_F(BusinessKeyTest, Import_MissingPurpose_Unsupported) {
    make_provider();
    std::vector<WrappedKeyItem> items;
    items.push_back(make_item("req-6", kBusinessPurposeUplinkAead, "kid", 1, random_key()));
    ImportResult r;
    EXPECT_EQ(service_->import("req-6", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);
}

TEST_F(BusinessKeyTest, Import_DuplicateKeyId_Invalid) {
    make_provider();
    std::vector<WrappedKeyItem> items;
    items.push_back(make_item("req-7", kBusinessPurposeUplinkAead, "same", 1, random_key()));
    items.push_back(make_item("req-7", kBusinessPurposeDownlinkAead, "same", 1, random_key()));
    ImportResult r;
    EXPECT_EQ(service_->import("req-7", kBusinessDomainV2c, items, r),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST_F(BusinessKeyTest, Import_UnsupportedDomain) {
    make_provider();
    auto items = make_batch("req-8", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-8", "OTHER", items, r),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);
}

TEST_F(BusinessKeyTest, Import_Expired_Invalid) {
    make_provider();
    std::vector<WrappedKeyItem> items;
    items.push_back(make_item("req-9", kBusinessPurposeUplinkAead, "k1", 1, random_key(),
                              now_ms() - 100000, now_ms() - 50000));
    items.push_back(make_item("req-9", kBusinessPurposeDownlinkAead, "k2", 1, random_key(),
                              now_ms() - 100000, now_ms() - 50000));
    ImportResult r;
    EXPECT_EQ(service_->import("req-9", kBusinessDomainV2c, items, r),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST_F(BusinessKeyTest, Import_BadAad_Invalid) {
    make_provider();
    // 用错误 AAD 封装 -> 解封装完整性/AAD 校验失败
    std::vector<uint8_t> bad_aad = {'x', 'y', 'z'};
    std::vector<uint8_t> wrapped;
    std::string params;
    ASSERT_EQ(SoftFileBusinessKeyProvider::wrapForTest(
                  device_pub_, SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm,
                  bad_aad, random_key(), wrapped, params),
              ErrorCode::SUCCESS);
    std::vector<WrappedKeyItem> items = make_batch("req-10", 1);
    items[0].wrapped_key.assign(wrapped);
    items[0].parameters.assign(std::vector<uint8_t>(params.begin(), params.end()));
    ImportResult r;
    EXPECT_EQ(service_->import("req-10", kBusinessDomainV2c, items, r),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST_F(BusinessKeyTest, Import_SecondItemFailure_NoSinglePurposeActive) {
    make_provider();
    auto items = make_batch("req-11", 1);
    // 破坏第二个 item（算法不在 allowlist）-> 整体失败，不得形成单用途 ACTIVE
    items[1].algorithm = "AES-512-BOGUS";
    ImportResult r;
    EXPECT_NE(service_->import("req-11", kBusinessDomainV2c, items, r), ErrorCode::SUCCESS);

    BusinessKeySlotInfo slot;
    ASSERT_EQ(provider_->querySlot(kBusinessDomainV2c, kBusinessPurposeUplinkAead, slot),
              ErrorCode::SUCCESS);
    EXPECT_FALSE(slot.present);
    EXPECT_EQ(slot.state, BusinessKeyState::MISSING);
    EXPECT_FALSE(provider_->hasPendingStaging());
}

// ---------------- 未就绪 / 关闭 ----------------

TEST_F(BusinessKeyTest, Disabled_NotReady) {
    make_provider(/*enabled=*/false);
    BusinessKeyStatusSet set;
    EXPECT_EQ(service_->getStatus(kBusinessDomainV2c, {kBusinessPurposeUplinkAead}, set),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    auto items = make_batch("req-12", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-12", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_NOT_READY);
}

TEST_F(BusinessKeyTest, BindingNotReady_NotReady) {
    binding_.ready = false;
    make_provider();
    auto items = make_batch("req-13", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-13", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_NOT_READY);
}

// ---------------- 结果查询 / 恢复 ----------------

TEST_F(BusinessKeyTest, ImportResult_Unknown) {
    make_provider();
    ImportResult r;
    ASSERT_EQ(service_->getImportResult("never-seen", r), ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::UNKNOWN);
}

TEST_F(BusinessKeyTest, Recovery_CommitBeforeReply) {
    make_provider();
    // 模拟：staging+commit 已完成，但 journal 仍停留在 STAGED（进程在回包前掉电）。
    auto items = make_batch("req-recover", 1);
    const uint64_t gen = 1;
    for (const auto& it : items) {
        std::vector<uint8_t> aad = BusinessKeyProvisioningService::buildAad(
            "req-recover", kBusinessDomainV2c, it.purpose, it.business_key_version,
            kDeviceIdentity);
        ASSERT_EQ(provider_->unwrapToStaging(kBusinessDomainV2c, it, aad, binding_, gen),
                  ErrorCode::SUCCESS);
        ASSERT_EQ(provider_->verifyStaging(kBusinessDomainV2c, it.purpose), ErrorCode::SUCCESS);
    }
    ASSERT_EQ(provider_->commitBatch(kBusinessDomainV2c, gen), ErrorCode::SUCCESS);

    // 写一条 STAGED journal（模拟 commit 后、journal 更新前掉电）
    auto rid_digest = sha256_hex_for_test("req-recover");
    BusinessKeyJournalEntry e;
    e.request_id_digest = rid_digest;
    e.request_digest = "stale-digest";
    e.state = BusinessKeyImportState::STAGED;
    e.generation = gen;
    ASSERT_EQ(provider_->saveJournal(e), ErrorCode::SUCCESS);

    // 重建 service（新 provider 读同一 store），启动恢复应识别已 commit 的事务
    BusinessKeyProviderConfig pcfg;
    pcfg.store_root = dir_ + "/bk";
    pcfg.kek_path = dir_ + "/bk/.kek";
    pcfg.allowed_algorithms = {"AES-256-GCM"};
    pcfg.allowed_wrapping_suites = {
        SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm};
    auto provider2 = std::make_unique<SoftFileBusinessKeyProvider>(
        hsm_.get(), std::move(pcfg), [this]() { return binding_; });

    auto ledger2 = std::make_unique<SecureMetadataLedger>(
        hwyz::store::Store::open("sec", dir_));
    BusinessKeyProvisioningConfig cfg;
    cfg.enabled = true;
    cfg.allowed_wrapping_suites = {
        SoftFileBusinessKeyProvider::kSuiteEciesEcdhEsA256Gcm};
    cfg.allowed_algorithms = {"AES-256-GCM"};
    auto service2 = std::make_unique<BusinessKeyProvisioningService>(
        std::move(cfg), std::move(provider2), fake_time(), std::move(ledger2),
        [this]() { return binding_; });
    ASSERT_EQ(service2->initialize(), ErrorCode::SUCCESS);

    ImportResult r;
    ASSERT_EQ(service2->getImportResult("req-recover", r), ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::COMMITTED);
}

// ---------------- SecureBuffer ----------------

TEST(SecureBufferTest, MoveAndClear) {
    SecureBuffer b;
    std::vector<uint8_t> v = {1, 2, 3, 4};
    b.assign(v);
    EXPECT_EQ(b.size(), 4u);
    SecureBuffer c(std::move(b));
    EXPECT_EQ(c.size(), 4u);
    EXPECT_TRUE(b.empty());
    c.clear();
    EXPECT_TRUE(c.empty());
}

TEST(SecureBufferTest, EnumRoundTrip) {
    EXPECT_EQ(business_key_state_to_string(BusinessKeyState::ACTIVE), "ACTIVE");
    EXPECT_EQ(string_to_business_key_state("INVALID"), BusinessKeyState::INVALID);
    EXPECT_EQ(business_key_import_state_to_string(BusinessKeyImportState::COMMITTED),
              "COMMITTED");
    EXPECT_EQ(string_to_business_key_import_state("STAGED"),
              BusinessKeyImportState::STAGED);
}

} // namespace

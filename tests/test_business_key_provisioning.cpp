//
// V2C 业务密钥开通单元测试（TBOX-SEC-DSN-CR-019；CR-020 §5/§8/§9/§11）。
//
#include <gtest/gtest.h>

#include "business_key_provisioning.h"
#include "business_key_provider.h"
#include "canonical_encoding.h"
#include "keyprov_envelope_builder.h"
#include "secure_metadata_ledger.h"
#include "soft_file_business_key_provider.h"
#include "soft_file_hsm.h"
#include "store.h"
#include "tbox/sec/business_key.h"
#include "trusted_time.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
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

const std::string kDeviceKeyId = "ecu1+ecu1";
const std::string kDeviceIdentity = "ecu1";

/// 用设备公钥验证 P1363 proof（恒 64B、low-S）对给定 proofInput 的签名。
bool verify_p1363_proof(const std::vector<uint8_t>& device_pub,
                        const std::vector<uint8_t>& proof_input,
                        const std::vector<uint8_t>& proof) {
    if (proof.size() != 64) return false;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return false;
    bool ok = false;
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (pt && EC_POINT_oct2point(group, pt, device_pub.data(), device_pub.size(), nullptr) == 1) {
        EC_KEY_set_public_key(ec, pt);
        BIGNUM* s_bn = BN_bin2bn(proof.data() + 32, 32, nullptr);
        BIGNUM* half = BN_new();
        BN_rshift1(half, EC_GROUP_get0_order(group));
        const bool low_s = BN_cmp(s_bn, half) <= 0;
        ECDSA_SIG* sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(sig, BN_bin2bn(proof.data(), 32, nullptr),
                       BN_bin2bn(proof.data() + 32, 32, nullptr));
        unsigned char* der = nullptr;
        int der_len = i2d_ECDSA_SIG(sig, &der);
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(proof_input.data(), proof_input.size(), digest);
        ok = low_s && der_len > 0 &&
             ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, der, der_len, ec) == 1;
        OPENSSL_free(der);
        ECDSA_SIG_free(sig);
        BN_free(s_bn);
        BN_free(half);
    }
    if (pt) EC_POINT_free(pt);
    EC_KEY_free(ec);
    return ok;
}

/// 复算某 item 的 canonical proofInput（与 provider 保持一致）。
std::vector<uint8_t> item_proof_input(const std::string& request_id, const std::string& purpose,
                                      const std::string& key_id, const WrappedKeyItem& item) {
    canonical::ProofInput pi;
    pi.request_id = request_id;
    pi.business_domain = kBusinessDomainV2c;
    uint64_t purpose_val = 0;
    purposeEnumValue(purpose, purpose_val);
    pi.purpose = purpose_val;
    pi.key_id = key_id;
    pi.business_key_version = item.business_key_version;
    pi.envelope_digest = item.envelope_digest;
    pi.key_check_value =
        std::vector<uint8_t>(item.key_check_value.begin(), item.key_check_value.end());
    return canonical::buildProofInput(pi);
}

/// 统计安全原语调用的 HSM 装饰器（用于认证 US-016「0 次硬件调用」）。
class CountingHsm : public SoftFileHsm {
public:
    CountingHsm(hwyz::store::Store store, const std::string& alg, const std::string& kek)
        : SoftFileHsm(std::move(store), alg, kek) {}
    ErrorCode unwrap_ecdh_es_v1(const std::string& key_id,
                                const std::vector<uint8_t>& eph,
                                const std::vector<uint8_t>& salt,
                                const std::vector<uint8_t>& info,
                                const std::vector<uint8_t>& nonce,
                                const std::vector<uint8_t>& ct,
                                const std::vector<uint8_t>& tag,
                                const std::vector<uint8_t>& aad,
                                std::vector<uint8_t>& plain) override {
        ++unwrap_calls;
        return SoftFileHsm::unwrap_ecdh_es_v1(key_id, eph, salt, info, nonce, ct, tag, aad,
                                              plain);
    }
    ErrorCode sign_digest_p1363(const std::string& key_id,
                                const std::vector<uint8_t>& digest,
                                std::vector<uint8_t>& signature) override {
        ++sign_calls;
        return SoftFileHsm::sign_digest_p1363(key_id, digest, signature);
    }
    int unwrap_calls = 0;
    int sign_calls = 0;
};

/// commit 阶段恒返回未知错误的 provider（用于 OUTCOME_UNKNOWN 对账路径）。
class FailingCommitProvider : public BusinessKeyProvider {
public:
    explicit FailingCommitProvider(std::unique_ptr<BusinessKeyProvider> inner)
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
    bool loadJournal(const std::string& r, BusinessKeyJournalEntry& o) override {
        return inner_->loadJournal(r, o);
    }
    ErrorCode saveJournal(const BusinessKeyJournalEntry& e) override {
        return inner_->saveJournal(e);
    }
    std::vector<BusinessKeyJournalEntry> listJournal() override { return inner_->listJournal(); }
    bool hasPendingStaging() const override { return inner_->hasPendingStaging(); }

private:
    std::unique_ptr<BusinessKeyProvider> inner_;
};

class BusinessKeyTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = unique_dir();
        store_ = std::make_unique<hwyz::store::Store>(hwyz::store::Store::open("sec", dir_));
        hsm_ = std::make_unique<SoftFileHsm>(hwyz::store::Store::open("sec_hsm", dir_),
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
    }

    void TearDown() override {
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

    BusinessKeyProvisioningConfig service_config(bool enabled = true) {
        BusinessKeyProvisioningConfig cfg;
        cfg.enabled = enabled;
        cfg.is_production = false;
        cfg.allowed_algorithms = {kDefaultKeyAlgorithm};
        cfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
        cfg.allowed_envelope_formats = {kKeyEnvelopeFormatEcdhEsP256V1};
        return cfg;
    }

    std::unique_ptr<BusinessKeyProvisioningService> build_service(
        HsmInterface* hsm, std::unique_ptr<BusinessKeyProvider> provider,
        bool enabled = true) {
        (void)hsm;
        auto ledger = std::make_unique<SecureMetadataLedger>(
            hwyz::store::Store::open("sec", dir_));
        return std::make_unique<BusinessKeyProvisioningService>(
            service_config(enabled), std::move(provider), fake_time(), std::move(ledger),
            [this]() { return binding_; });
    }

    void make_provider(bool enabled = true) {
        auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
            hsm_.get(), provider_config(), [this]() { return binding_; });
        provider_ = provider.get();
        service_ = build_service(hsm_.get(), std::move(provider), enabled);
        ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);
    }

    std::vector<uint8_t> build_envelope(const std::string& request_id,
                                        const std::string& purpose, const std::string& key_id,
                                        uint64_t version, const std::vector<uint8_t>& key,
                                        const std::string& operation_id,
                                        KeyprovEnvelopeOutput& out) {
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
        in.operation_id = operation_id;
        in.recipient_certificate_digest = binding_.active_cert_digest;
        in.wrapping_suite = kWrappingSuiteEcdhEsP256;
        in.key_algorithm = kDefaultKeyAlgorithm;
        EXPECT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
        return out.wrapped_key;
    }

    WrappedKeyItem make_item(const std::string& request_id, const std::string& purpose,
                             const std::string& key_id, uint64_t version,
                             const std::vector<uint8_t>& key, int64_t from_ms = 0,
                             int64_t to_ms = 0) {
        if (from_ms == 0) from_ms = now_ms() - 1000;
        if (to_ms == 0) to_ms = now_ms() + 86400000;
        KeyprovEnvelopeOutput out;
        build_envelope(request_id, purpose, key_id, version, key, "op-" + purpose, out);
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

    std::vector<WrappedKeyItem> make_batch(const std::string& request_id, uint64_t version) {
        std::vector<WrappedKeyItem> items;
        items.push_back(make_item(request_id, kBusinessPurposeUplinkAead,
                                  "kid-up-" + std::to_string(version), version, random_key()));
        items.push_back(make_item(request_id, kBusinessPurposeDownlinkAead,
                                  "kid-down-" + std::to_string(version), version, random_key()));
        return items;
    }

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
    EXPECT_EQ(result.proof_algorithm, kImportProofAlgorithmP1363);
    EXPECT_EQ(result.binding_certificate_digest, binding_.active_cert_digest);
    for (size_t i = 0; i < result.items.size(); ++i) {
        const auto& it = result.items[i];
        EXPECT_EQ(it.envelope_format, KeyEnvelopeFormat::ECDH_ES_P256_V1);
        EXPECT_EQ(it.envelope_digest.size(), 32u);
        EXPECT_TRUE(it.key_check_value_present);
        // 逐 item Import Attestation：64B P1363 low-S，可用设备公钥验签。
        ASSERT_EQ(it.import_proof.size(), kImportProofSizeP1363);
        EXPECT_EQ(it.proof_algorithm, kImportProofAlgorithmP1363);
        auto pin = item_proof_input("req-1", items[i].purpose, items[i].key_id, items[i]);
        EXPECT_TRUE(verify_p1363_proof(device_pub_, pin, it.import_proof));
        // 篡改 proofInput 后验签必须失败（测试矩阵 §13.11）。
        pin[0] ^= 0xff;
        EXPECT_FALSE(verify_p1363_proof(device_pub_, pin, it.import_proof));
    }

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
        EXPECT_EQ(s.envelope_format, KeyEnvelopeFormat::ECDH_ES_P256_V1);
        EXPECT_EQ(s.envelope_digest.size(), 32u);
        EXPECT_TRUE(s.key_check_value_present);
    }
}

TEST_F(BusinessKeyTest, Import_Idempotent_SameDigest) {
    make_provider();
    auto items = make_batch("req-2", 1);
    ImportResult r1;
    ASSERT_EQ(service_->import("req-2", kBusinessDomainV2c, items, r1), ErrorCode::SUCCESS);
    ImportResult r2;
    ASSERT_EQ(service_->import("req-2", kBusinessDomainV2c, items, r2), ErrorCode::SUCCESS);
    EXPECT_EQ(r2.state, BusinessKeyImportState::COMMITTED);
    EXPECT_EQ(r1.items[0].key_id_digest, r2.items[0].key_id_digest);
    // 重放返回 journal 中原 proof bytes（不重新签名，测试矩阵 §13.12）。
    ASSERT_EQ(r1.items.size(), 2u);
    for (size_t i = 0; i < r1.items.size(); ++i) {
        EXPECT_EQ(r1.items[i].import_proof, r2.items[i].import_proof);
        EXPECT_EQ(r2.items[i].proof_algorithm, kImportProofAlgorithmP1363);
    }
}

TEST_F(BusinessKeyTest, Import_Conflict_DifferentDigest) {
    make_provider();
    auto items = make_batch("req-3", 1);
    ImportResult r1;
    ASSERT_EQ(service_->import("req-3", kBusinessDomainV2c, items, r1), ErrorCode::SUCCESS);
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
    EXPECT_EQ(service_->import("req-8", "OTHER", items, r), ErrorCode::BUSINESS_KEY_UNSUPPORTED);
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

TEST_F(BusinessKeyTest, Import_KcvMismatch_Invalid) {
    make_provider();
    auto items = make_batch("req-kcv", 1);
    items[0].key_check_value = {0x00, 0x00, 0x00};
    ImportResult r;
    EXPECT_EQ(service_->import("req-kcv", kBusinessDomainV2c, items, r),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST_F(BusinessKeyTest, Import_CiphertextTamper_Invalid) {
    make_provider();
    auto items = make_batch("req-ct", 1);
    items[0].wrapped_key.data()[0] ^= 0xff;
    ImportResult r;
    EXPECT_EQ(service_->import("req-ct", kBusinessDomainV2c, items, r),
              ErrorCode::WRAPPED_KEY_INVALID);
    EXPECT_FALSE(provider_->hasPendingStaging());
}

TEST_F(BusinessKeyTest, Import_SecondItemFailure_NoSinglePurposeActive) {
    make_provider();
    auto items = make_batch("req-11", 1);
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

TEST_F(BusinessKeyTest, CertKeyAgreementMissing_NotReady_NoHardwareCalls) {
    binding_.active_cert_key_agreement = false;
    auto counting = std::make_unique<CountingHsm>(
        hwyz::store::Store::open("sec_hsm", dir_), "aes-256-gcm", dir_ + "/.hsm_kek");
    ASSERT_EQ(counting->initialize(), ErrorCode::SUCCESS);
    KeyPair kp;
    ASSERT_EQ(counting->generate_key_pair(kDeviceKeyId, "ecdsa-p256", kp), ErrorCode::SUCCESS);
    CountingHsm* counter = counting.get();

    auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
        counting.get(), provider_config(), [this]() { return binding_; });
    service_ = build_service(counting.get(), std::move(provider));
    ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);

    auto items = make_batch("req-ku", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-ku", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_EQ(counter->unwrap_calls, 0);
}

TEST_F(BusinessKeyTest, CertDigitalSignatureMissing_NotReady_NoHardwareCalls) {
    binding_.active_cert_digital_signature = false;
    auto counting = std::make_unique<CountingHsm>(
        hwyz::store::Store::open("sec_hsm", dir_), "aes-256-gcm", dir_ + "/.hsm_kek");
    ASSERT_EQ(counting->initialize(), ErrorCode::SUCCESS);
    KeyPair kp;
    ASSERT_EQ(counting->generate_key_pair(kDeviceKeyId, "ecdsa-p256", kp), ErrorCode::SUCCESS);
    CountingHsm* counter = counting.get();

    auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
        counting.get(), provider_config(), [this]() { return binding_; });
    service_ = build_service(counting.get(), std::move(provider));
    ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);

    auto items = make_batch("req-digsig", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-digsig", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_EQ(counter->unwrap_calls, 0);
    EXPECT_EQ(counter->sign_calls, 0);
}

TEST_F(BusinessKeyTest, PrivateKeySignMissing_NotReady_NoHardwareCalls) {
    binding_.private_key_can_sign = false;
    auto counting = std::make_unique<CountingHsm>(
        hwyz::store::Store::open("sec_hsm", dir_), "aes-256-gcm", dir_ + "/.hsm_kek");
    ASSERT_EQ(counting->initialize(), ErrorCode::SUCCESS);
    KeyPair kp;
    ASSERT_EQ(counting->generate_key_pair(kDeviceKeyId, "ecdsa-p256", kp), ErrorCode::SUCCESS);
    CountingHsm* counter = counting.get();

    auto provider = std::make_unique<SoftFileBusinessKeyProvider>(
        counting.get(), provider_config(), [this]() { return binding_; });
    service_ = build_service(counting.get(), std::move(provider));
    ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);

    auto items = make_batch("req-sign", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-sign", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_NOT_READY);
    EXPECT_EQ(counter->unwrap_calls, 0);
    EXPECT_EQ(counter->sign_calls, 0);
}

TEST_F(BusinessKeyTest, ImportProof_ReplayDoesNotReSign) {
    make_provider();
    auto items = make_batch("req-resign", 1);
    ImportResult r1;
    ASSERT_EQ(service_->import("req-resign", kBusinessDomainV2c, items, r1), ErrorCode::SUCCESS);
    // ECDSA 非确定性：若重放重新签名，字节必然不同。逐字节相等即证明未重新签名。
    for (const auto& it : r1.items) ASSERT_EQ(it.import_proof.size(), kImportProofSizeP1363);
    ImportResult r2;
    ASSERT_EQ(service_->import("req-resign", kBusinessDomainV2c, items, r2), ErrorCode::SUCCESS);
    ASSERT_EQ(r2.items.size(), r1.items.size());
    for (size_t i = 0; i < r1.items.size(); ++i) {
        EXPECT_EQ(r1.items[i].import_proof, r2.items[i].import_proof);
    }

    // 结果查询同样回传 journal 原 proof。
    ImportResult q;
    ASSERT_EQ(service_->getImportResult("req-resign", q), ErrorCode::SUCCESS);
    ASSERT_EQ(q.items.size(), r1.items.size());
    for (size_t i = 0; i < r1.items.size(); ++i) {
        EXPECT_EQ(q.items[i].import_proof, r1.items[i].import_proof);
    }
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
    auto items = make_batch("req-recover", 1);
    ImportResult r0;
    ASSERT_EQ(service_->import("req-recover", kBusinessDomainV2c, items, r0), ErrorCode::SUCCESS);

    // 模拟：commit 已完成但进程在更新 journal 前掉电（journal 停留在 PROCESSING）。
    const std::string rid = canonical::toHex(canonical::sha256(std::string("req-recover")));
    BusinessKeyJournalEntry e;
    ASSERT_TRUE(provider_->loadJournal(rid, e));
    e.phase = BusinessKeyImportPhase::PROCESSING;
    ASSERT_EQ(provider_->saveJournal(e), ErrorCode::SUCCESS);

    // 重建 service（新 provider 读同一 store），启动恢复应识别已 commit 的事务。
    service_.reset();
    auto provider2 = std::make_unique<SoftFileBusinessKeyProvider>(
        hsm_.get(), provider_config(), [this]() { return binding_; });
    auto service2 = build_service(hsm_.get(), std::move(provider2));
    ASSERT_EQ(service2->initialize(), ErrorCode::SUCCESS);

    ImportResult r;
    ASSERT_EQ(service2->getImportResult("req-recover", r), ErrorCode::SUCCESS);
    EXPECT_EQ(r.state, BusinessKeyImportState::COMMITTED);
}

TEST_F(BusinessKeyTest, OutcomeUnknown_WhenCommitAmbiguous) {
    auto inner = std::make_unique<SoftFileBusinessKeyProvider>(
        hsm_.get(), provider_config(), [this]() { return binding_; });
    auto provider = std::make_unique<FailingCommitProvider>(std::move(inner));
    service_ = build_service(hsm_.get(), std::move(provider));
    ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);

    auto items = make_batch("req-unknown", 1);
    ImportResult r;
    EXPECT_EQ(service_->import("req-unknown", kBusinessDomainV2c, items, r),
              ErrorCode::BUSINESS_KEY_OUTCOME_UNKNOWN);
    EXPECT_EQ(r.state, BusinessKeyImportState::UNKNOWN);

    ImportResult q;
    ASSERT_EQ(service_->getImportResult("req-unknown", q), ErrorCode::SUCCESS);
    EXPECT_EQ(q.state, BusinessKeyImportState::UNKNOWN);
}

// ---------------- SecureBuffer / 枚举 ----------------

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
    EXPECT_EQ(string_to_business_key_import_state("STAGED"), BusinessKeyImportState::STAGED);
    EXPECT_EQ(key_envelope_format_to_string(KeyEnvelopeFormat::ECDH_ES_P256_V1),
              "ECDH_ES_P256_V1");
    EXPECT_EQ(string_to_key_envelope_format("ECDH_ES_P256_V1"),
              KeyEnvelopeFormat::ECDH_ES_P256_V1);
    EXPECT_EQ(business_key_import_phase_to_string(BusinessKeyImportPhase::OUTCOME_UNKNOWN),
              "OUTCOME_UNKNOWN");
    EXPECT_EQ(string_to_business_key_import_phase("BOTH_STAGED"),
              BusinessKeyImportPhase::BOTH_STAGED);
}

} // namespace

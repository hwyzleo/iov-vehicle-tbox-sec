//
// V2C 业务密钥开通服务实现（TBOX-SEC-DSN-CR-019）。
//
#include "business_key_provisioning.h"
#include "sec_log_adapter.h"

#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <set>

namespace tbox {
namespace sec {

namespace {

using json = nlohmann::json;

std::string to_hex(const std::vector<uint8_t>& v) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (uint8_t b : v) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

std::string sha256_hex(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> d(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), d.data());
    return to_hex(d);
}
std::string sha256_hex(const std::string& s) {
    return sha256_hex(std::vector<uint8_t>(s.begin(), s.end()));
}
std::string sha256_hex(const uint8_t* p, size_t n) {
    std::vector<uint8_t> d(SHA256_DIGEST_LENGTH);
    SHA256(p, n, d.data());
    return to_hex(d);
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

/// 导入事件日志守护：仅记录 requestId 摘要/状态/耗时，绝不记录 proof/密钥/wrapped key。
struct ImportLogGuard {
    std::string rid_digest;
    const ImportResult& out;
    std::chrono::steady_clock::time_point t0;
    ~ImportLogGuard() {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        SecLogAdapter::business_key().info(
            "sec.business_key.import",
            "业务密钥批次导入处理完成",
            {tbox::fw::log::Field("request_id_digest",
                 tbox::fw::log::FieldValue::makeString(rid_digest)),
             tbox::fw::log::Field("state",
                 tbox::fw::log::FieldValue::makeString(
                     business_key_import_state_to_string(out.state))),
             tbox::fw::log::Field("duration_ms",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(ms)))});
    }
};

} // namespace

// ============================================================
// Impl
// ============================================================

class BusinessKeyProvisioningService::Impl {
public:
    BusinessKeyProvisioningConfig cfg;
    std::unique_ptr<BusinessKeyProvider> provider;
    std::shared_ptr<TrustedTimeProvider> trusted_time;
    std::unique_ptr<SecureMetadataLedger> ledger;
    BusinessKeyDeviceBindingProvider binding_provider;

    mutable std::mutex mtx;
    bool ready = false;

    ErrorCode trusted_now_ms(int64_t& out) {
        if (!trusted_time) return ErrorCode::BUSINESS_KEY_NOT_READY;
        TrustedTimeSample s = trusted_time->now();
        if (s.trust_state != TimeTrustState::Trusted) return ErrorCode::BUSINESS_KEY_NOT_READY;
        out = std::chrono::duration_cast<std::chrono::milliseconds>(
                  s.utc_now.time_since_epoch())
                  .count();
        return ErrorCode::SUCCESS;
    }

    uint64_t next_generation() {
        uint64_t max_gen = 0;
        for (const auto& p : cfg.required_purposes) {
            BusinessKeySlotInfo slot;
            if (provider->querySlot(kBusinessDomainV2c, p, slot) == ErrorCode::SUCCESS) {
                max_gen = std::max(max_gen, slot.active_generation);
            }
        }
        return max_gen + 1;
    }

    ErrorCode validate_structure(const std::string& request_id,
                                 const std::string& domain,
                                 const std::vector<WrappedKeyItem>& items) {
        if (request_id.empty()) return ErrorCode::INVALID_PARAMETER;
        if (request_id.size() > 128) return ErrorCode::INVALID_PARAMETER;
        if (!contains(cfg.allowed_domains, domain)) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
        if (static_cast<int>(items.size()) != cfg.max_items) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
        if (static_cast<int>(items.size()) != static_cast<int>(cfg.required_purposes.size()))
            return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

        std::set<std::string> seen_purposes;
        std::set<std::string> seen_key_ids;
        for (const auto& item : items) {
            if (!contains(cfg.required_purposes, item.purpose))
                return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
            if (!seen_purposes.insert(item.purpose).second)
                return ErrorCode::BUSINESS_KEY_UNSUPPORTED;  // 重复 purpose
            if (item.key_id.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
            if (!seen_key_ids.insert(item.key_id).second)
                return ErrorCode::WRAPPED_KEY_INVALID;  // 两用途不得共用 keyId
            if (!contains(cfg.allowed_algorithms, item.algorithm))
                return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
            if (item.business_key_version == 0) return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.valid_from_ms <= 0 || item.valid_to_ms <= item.valid_from_ms)
                return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.wrapped_key.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
            if (static_cast<int64_t>(item.wrapped_key.size()) > cfg.max_wrapped_key_bytes)
                return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.parameters.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
        }
        // 完整 purpose 集合：所有 required_purposes 必须出现
        for (const auto& p : cfg.required_purposes) {
            if (seen_purposes.find(p) == seen_purposes.end())
                return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
        }
        return ErrorCode::SUCCESS;
    }

    ErrorCode validate_version_and_time(const std::string& domain,
                                        const std::vector<WrappedKeyItem>& items) {
        int64_t now = 0;
        ErrorCode rc = trusted_now_ms(now);
        if (rc != ErrorCode::SUCCESS) return rc;
        for (const auto& item : items) {
            BusinessKeySlotInfo slot;
            if (provider->querySlot(domain, item.purpose, slot) == ErrorCode::SUCCESS &&
                slot.present && item.business_key_version <= slot.business_key_version) {
                return ErrorCode::BUSINESS_KEY_CONFLICT;  // 版本必须单调递增
            }
            if (now < item.valid_from_ms || now > item.valid_to_ms) {
                return ErrorCode::WRAPPED_KEY_INVALID;  // 不在有效期
            }
        }
        return ErrorCode::SUCCESS;
    }

    std::string build_request_digest(const std::string& domain,
                                     const std::vector<WrappedKeyItem>& items) {
        std::vector<const WrappedKeyItem*> sorted;
        for (const auto& i : items) sorted.push_back(&i);
        std::sort(sorted.begin(), sorted.end(),
                  [](const WrappedKeyItem* a, const WrappedKeyItem* b) {
                      return a->purpose < b->purpose;
                  });
        json j;
        j["domain"] = domain;
        j["provider"] = provider->providerVersionDigest();
        json arr = json::array();
        for (auto* i : sorted) {
            json e;
            e["purpose"] = i->purpose;
            e["key_id"] = i->key_id;
            e["version"] = i->business_key_version;
            e["algorithm"] = i->algorithm;
            e["valid_from_ms"] = i->valid_from_ms;
            e["valid_to_ms"] = i->valid_to_ms;
            e["wrapped_sha256"] = sha256_hex(i->wrapped_key.data(), i->wrapped_key.size());
            e["params_sha256"] = sha256_hex(i->parameters.data(), i->parameters.size());
            arr.push_back(e);
        }
        j["items"] = arr;
        return sha256_hex(j.dump());
    }

    ErrorCode fill_status(const std::string& domain, const std::string& purpose,
                          BusinessKeyStatus& out) {
        out.business_domain = domain;
        out.purpose = purpose;
        BusinessKeySlotInfo slot;
        ErrorCode rc = provider->querySlot(domain, purpose, slot);
        if (rc != ErrorCode::SUCCESS) return rc;
        BusinessKeyMetadata meta;
        bool has_meta = ledger && ledger->get(domain, purpose, meta);

        if (!slot.present && !has_meta) {
            out.state = BusinessKeyState::MISSING;
            return ErrorCode::SUCCESS;
        }
        if (slot.present && has_meta && slot.state == BusinessKeyState::ACTIVE &&
            meta.business_key_version == slot.business_key_version &&
            meta.key_id_digest == slot.key_id_digest && meta.algorithm == slot.algorithm) {
            out.state = BusinessKeyState::ACTIVE;
            out.business_key_version = slot.business_key_version;
            out.key_id_digest = slot.key_id_digest;
            out.algorithm = slot.algorithm;
            out.valid_from_ms = slot.valid_from_ms;
            out.valid_to_ms = slot.valid_to_ms;
            return ErrorCode::SUCCESS;
        }
        // slot 与 ledger 不一致或 slot 非法 → INVALID（fail-closed）
        out.state = BusinessKeyState::INVALID;
        out.business_key_version = slot.present ? slot.business_key_version : 0;
        out.key_id_digest = slot.key_id_digest;
        out.algorithm = slot.algorithm;
        return ErrorCode::SUCCESS;
    }

    ErrorCode build_committed_result(const BusinessKeyJournalEntry& entry,
                                     ImportResult& out) {
        out.business_domain = kBusinessDomainV2c;
        out.state = BusinessKeyImportState::COMMITTED;
        out.items = entry.items;
        out.committed_at_ms = entry.committed_at_ms;
        out.provider_version_digest = entry.provider_version_digest;
        // 重新生成 importProof（确定性 HMAC；不落日志/Store）
        json proofs = json::object();
        std::string alg = "HMAC-SHA256";
        for (const auto& it : entry.items) {
            std::vector<uint8_t> proof;
            std::string palg;
            ErrorCode rc = provider->generateProof(kBusinessDomainV2c, it.purpose,
                                                   it.business_key_version,
                                                   out.request_id, it.key_id_digest, proof, palg);
            (void)rc;
            if (rc == ErrorCode::SUCCESS) {
                proofs[it.purpose] = to_hex(proof);
                alg = palg;
                if (!proof.empty()) OPENSSL_cleanse(proof.data(), proof.size());
            }
        }
        std::string s = proofs.dump();
        out.import_proof.assign(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        out.proof_algorithm = alg;
        return ErrorCode::SUCCESS;
    }

    ErrorCode recover_entry(BusinessKeyJournalEntry& entry) {
        int64_t now = 0;
        trusted_now_ms(now);
        bool both_active = true;
        for (const auto& p : cfg.required_purposes) {
            BusinessKeySlotInfo slot;
            provider->querySlot(kBusinessDomainV2c, p, slot);
            if (!(slot.present && slot.state == BusinessKeyState::ACTIVE &&
                  slot.active_generation == entry.generation)) {
                both_active = false;
                break;
            }
        }
        if (both_active) {
            entry.state = BusinessKeyImportState::COMMITTED;
            entry.committed_at_ms = now;
            entry.provider_version_digest = provider->providerVersionDigest();
            for (auto& it : entry.items) it.state = BusinessKeyState::ACTIVE;
            provider->saveJournal(entry);
            for (const auto& it : entry.items) {
                BusinessKeyMetadata meta;
                meta.present = true;
                meta.business_domain = kBusinessDomainV2c;
                meta.purpose = it.purpose;
                meta.key_id_digest = it.key_id_digest;
                meta.business_key_version = it.business_key_version;
                meta.algorithm = it.algorithm;
                meta.valid_from_ms = it.valid_from_ms;
                meta.valid_to_ms = it.valid_to_ms;
                meta.active_generation = entry.generation;
                meta.request_id_digest = entry.request_id_digest;
                meta.committed_at_ms = entry.committed_at_ms;
                if (ledger) ledger->put(meta);
            }
            return ErrorCode::SUCCESS;
        }
        // 未 commit：安全回滚，不得形成单用途 ACTIVE
        provider->rollbackStaging(kBusinessDomainV2c, entry.generation);
        entry.state = BusinessKeyImportState::FAILED;
        entry.last_error = "BUSINESS_KEY_PARTIAL_ROLLBACK";
        provider->saveJournal(entry);
        return ErrorCode::SUCCESS;
    }

    ErrorCode recover_on_startup() {
        for (auto entry : provider->listJournal()) {
            if (entry.state == BusinessKeyImportState::COMMITTED ||
                entry.state == BusinessKeyImportState::FAILED) {
                continue;
            }
            recover_entry(entry);
        }
        return ErrorCode::SUCCESS;
    }
};

// ============================================================
// Construction
// ============================================================

BusinessKeyProvisioningService::BusinessKeyProvisioningService(
    BusinessKeyProvisioningConfig config,
    std::unique_ptr<BusinessKeyProvider> provider,
    std::shared_ptr<TrustedTimeProvider> trusted_time,
    std::unique_ptr<SecureMetadataLedger> ledger,
    BusinessKeyDeviceBindingProvider binding_provider)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
    impl_->provider = std::move(provider);
    impl_->trusted_time = std::move(trusted_time);
    impl_->ledger = std::move(ledger);
    impl_->binding_provider = std::move(binding_provider);

    if (impl_->cfg.allowed_domains.empty()) impl_->cfg.allowed_domains = {kBusinessDomainV2c};
    if (impl_->cfg.required_purposes.empty()) {
        impl_->cfg.required_purposes = {kBusinessPurposeUplinkAead,
                                        kBusinessPurposeDownlinkAead};
    }
    if (impl_->cfg.allowed_algorithms.empty()) impl_->cfg.allowed_algorithms = {"AES-256-GCM"};
    if (impl_->cfg.allowed_wrapping_suites.empty()) {
        impl_->cfg.allowed_wrapping_suites = {
            "ECIES-ECDH-ES-A256GCM-v1"};
    }
}

BusinessKeyProvisioningService::~BusinessKeyProvisioningService() = default;

ErrorCode BusinessKeyProvisioningService::initialize() {
    std::lock_guard<std::mutex> lock(impl_->mtx);

    if (!impl_->cfg.enabled) {
        impl_->ready = false;
        SecLogAdapter::business_key().info(
            "sec.business_key.disabled", "业务密钥开通未启用（保持 NOT_READY）");
        return ErrorCode::SUCCESS;
    }
    if (!impl_->provider || !impl_->ledger || !impl_->trusted_time) {
        impl_->ready = false;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    if (impl_->provider->initialize() != ErrorCode::SUCCESS) {
        impl_->ready = false;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    if (impl_->ledger->load() != ErrorCode::SUCCESS) {
        impl_->ready = false;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    impl_->recover_on_startup();
    impl_->ready = impl_->provider->isReady();
    if (!impl_->ready) {
        SecLogAdapter::business_key().warn(
            "sec.business_key.provider_not_ready",
            "业务密钥 provider 未就绪（fail-closed，保持 NOT_READY）");
    }
    return ErrorCode::SUCCESS;
}

void BusinessKeyProvisioningService::beginShutdown() {
    shutting_down_.store(true);
}

bool BusinessKeyProvisioningService::isReady() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->ready && !shutting_down_.load();
}

// ============================================================
// Status
// ============================================================

ErrorCode BusinessKeyProvisioningService::getStatus(
    const std::string& business_domain, const std::vector<std::string>& purposes,
    BusinessKeyStatusSet& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out.items.clear();
    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!contains(impl_->cfg.allowed_domains, business_domain))
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    if (purposes.empty()) return ErrorCode::INVALID_PARAMETER;
    for (const auto& p : purposes) {
        if (!contains(impl_->cfg.required_purposes, p))
            return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
        BusinessKeyStatus st;
        ErrorCode rc = impl_->fill_status(business_domain, p, st);
        if (rc != ErrorCode::SUCCESS) return rc;
        out.items.push_back(std::move(st));
    }
    return ErrorCode::SUCCESS;
}

// ============================================================
// Import
// ============================================================

ErrorCode BusinessKeyProvisioningService::import(
    const std::string& request_id, const std::string& business_domain,
    const std::vector<WrappedKeyItem>& items, ImportResult& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out = ImportResult{};
    out.request_id = request_id;
    out.business_domain = business_domain;
    ImportLogGuard log_guard{sha256_hex(request_id), out, std::chrono::steady_clock::now()};

    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->cfg.enabled || !impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;

    ErrorCode rc = impl_->validate_structure(request_id, business_domain, items);
    if (rc != ErrorCode::SUCCESS) {
        out.state = BusinessKeyImportState::FAILED;
        return rc;
    }

    const std::string rid_digest = sha256_hex(request_id);
    const std::string digest = impl_->build_request_digest(business_domain, items);

    // ---- 幂等 / 冲突 / 恢复 ----
    BusinessKeyJournalEntry existing;
    if (impl_->provider->loadJournal(rid_digest, existing)) {
        if (!existing.request_digest.empty() && existing.request_digest != digest) {
            out.state = BusinessKeyImportState::FAILED;
            return ErrorCode::BUSINESS_KEY_CONFLICT;
        }
        if (existing.state == BusinessKeyImportState::COMMITTED) {
            return impl_->build_committed_result(existing, out);
        }
        if (existing.state == BusinessKeyImportState::FAILED) {
            out.state = BusinessKeyImportState::FAILED;
            out.items = existing.items;
            return ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN;
        }
        // REQUESTED/STAGED/UNKNOWN：尝试收敛
        impl_->recover_entry(existing);
        if (existing.state == BusinessKeyImportState::COMMITTED) {
            return impl_->build_committed_result(existing, out);
        }
        out.state = BusinessKeyImportState::FAILED;
        out.items = existing.items;
        return ErrorCode::BUSINESS_KEY_PARTIAL_ROLLBACK;
    }

    // ---- 版本/有效期/可信时间 ----
    rc = impl_->validate_version_and_time(business_domain, items);
    if (rc != ErrorCode::SUCCESS) {
        out.state = BusinessKeyImportState::FAILED;
        return rc;
    }

    // ---- 设备解封装身份 ----
    BusinessKeyDeviceBinding binding;
    if (impl_->binding_provider) binding = impl_->binding_provider();
    if (!binding.ready || binding.device_key_id.empty()) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }

    const uint64_t generation = impl_->next_generation();
    int64_t now = 0;
    impl_->trusted_now_ms(now);

    // ---- journal REQUESTED ----
    BusinessKeyJournalEntry entry;
    entry.request_id_digest = rid_digest;
    entry.request_digest = digest;
    entry.state = BusinessKeyImportState::REQUESTED;
    entry.generation = generation;
    entry.created_at_ms = now;
    entry.provider_version_digest = impl_->provider->providerVersionDigest();
    impl_->provider->saveJournal(entry);

    // ---- unwrap 到 staging ----
    for (const auto& item : items) {
        std::vector<uint8_t> aad = buildAad(request_id, business_domain, item.purpose,
                                            item.business_key_version, binding.device_identity);
        rc = impl_->provider->unwrapToStaging(business_domain, item, aad, binding, generation);
        if (rc != ErrorCode::SUCCESS) {
            impl_->provider->rollbackStaging(business_domain, generation);
            entry.state = BusinessKeyImportState::FAILED;
            entry.last_error = error_code_to_string(rc);
            impl_->provider->saveJournal(entry);
            binding.clearPublicKey();
            out.state = BusinessKeyImportState::FAILED;
            return rc;
        }
    }

    // ---- verify staging ----
    for (const auto& item : items) {
        rc = impl_->provider->verifyStaging(business_domain, item.purpose);
        if (rc != ErrorCode::SUCCESS) {
            impl_->provider->rollbackStaging(business_domain, generation);
            entry.state = BusinessKeyImportState::FAILED;
            entry.last_error = error_code_to_string(rc);
            impl_->provider->saveJournal(entry);
            binding.clearPublicKey();
            out.state = BusinessKeyImportState::FAILED;
            return rc;
        }
    }

    // ---- 原子 commit ----
    rc = impl_->provider->commitBatch(business_domain, generation);
    if (rc != ErrorCode::SUCCESS) {
        impl_->provider->rollbackStaging(business_domain, generation);
        entry.state = BusinessKeyImportState::FAILED;
        entry.last_error = error_code_to_string(rc);
        impl_->provider->saveJournal(entry);
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return rc;
    }
    binding.clearPublicKey();

    // ---- 结果元数据 + ledger ----
    int64_t committed_at = now;
    impl_->trusted_now_ms(committed_at);
    entry.state = BusinessKeyImportState::COMMITTED;
    entry.committed_at_ms = committed_at;
    entry.provider_version_digest = impl_->provider->providerVersionDigest();
    for (const auto& item : items) {
        BusinessKeyStatus st;
        impl_->fill_status(business_domain, item.purpose, st);
        entry.items.push_back(st);

        BusinessKeyMetadata meta;
        meta.present = true;
        meta.business_domain = business_domain;
        meta.purpose = item.purpose;
        meta.key_id_digest = st.key_id_digest;
        meta.business_key_version = item.business_key_version;
        meta.algorithm = item.algorithm;
        meta.valid_from_ms = item.valid_from_ms;
        meta.valid_to_ms = item.valid_to_ms;
        meta.active_generation = generation;
        meta.request_id_digest = rid_digest;
        meta.created_at_ms = now;
        meta.committed_at_ms = committed_at;
        impl_->ledger->put(meta);
    }
    impl_->provider->saveJournal(entry);

    return impl_->build_committed_result(entry, out);
}

// ============================================================
// Result query
// ============================================================

ErrorCode BusinessKeyProvisioningService::getImportResult(const std::string& request_id,
                                                          ImportResult& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out = ImportResult{};
    out.request_id = request_id;
    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->cfg.enabled || !impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (request_id.empty()) return ErrorCode::INVALID_PARAMETER;

    const std::string rid_digest = sha256_hex(request_id);
    BusinessKeyJournalEntry entry;
    if (!impl_->provider->loadJournal(rid_digest, entry)) {
        out.state = BusinessKeyImportState::UNKNOWN;
        return ErrorCode::SUCCESS;  // 未知：调用方应先查询而非重放
    }
    if (entry.state == BusinessKeyImportState::COMMITTED) {
        return impl_->build_committed_result(entry, out);
    }
    out.business_domain = kBusinessDomainV2c;
    out.state = entry.state;
    out.items = entry.items;
    out.provider_version_digest = entry.provider_version_digest;
    return ErrorCode::SUCCESS;
}

// ============================================================
// AAD
// ============================================================

std::vector<uint8_t> BusinessKeyProvisioningService::buildAad(
    const std::string& request_id, const std::string& business_domain,
    const std::string& purpose, uint64_t business_key_version,
    const std::string& device_identity) {
    std::string aad = "openiov|keyprov|v1|" + request_id + "|" + business_domain + "|" +
                      purpose + "|" + std::to_string(business_key_version) + "|" +
                      device_identity;
    return std::vector<uint8_t>(aad.begin(), aad.end());
}

} // namespace sec
} // namespace tbox

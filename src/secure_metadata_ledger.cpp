//
// SecureMetadataLedger 实现（TBOX-SEC-DSN-CR-019 §6）。
//
#include "secure_metadata_ledger.h"
#include "store.h"

#include <nlohmann/json.hpp>

#include <map>

namespace tbox {
namespace sec {

class SecureMetadataLedger::Impl {
public:
    explicit Impl(hwyz::store::Store store) : store_(std::move(store)) {}

    hwyz::store::Store store_;
    mutable std::mutex mtx_;
    std::map<std::string, BusinessKeyMetadata> entries;  // key = domain + "|" + purpose

    static std::string make_key(const std::string& domain, const std::string& purpose) {
        return domain + "|" + purpose;
    }

    static nlohmann::json to_json(const BusinessKeyMetadata& m) {
        nlohmann::json j;
        j["business_domain"] = m.business_domain;
        j["purpose"] = m.purpose;
        j["key_id_digest"] = m.key_id_digest;
        j["business_key_version"] = m.business_key_version;
        j["algorithm"] = m.algorithm;
        j["valid_from_ms"] = m.valid_from_ms;
        j["valid_to_ms"] = m.valid_to_ms;
        j["active_generation"] = m.active_generation;
        j["request_id_digest"] = m.request_id_digest;
        j["created_at_ms"] = m.created_at_ms;
        j["committed_at_ms"] = m.committed_at_ms;
        return j;
    }

    static BusinessKeyMetadata from_json(const nlohmann::json& j) {
        BusinessKeyMetadata m;
        m.present = true;
        m.business_domain = j.value("business_domain", "");
        m.purpose = j.value("purpose", "");
        m.key_id_digest = j.value("key_id_digest", "");
        m.business_key_version = j.value("business_key_version", 0ULL);
        m.algorithm = j.value("algorithm", "");
        m.valid_from_ms = j.value("valid_from_ms", 0LL);
        m.valid_to_ms = j.value("valid_to_ms", 0LL);
        m.active_generation = j.value("active_generation", 0ULL);
        m.request_id_digest = j.value("request_id_digest", "");
        m.created_at_ms = j.value("created_at_ms", 0LL);
        m.committed_at_ms = j.value("committed_at_ms", 0LL);
        return m;
    }
};

SecureMetadataLedger::SecureMetadataLedger(hwyz::store::Store store)
    : impl_(std::make_unique<Impl>(std::move(store))) {}

SecureMetadataLedger::~SecureMetadataLedger() = default;

ErrorCode SecureMetadataLedger::load() {
    std::lock_guard<std::mutex> lock(impl_->mtx_);
    if (!impl_->store_.isReady()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    try {
        if (!impl_->store_.has("ledger")) return ErrorCode::SUCCESS;
        auto j = nlohmann::json::parse(impl_->store_.load<std::string>("ledger"));
        impl_->entries.clear();
        for (auto& [k, v] : j.items()) {
            impl_->entries[k] = Impl::from_json(v);
        }
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::STORAGE_CORRUPTION;
    }
}

bool SecureMetadataLedger::get(const std::string& domain, const std::string& purpose,
                               BusinessKeyMetadata& out) const {
    std::lock_guard<std::mutex> lock(impl_->mtx_);
    auto it = impl_->entries.find(Impl::make_key(domain, purpose));
    if (it == impl_->entries.end()) {
        out = BusinessKeyMetadata{};
        return false;
    }
    out = it->second;
    return true;
}

ErrorCode SecureMetadataLedger::put(const BusinessKeyMetadata& meta) {
    std::lock_guard<std::mutex> lock(impl_->mtx_);
    if (!impl_->store_.isReady()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    impl_->entries[Impl::make_key(meta.business_domain, meta.purpose)] = meta;
    try {
        nlohmann::json j = nlohmann::json::object();
        for (auto& [k, v] : impl_->entries) {
            j[k] = Impl::to_json(v);
        }
        impl_->store_.save("ledger", j.dump());
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::STORAGE_WRITE_FAILED;
    }
}

} // namespace sec
} // namespace tbox

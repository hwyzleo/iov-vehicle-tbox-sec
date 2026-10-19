//
// SoftFile V2C 业务密钥 provider 实现（TBOX-SEC-DSN-CR-019；CR-020 §7/§8/§11）。
//
#include "soft_file_business_key_provider.h"

#include "business_key_envelope.h"
#include "canonical_encoding.h"
#include "sec_log_adapter.h"
#include "store.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>

namespace tbox {
namespace sec {

namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr int kAesGcmIv = 12;
constexpr int kAesGcmTag = 16;
constexpr int kKekSize = 32;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string to_hex(const uint8_t* data, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}
std::string to_hex(const std::vector<uint8_t>& v) { return to_hex(v.data(), v.size()); }

bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

void zero(std::vector<uint8_t>& v) {
    if (!v.empty()) OPENSSL_cleanse(v.data(), v.size());
    v.clear();
}

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> mac(SHA256_DIGEST_LENGTH);
    unsigned int n = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), msg.data(), msg.size(),
         mac.data(), &n);
    mac.resize(n);
    return mac;
}

void hkdf_sha256(const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& salt,
                 const std::vector<uint8_t>& info, uint8_t* out, size_t out_len) {
    uint8_t prk[SHA256_DIGEST_LENGTH];
    unsigned int prk_len = 0;
    const uint8_t zeros[SHA256_DIGEST_LENGTH] = {0};
    const uint8_t* salt_ptr = salt.empty() ? zeros : salt.data();
    size_t salt_len = salt.empty() ? SHA256_DIGEST_LENGTH : salt.size();
    HMAC(EVP_sha256(), salt_ptr, static_cast<int>(salt_len), ikm.data(), ikm.size(), prk,
         &prk_len);

    std::vector<uint8_t> t;
    size_t pos = 0;
    uint8_t counter = 1;
    while (pos < out_len) {
        std::vector<uint8_t> data;
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(counter);
        uint8_t block[SHA256_DIGEST_LENGTH];
        unsigned int n = 0;
        HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH, data.data(), data.size(), block, &n);
        size_t take = std::min<size_t>(n, out_len - pos);
        std::memcpy(out + pos, block, take);
        pos += take;
        t.assign(block, block + n);
        ++counter;
    }
    OPENSSL_cleanse(prk, sizeof(prk));
}

// AES-256-GCM：仅用于 at-rest slot 加密（IV 前置、tag 后置）。
bool aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& aad,
                     const std::vector<uint8_t>& plain, std::vector<uint8_t>& out_iv_ct_tag) {
    std::vector<uint8_t> iv(kAesGcmIv);
    if (RAND_bytes(iv.data(), kAesGcmIv) != 1) return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    std::vector<uint8_t> ct(plain.size() + kAesGcmTag);
    int out_len = 0, total = 0;
    bool ok = true;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) ok = false;
    if (ok && !aad.empty() &&
        EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1)
        ok = false;
    if (ok && !plain.empty() &&
        EVP_EncryptUpdate(ctx, ct.data(), &out_len, plain.data(), static_cast<int>(plain.size())) !=
            1)
        ok = false;
    total = out_len;
    if (ok && EVP_EncryptFinal_ex(ctx, ct.data() + total, &out_len) != 1) ok = false;
    total += out_len;
    std::vector<uint8_t> tag(kAesGcmTag);
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kAesGcmTag, tag.data()) != 1)
        ok = false;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    out_iv_ct_tag.clear();
    out_iv_ct_tag.insert(out_iv_ct_tag.end(), iv.begin(), iv.end());
    out_iv_ct_tag.insert(out_iv_ct_tag.end(), ct.begin(), ct.begin() + total);
    out_iv_ct_tag.insert(out_iv_ct_tag.end(), tag.begin(), tag.end());
    return true;
}

bool aes_gcm_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& aad,
                     const std::vector<uint8_t>& iv_ct_tag, std::vector<uint8_t>& plain) {
    if (iv_ct_tag.size() < kAesGcmIv + kAesGcmTag) return false;
    const uint8_t* iv = iv_ct_tag.data();
    const uint8_t* ct = iv_ct_tag.data() + kAesGcmIv;
    int ct_len = static_cast<int>(iv_ct_tag.size() - kAesGcmIv - kAesGcmTag);
    const uint8_t* tag = iv_ct_tag.data() + iv_ct_tag.size() - kAesGcmTag;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = true;
    int out_len = 0, total = 0;
    plain.assign(static_cast<size_t>(ct_len), 0);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) ok = false;
    if (ok && !aad.empty() &&
        EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1)
        ok = false;
    if (ok && ct_len > 0 && EVP_DecryptUpdate(ctx, plain.data(), &out_len, ct, ct_len) != 1)
        ok = false;
    total = out_len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kAesGcmTag,
                                  const_cast<uint8_t*>(tag)) != 1)
        ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, plain.data() + total, &out_len) != 1) ok = false;
    total += out_len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        zero(plain);
        return false;
    }
    plain.resize(static_cast<size_t>(total));
    return true;
}

size_t algorithm_key_size(const std::string& alg) {
    if (alg == kDefaultKeyAlgorithm) return 32;
    if (alg == "AES-256-GCM") return 32;
    if (alg == "AES-128-GCM") return 16;
    return 0;
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

// ============================================================
// Impl
// ============================================================

class SoftFileBusinessKeyProvider::Impl {
public:
    struct Slot {
        bool present = false;
        uint64_t version = 0;
        std::string key_id_digest;
        std::string algorithm;
        int64_t valid_from_ms = 0;
        int64_t valid_to_ms = 0;
        uint64_t generation = 0;
        std::string key_enc_hex;
    };

    struct JournalStored {
        BusinessKeyJournalEntry entry;
        std::string mac_hex;
    };

    HsmInterface* hsm = nullptr;
    BusinessKeyProviderConfig cfg;
    BusinessKeyDeviceBindingProvider binding_provider;
    std::unique_ptr<hwyz::store::Store> store;
    std::vector<uint8_t> kek;
    std::vector<uint8_t> mac_key;

    uint64_t generation = 0;
    std::string commit_marker;
    std::map<std::string, Slot> active;
    std::map<std::string, Slot> staging;
    uint64_t staging_generation = 0;
    std::map<std::string, JournalStored> journal;

    mutable std::mutex mtx;
    bool ready = false;

    std::string slot_aad(const std::string& domain, const std::string& purpose,
                         const Slot& s) const {
        return "openiov|slot|" + domain + "|" + purpose + "|" + std::to_string(s.version) + "|" +
               std::to_string(s.generation);
    }

    std::string compute_commit_marker() const {
        std::string canon = "commit|" + std::to_string(generation);
        std::vector<std::string> purposes;
        for (auto& [p, s] : active) purposes.push_back(p);
        std::sort(purposes.begin(), purposes.end());
        for (auto& p : purposes) {
            const Slot& s = active.at(p);
            canon += "|" + p + ":" + std::to_string(s.version) + ":" + s.key_id_digest + ":" +
                     s.algorithm + ":" + std::to_string(s.generation);
        }
        std::vector<uint8_t> msg(canon.begin(), canon.end());
        return to_hex(hmac_sha256(mac_key, msg));
    }

    json slot_to_json(const Slot& s) const {
        json j;
        j["present"] = s.present;
        j["version"] = s.version;
        j["key_id_digest"] = s.key_id_digest;
        j["algorithm"] = s.algorithm;
        j["valid_from_ms"] = s.valid_from_ms;
        j["valid_to_ms"] = s.valid_to_ms;
        j["generation"] = s.generation;
        j["key_enc"] = s.key_enc_hex;
        return j;
    }

    Slot slot_from_json(const json& j) const {
        Slot s;
        s.present = j.value("present", false);
        s.version = j.value("version", 0ULL);
        s.key_id_digest = j.value("key_id_digest", "");
        s.algorithm = j.value("algorithm", "");
        s.valid_from_ms = j.value("valid_from_ms", 0LL);
        s.valid_to_ms = j.value("valid_to_ms", 0LL);
        s.generation = j.value("generation", 0ULL);
        s.key_enc_hex = j.value("key_enc", "");
        return s;
    }

    json journal_entry_json(const BusinessKeyJournalEntry& e) const {
        json j;
        j["request_id_digest"] = e.request_id_digest;
        j["request_digest"] = e.request_digest;
        j["phase"] = business_key_import_phase_to_string(e.phase);
        j["generation"] = e.generation;
        j["created_at_ms"] = e.created_at_ms;
        j["committed_at_ms"] = e.committed_at_ms;
        j["provider_version_digest"] = e.provider_version_digest;
        j["last_error"] = e.last_error;
        j["proof_algorithm"] = e.proof_algorithm;
        j["import_proof"] = to_hex(e.import_proof);
        j["binding_certificate_digest"] = to_hex(e.binding_certificate_digest);
        json items = json::array();
        for (auto& it : e.items) {
            json si;
            si["business_domain"] = it.business_domain;
            si["purpose"] = it.purpose;
            si["business_key_version"] = it.business_key_version;
            si["state"] = business_key_state_to_string(it.state);
            // CR-012 Q3：journal 保存完整 key_id 与逐 item 证书摘要（OperationalMetadata，非秘密）
            si["key_id"] = it.key_id;
            si["key_id_digest"] = it.key_id_digest;
            si["algorithm"] = it.algorithm;
            si["valid_from_ms"] = it.valid_from_ms;
            si["valid_to_ms"] = it.valid_to_ms;
            si["envelope_format"] = key_envelope_format_to_string(it.envelope_format);
            si["envelope_digest"] = to_hex(it.envelope_digest);
            si["key_check_value"] = to_hex(it.key_check_value.data(), it.key_check_value.size());
            si["key_check_value_present"] = it.key_check_value_present;
            si["import_proof"] = to_hex(it.import_proof);
            si["proof_algorithm"] = it.proof_algorithm;
            si["recipient_certificate_digest"] = to_hex(it.recipient_certificate_digest);
            items.push_back(si);
        }
        j["items"] = items;
        return j;
    }

    BusinessKeyJournalEntry journal_entry_from_json(const json& j) const {
        BusinessKeyJournalEntry e;
        e.request_id_digest = j.value("request_id_digest", "");
        e.request_digest = j.value("request_digest", "");
        e.phase = string_to_business_key_import_phase(j.value("phase", "UNKNOWN"));
        e.generation = j.value("generation", 0ULL);
        e.created_at_ms = j.value("created_at_ms", 0LL);
        e.committed_at_ms = j.value("committed_at_ms", 0LL);
        e.provider_version_digest = j.value("provider_version_digest", "");
        e.last_error = j.value("last_error", "");
        e.proof_algorithm = j.value("proof_algorithm", "");
        from_hex(j.value("import_proof", ""), e.import_proof);
        from_hex(j.value("binding_certificate_digest", ""), e.binding_certificate_digest);
        if (j.contains("items") && j["items"].is_array()) {
            for (auto& si : j["items"]) {
                BusinessKeyStatus s;
                s.business_domain = si.value("business_domain", "");
                s.purpose = si.value("purpose", "");
                s.business_key_version = si.value("business_key_version", 0ULL);
                s.state = string_to_business_key_state(si.value("state", "UNKNOWN"));
                s.key_id = si.value("key_id", "");
                s.key_id_digest = si.value("key_id_digest", "");
                s.algorithm = si.value("algorithm", "");
                s.valid_from_ms = si.value("valid_from_ms", 0LL);
                s.valid_to_ms = si.value("valid_to_ms", 0LL);
                s.envelope_format =
                    string_to_key_envelope_format(si.value("envelope_format", "UNSPECIFIED"));
                from_hex(si.value("envelope_digest", ""), s.envelope_digest);
                std::vector<uint8_t> kcv;
                if (from_hex(si.value("key_check_value", ""), kcv) && kcv.size() == 3) {
                    s.key_check_value = {kcv[0], kcv[1], kcv[2]};
                }
                s.key_check_value_present = si.value("key_check_value_present", false);
                from_hex(si.value("import_proof", ""), s.import_proof);
                s.proof_algorithm = si.value("proof_algorithm", "");
                from_hex(si.value("recipient_certificate_digest", ""),
                         s.recipient_certificate_digest);
                e.items.push_back(std::move(s));
            }
        }
        return e;
    }

    std::string journal_mac(const BusinessKeyJournalEntry& e) const {
        std::string canon = journal_entry_json(e).dump();
        std::vector<uint8_t> msg(canon.begin(), canon.end());
        return to_hex(hmac_sha256(mac_key, msg));
    }

    ErrorCode load_state() {
        if (!store || !store->isReady()) return ErrorCode::BUSINESS_KEY_NOT_READY;
        if (!store->has("state")) return ErrorCode::SUCCESS;
        try {
            auto state = json::parse(store->load<std::string>("state"));
            generation = state.value("generation", 0ULL);
            commit_marker = state.value("commit_marker", "");
            staging_generation = state.value("staging_generation", 0ULL);
            active.clear();
            staging.clear();
            journal.clear();
            if (state.contains("active")) {
                for (auto& [p, v] : state["active"].items()) active[p] = slot_from_json(v);
            }
            if (state.contains("staging")) {
                for (auto& [p, v] : state["staging"].items()) staging[p] = slot_from_json(v);
            }
            if (state.contains("journal")) {
                for (auto& [rid, v] : state["journal"].items()) {
                    JournalStored js;
                    js.entry = journal_entry_from_json(v.value("entry", json::object()));
                    js.mac_hex = v.value("mac", "");
                    journal[rid] = std::move(js);
                }
            }
            return ErrorCode::SUCCESS;
        } catch (const std::exception&) {
            return ErrorCode::STORAGE_CORRUPTION;
        }
    }

    ErrorCode save_state() {
        if (!store || !store->isReady()) return ErrorCode::BUSINESS_KEY_NOT_READY;
        try {
            json state;
            state["v"] = 1;
            state["generation"] = generation;
            state["commit_marker"] = commit_marker;
            state["staging_generation"] = staging_generation;
            json act = json::object();
            for (auto& [p, s] : active) act[p] = slot_to_json(s);
            state["active"] = act;
            json stg = json::object();
            for (auto& [p, s] : staging) stg[p] = slot_to_json(s);
            state["staging"] = stg;
            json jr = json::object();
            for (auto& [rid, js] : journal) {
                json v;
                v["entry"] = journal_entry_json(js.entry);
                v["mac"] = js.mac_hex;
                jr[rid] = v;
            }
            state["journal"] = jr;
            store->save("state", state.dump());
            return ErrorCode::SUCCESS;
        } catch (const std::exception&) {
            return ErrorCode::STORAGE_WRITE_FAILED;
        }
    }

    ErrorCode generate_kek() {
        kek.resize(kKekSize);
        if (RAND_bytes(kek.data(), kKekSize) != 1) return ErrorCode::INTERNAL_ERROR;
        fs::path p(cfg.kek_path);
        if (p.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(p.parent_path(), ec);
        }
        std::ofstream ofs(cfg.kek_path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return ErrorCode::STORAGE_WRITE_FAILED;
        ofs.write(reinterpret_cast<const char*>(kek.data()), kKekSize);
        ofs.close();
        fs::permissions(cfg.kek_path, fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace);
        return ErrorCode::SUCCESS;
    }

    ErrorCode load_kek() {
        std::ifstream ifs(cfg.kek_path, std::ios::binary);
        if (!ifs.is_open()) return ErrorCode::STORAGE_READ_FAILED;
        kek.resize(kKekSize);
        ifs.read(reinterpret_cast<char*>(kek.data()), kKekSize);
        if (ifs.gcount() != kKekSize) {
            zero(kek);
            return ErrorCode::STORAGE_CORRUPTION;
        }
        return ErrorCode::SUCCESS;
    }

    void derive_mac_key() {
        std::string info = "openiov|keyprov|mac|v1";
        mac_key.resize(SHA256_DIGEST_LENGTH);
        hkdf_sha256(kek, {}, std::vector<uint8_t>(info.begin(), info.end()), mac_key.data(),
                    mac_key.size());
    }

    ErrorCode encrypt_slot_key(const std::string& domain, const std::string& purpose,
                               const Slot& s, const std::vector<uint8_t>& plain,
                               std::string& out_hex) {
        std::string aad = slot_aad(domain, purpose, s);
        std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
        std::vector<uint8_t> enc;
        if (!aes_gcm_encrypt(kek, aad_bytes, plain, enc)) return ErrorCode::INTERNAL_ERROR;
        out_hex = to_hex(enc);
        return ErrorCode::SUCCESS;
    }

    ErrorCode decrypt_slot_key(const std::string& domain, const std::string& purpose,
                               const Slot& s, std::vector<uint8_t>& plain) {
        std::vector<uint8_t> enc;
        if (!from_hex(s.key_enc_hex, enc)) return ErrorCode::STORAGE_CORRUPTION;
        std::string aad = slot_aad(domain, purpose, s);
        std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
        if (!aes_gcm_decrypt(kek, aad_bytes, enc, plain)) {
            zero(enc);
            return ErrorCode::WRAPPED_KEY_INVALID;
        }
        zero(enc);
        return ErrorCode::SUCCESS;
    }

    std::vector<std::string> required_purposes() const {
        return {kBusinessPurposeUplinkAead, kBusinessPurposeDownlinkAead};
    }
};

// ============================================================
// Construction / lifecycle
// ============================================================

SoftFileBusinessKeyProvider::SoftFileBusinessKeyProvider(
    HsmInterface* hsm, BusinessKeyProviderConfig config,
    BusinessKeyDeviceBindingProvider binding_provider)
    : impl_(std::make_unique<Impl>()) {
    impl_->hsm = hsm;
    impl_->cfg = std::move(config);
    impl_->binding_provider = std::move(binding_provider);
    if (impl_->cfg.kek_path.empty()) {
        impl_->cfg.kek_path = impl_->cfg.store_root + "/.business_key_kek";
    }
}

SoftFileBusinessKeyProvider::~SoftFileBusinessKeyProvider() {
    if (impl_) {
        zero(impl_->kek);
        zero(impl_->mac_key);
    }
}

ErrorCode SoftFileBusinessKeyProvider::initialize() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    try {
        impl_->store = std::make_unique<hwyz::store::Store>(
            hwyz::store::Store::open("sec_business_keys", impl_->cfg.store_root));
    } catch (const std::exception&) {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    if (!impl_->store->isReady()) return ErrorCode::BUSINESS_KEY_NOT_READY;

    ErrorCode rc = fs::exists(impl_->cfg.kek_path) ? impl_->load_kek() : impl_->generate_kek();
    if (rc != ErrorCode::SUCCESS) return rc;
    impl_->derive_mac_key();

    rc = impl_->load_state();
    if (rc != ErrorCode::SUCCESS) return rc;

    if (!impl_->active.empty()) {
        std::string expected = impl_->compute_commit_marker();
        if (impl_->commit_marker != expected) {
            SecLogAdapter::business_key().error(
                "sec.business_key.state_integrity_failed",
                "业务密钥 state commit marker 校验失败，标记 INVALID");
            impl_->active.clear();
        }
    }

    impl_->ready = (impl_->hsm != nullptr);
    return ErrorCode::SUCCESS;
}

bool SoftFileBusinessKeyProvider::isReady() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->ready;
}

std::string SoftFileBusinessKeyProvider::providerVersionDigest() const {
    return impl_->cfg.provider_version;
}

BusinessKeyProviderCapability SoftFileBusinessKeyProvider::capability() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    BusinessKeyProviderCapability cap;
    const bool h = impl_->hsm != nullptr;
    cap.p256_ecdh = h;
    cap.hkdf_sha256 = h;
    cap.aes256_gcm_decrypt_to_slot = h;
    cap.atomic_dual_slot_commit = true;
    cap.secure_journal_ready = impl_->ready && impl_->store && impl_->store->isReady();
    cap.ecdsa_p256_sha256_p1363 = h;
    return cap;
}

// ============================================================
// Unwrap / staging / commit
// ============================================================

ErrorCode SoftFileBusinessKeyProvider::unwrapToStaging(
    const std::string& domain, const WrappedKeyItem& item,
    const EcdhEsP256EnvelopeParameters& params, const std::vector<uint8_t>& canonical_aad,
    const std::vector<uint8_t>& hkdf_info, const BusinessKeyDeviceBinding& binding,
    uint64_t generation, std::array<uint8_t, 3>& actual_kcv) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    actual_kcv = {};
    if (!impl_->ready || !impl_->hsm) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!binding.ready || binding.device_key_id.empty()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (item.wrapped_key.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
    if (static_cast<int64_t>(item.wrapped_key.size()) > impl_->cfg.max_wrapped_key_bytes)
        return ErrorCode::WRAPPED_KEY_INVALID;
    if (!contains(impl_->cfg.allowed_algorithms, item.algorithm))
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    if (!contains(impl_->cfg.allowed_wrapping_suites, item.wrapping_suite))
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    if (item.wrapping_suite != kWrappingSuiteEcdhEsP256)
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    size_t key_size = algorithm_key_size(item.algorithm);
    if (key_size == 0) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

    std::vector<uint8_t> ciphertext(item.wrapped_key.data(),
                                    item.wrapped_key.data() + item.wrapped_key.size());
    std::vector<uint8_t> plain;
    ErrorCode rc = impl_->hsm->unwrap_ecdh_es_v1(
        binding.device_key_id, params.server_ephemeral_public_key, params.hkdf_salt, hkdf_info,
        params.nonce, ciphertext, params.authentication_tag, canonical_aad, plain);
    zero(ciphertext);
    if (rc != ErrorCode::SUCCESS) {
        zero(plain);
        return rc == ErrorCode::NOT_IMPLEMENTED ? ErrorCode::BUSINESS_KEY_NOT_READY
                                                : ErrorCode::WRAPPED_KEY_INVALID;
    }
    if (plain.size() != key_size) {
        zero(plain);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }

    // KCV 校验（常量时间）；不一致即拒绝，不落 staging。
    std::array<uint8_t, 3> kcv = canonical::computeKcv(plain);
    if (item.key_check_value_present) {
        if (!canonical::constantTimeEqual(kcv.data(), item.key_check_value.data(), 3)) {
            zero(plain);
            return ErrorCode::WRAPPED_KEY_INVALID;
        }
    }
    actual_kcv = kcv;

    Impl::Slot s;
    s.present = true;
    s.version = item.business_key_version;
    std::vector<uint8_t> kid(item.key_id.begin(), item.key_id.end());
    s.key_id_digest = canonical::toHex(canonical::sha256(kid));
    s.algorithm = item.algorithm;
    s.valid_from_ms = item.valid_from_ms;
    s.valid_to_ms = item.valid_to_ms;
    s.generation = generation;
    rc = impl_->encrypt_slot_key(domain, item.purpose, s, plain, s.key_enc_hex);
    zero(plain);
    if (rc != ErrorCode::SUCCESS) return rc;

    impl_->staging[item.purpose] = std::move(s);
    impl_->staging_generation = generation;
    return impl_->save_state();
}

ErrorCode SoftFileBusinessKeyProvider::verifyStaging(const std::string& domain,
                                                     const std::string& purpose) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
    auto it = impl_->staging.find(purpose);
    if (it == impl_->staging.end() || !it->second.present) return ErrorCode::WRAPPED_KEY_INVALID;
    const auto& s = it->second;
    size_t key_size = algorithm_key_size(s.algorithm);
    if (key_size == 0) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    std::vector<uint8_t> plain;
    ErrorCode rc = impl_->decrypt_slot_key(domain, purpose, s, plain);
    if (rc != ErrorCode::SUCCESS) return rc;
    bool ok = plain.size() == key_size;
    zero(plain);
    return ok ? ErrorCode::SUCCESS : ErrorCode::WRAPPED_KEY_INVALID;
}

ErrorCode SoftFileBusinessKeyProvider::commitBatch(const std::string& domain,
                                                   uint64_t generation) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;

    for (const auto& p : impl_->required_purposes()) {
        auto it = impl_->staging.find(p);
        if (it == impl_->staging.end() || !it->second.present ||
            it->second.generation != generation) {
            return ErrorCode::BUSINESS_KEY_PARTIAL_ROLLBACK;
        }
    }
    if (impl_->staging_generation != generation) {
        return ErrorCode::BUSINESS_KEY_CONFLICT;
    }

    std::map<std::string, Impl::Slot> new_active = impl_->active;
    for (const auto& p : impl_->required_purposes()) {
        new_active[p] = impl_->staging.at(p);
        new_active[p].generation = generation;
    }
    auto old_active = impl_->active;
    auto old_gen = impl_->generation;
    auto old_marker = impl_->commit_marker;

    impl_->active = std::move(new_active);
    impl_->generation = generation;
    impl_->commit_marker = impl_->compute_commit_marker();
    impl_->staging.clear();
    impl_->staging_generation = 0;

    ErrorCode rc = impl_->save_state();
    if (rc != ErrorCode::SUCCESS) {
        impl_->active = std::move(old_active);
        impl_->generation = old_gen;
        impl_->commit_marker = old_marker;
        return rc;
    }
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileBusinessKeyProvider::rollbackStaging(const std::string& domain,
                                                       uint64_t generation) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (impl_->staging_generation != 0 && impl_->staging_generation != generation)
        return ErrorCode::BUSINESS_KEY_CONFLICT;
    impl_->staging.clear();
    impl_->staging_generation = 0;
    return impl_->save_state();
}

// ============================================================
// Query / proof
// ============================================================

ErrorCode SoftFileBusinessKeyProvider::querySlot(const std::string& domain,
                                                 const std::string& purpose,
                                                 BusinessKeySlotInfo& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out = BusinessKeySlotInfo{};
    if (!impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
    auto it = impl_->active.find(purpose);
    if (it == impl_->active.end() || !it->second.present) {
        out.state = BusinessKeyState::MISSING;
        return ErrorCode::SUCCESS;
    }
    const auto& s = it->second;
    out.present = true;
    out.business_key_version = s.version;
    out.key_id_digest = s.key_id_digest;
    out.algorithm = s.algorithm;
    out.valid_from_ms = s.valid_from_ms;
    out.valid_to_ms = s.valid_to_ms;
    out.active_generation = s.generation;
    std::vector<uint8_t> plain;
    ErrorCode rc = impl_->decrypt_slot_key(domain, purpose, s, plain);
    zero(plain);
    out.state = (rc == ErrorCode::SUCCESS) ? BusinessKeyState::ACTIVE : BusinessKeyState::INVALID;
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileBusinessKeyProvider::generateProof(
    const std::string& domain, const std::string& purpose, uint64_t business_key_version,
    const std::string& request_id, const std::string& key_id,
    const std::vector<uint8_t>& envelope_digest, const std::vector<uint8_t>& key_check_value,
    std::vector<uint8_t>& proof, std::string& algorithm) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    proof.clear();
    if (!impl_->ready || !impl_->hsm) return ErrorCode::BUSINESS_KEY_NOT_READY;
    auto it = impl_->active.find(purpose);
    if (it == impl_->active.end() || !it->second.present)
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    const auto& s = it->second;
    if (s.version != business_key_version) return ErrorCode::BUSINESS_KEY_CONFLICT;

    uint64_t purpose_val = 0;
    if (!purposeEnumValue(purpose, purpose_val)) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

    // 签名身份：本次 provisioning 绑定的 ACTIVE 设备证书对应不可导出私钥。
    BusinessKeyDeviceBinding binding =
        impl_->binding_provider ? impl_->binding_provider() : BusinessKeyDeviceBinding{};
    if (!binding.ready || binding.device_key_id.empty()) return ErrorCode::BUSINESS_KEY_NOT_READY;

    canonical::ProofInput pi;
    pi.request_id = request_id;
    pi.business_domain = domain;
    pi.purpose = purpose_val;
    pi.key_id = key_id;
    pi.business_key_version = business_key_version;
    pi.envelope_digest = envelope_digest;
    pi.key_check_value = key_check_value;
    std::vector<uint8_t> proof_input = canonical::buildProofInput(pi);

    // ECDSA_P256_SHA256_P1363：对 SHA-256(proofInput) 用设备身份私钥签名。
    std::vector<uint8_t> digest = canonical::sha256(proof_input);
    ErrorCode rc = impl_->hsm->sign_digest_p1363(binding.device_key_id, digest, proof);
    OPENSSL_cleanse(proof_input.data(), proof_input.size());
    OPENSSL_cleanse(digest.data(), digest.size());
    binding.clearPublicKey();
    if (rc != ErrorCode::SUCCESS) {
        proof.clear();
        return rc == ErrorCode::NOT_IMPLEMENTED ? ErrorCode::BUSINESS_KEY_NOT_READY : rc;
    }
    if (proof.size() != kImportProofSizeP1363) {
        proof.clear();
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    algorithm = kImportProofAlgorithmP1363;
    return ErrorCode::SUCCESS;
}

// ============================================================
// Journal
// ============================================================

bool SoftFileBusinessKeyProvider::loadJournal(const std::string& request_id_digest,
                                              BusinessKeyJournalEntry& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->journal.find(request_id_digest);
    if (it == impl_->journal.end()) return false;
    if (it->second.mac_hex != impl_->journal_mac(it->second.entry)) {
        SecLogAdapter::business_key().error(
            "sec.business_key.journal_tamper", "导入 journal 条目 MAC 校验失败，按 UNKNOWN 处理");
        out = BusinessKeyJournalEntry{};
        out.request_id_digest = request_id_digest;
        out.phase = BusinessKeyImportPhase::UNKNOWN;
        return true;
    }
    out = it->second.entry;
    return true;
}

ErrorCode SoftFileBusinessKeyProvider::saveJournal(const BusinessKeyJournalEntry& entry) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
    Impl::JournalStored js;
    js.entry = entry;
    js.mac_hex = impl_->journal_mac(entry);
    impl_->journal[entry.request_id_digest] = std::move(js);
    return impl_->save_state();
}

std::vector<BusinessKeyJournalEntry> SoftFileBusinessKeyProvider::listJournal() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<BusinessKeyJournalEntry> out;
    for (auto& [rid, js] : impl_->journal) {
        if (js.mac_hex == impl_->journal_mac(js.entry)) {
            out.push_back(js.entry);
        } else {
            BusinessKeyJournalEntry e;
            e.request_id_digest = rid;
            e.phase = BusinessKeyImportPhase::UNKNOWN;
            out.push_back(e);
        }
    }
    return out;
}

bool SoftFileBusinessKeyProvider::hasPendingStaging() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return !impl_->staging.empty();
}

} // namespace sec
} // namespace tbox

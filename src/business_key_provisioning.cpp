//
// V2C 业务密钥开通服务实现（TBOX-SEC-DSN-CR-019；CR-020 §5/§8/§9/§11）。
//
#include "business_key_provisioning.h"

#include "business_key_envelope.h"
#include "canonical_encoding.h"
#include "sec_log_adapter.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <set>

namespace tbox {
namespace sec {

namespace {

/// KL1 daemon/SDK 构建标识（可观测；非敏感；与发布单元匹配）。
constexpr const char* kKeyprovDaemonBuildId = "sec-kl1-v1";
constexpr const char* kKeyprovSdkBuildId = "sec-client-kl1-v1";

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

std::string rid_digest_of(const std::string& request_id) {
    return canonical::toHex(canonical::sha256(request_id));
}

/// §9：公开的粗粒度状态（IPC 结果）由 journal 权威 phase 派生。
BusinessKeyImportState import_state_from_phase(BusinessKeyImportPhase p) {
    switch (p) {
        case BusinessKeyImportPhase::NEW:
        case BusinessKeyImportPhase::VALIDATED:
        case BusinessKeyImportPhase::PROCESSING:
            return BusinessKeyImportState::REQUESTED;
        case BusinessKeyImportPhase::UPLINK_STAGED:
        case BusinessKeyImportPhase::BOTH_STAGED:
        case BusinessKeyImportPhase::COMMITTING:
            return BusinessKeyImportState::STAGED;
        case BusinessKeyImportPhase::SUCCEEDED:
            return BusinessKeyImportState::COMMITTED;
        case BusinessKeyImportPhase::ROLLING_BACK:
        case BusinessKeyImportPhase::FAILED:
            return BusinessKeyImportState::FAILED;
        case BusinessKeyImportPhase::OUTCOME_UNKNOWN:
        case BusinessKeyImportPhase::RECOVERING:
        case BusinessKeyImportPhase::UNKNOWN:
        default:
            return BusinessKeyImportState::UNKNOWN;
    }
}

/// 安全调用结果未知（需对账）判定：仅模糊 IO/内部错误。
bool is_outcome_unknown(ErrorCode rc) {
    return rc == ErrorCode::INTERNAL_ERROR || rc == ErrorCode::STORAGE_WRITE_FAILED ||
           rc == ErrorCode::NOT_INITIALIZED;
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
            "sec.business_key.import", "业务密钥批次导入处理完成",
            {tbox::fw::log::Field("request_id_digest",
                 tbox::fw::log::FieldValue::makeString(rid_digest)),
             tbox::fw::log::Field("state",
                 tbox::fw::log::FieldValue::makeString(
                     business_key_import_state_to_string(out.state))),
             tbox::fw::log::Field("duration_ms",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(ms)))});
    }
};

/// KL1 capability_epoch 源：绑定 daemon boot nonce 与存储恢复世代。
/// 重启（新实例）→ 新 boot nonce → 新 epoch；恢复/存储更换 → 世代递增 → 新 epoch。
class KeyprovEpochSource {
public:
    KeyprovEpochSource() {
        uint32_t n = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&n), sizeof(n)) != 1) {
            n = static_cast<uint32_t>(
                std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFFu);
        }
        boot_nonce_ = n;
    }
    uint64_t epoch() const {
        std::vector<uint8_t> buf;
        canonical::appendUint32be(buf, boot_nonce_);
        canonical::appendUint64be(buf, generation_);
        std::vector<uint8_t> h = canonical::sha256(buf);
        uint64_t e = 0;
        for (size_t i = 0; i < 8; ++i) e = (e << 8) | h[i];
        return e;
    }
    uint64_t generation() const { return generation_; }
    void bumpRecovery() { ++generation_; }
    void bumpStorageReplacement() {
        ++generation_;
        governance_ = true;
    }
    bool governance() const { return governance_; }

private:
    uint32_t boot_nonce_ = 0;
    uint64_t generation_ = 1;
    bool governance_ = false;
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
    bool provider_ready = false;   ///< 可供状态查询（enabled && provider/journal 可用）
    bool import_ready = false;     ///< 接受新信封（能力合取 + 存储健康 + 非治理）
    V2cKeyProvisioningCapability cap;

    // ---- KL1（TBOX-SEC-DSN-CR-023）----
    KeyprovEpochSource epoch_src;
    bool storage_ready_ = false;       ///< journal/ledger 存储健康可读且非治理
    bool governance_required_ = false; ///< 存储被清空/更换，旧世代副作用无法排除 → UNKNOWN/治理

    ErrorCode trusted_now_ms(int64_t& out) {
        if (!trusted_time) return ErrorCode::BUSINESS_KEY_NOT_READY;
        TrustedTimeSample s = trusted_time->now();
        if (s.trust_state != TimeTrustState::Trusted) return ErrorCode::BUSINESS_KEY_NOT_READY;
        out = std::chrono::duration_cast<std::chrono::milliseconds>(s.utc_now.time_since_epoch())
                  .count();
        return ErrorCode::SUCCESS;
    }

    /// KL1 可信时间门禁（TBOX-SEC-DSN-CR-023 §12.11.6 / LC21）：
    /// TRUSTED 且 uncertainty≤1000ms、freshness≤300000ms、无回拨（Composite 已判定）。
    /// 返回 U = utc_ms + uncertainty_ms；仅 U<E 可新启动，U==E 必拒绝。
    ErrorCode kl1_trusted_upper_now(int64_t& out_u) {
        if (!trusted_time) return ErrorCode::BUSINESS_KEY_NOT_READY;
        TrustedTimeSample s = trusted_time->now();
        if (s.trust_state != TimeTrustState::Trusted) return ErrorCode::BUSINESS_KEY_NOT_READY;
        const auto unc = std::chrono::duration_cast<std::chrono::milliseconds>(s.uncertainty);
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(s.freshness_age);
        if (unc.count() > 1000) return ErrorCode::BUSINESS_KEY_NOT_READY;   // LC21.uncertainty
        if (age.count() > 300000) return ErrorCode::BUSINESS_KEY_NOT_READY;  // LC21.stale
        const auto utc =
            std::chrono::duration_cast<std::chrono::milliseconds>(s.utc_now.time_since_epoch())
                .count();
        out_u = utc + unc.count();
        return ErrorCode::SUCCESS;
    }

    BusinessKeyDeviceBinding probe_binding() {
        if (!binding_provider) return BusinessKeyDeviceBinding{};
        return binding_provider();
    }

    bool binding_agreement_ok(const BusinessKeyDeviceBinding& b) const {
        return b.ready && !b.device_key_id.empty() && b.active_cert_p256 &&
               b.active_cert_key_agreement && b.active_cert_digital_signature &&
               b.private_key_can_derive && b.private_key_can_sign &&
               !b.active_cert_digest.empty() &&
               // CR-020 §2.1/§11 修订：逻辑 Profile 合取 + 原始 leaf DER 绑定 + 链/密钥匹配
               b.active_cert_ca_false && b.active_cert_eku_client_auth_only &&
               b.active_cert_critical_extensions_allowed &&
               b.active_cert_leaf_digest_bound && b.active_cert_chain_key_match &&
               b.identity_template_sign_derive;
    }

    /// KL1 契约快照（TBOX-SEC-DSN-CR-023 §12.11.1）。
    /// 与 capability()/查询同一锁内读取，保证同 epoch 一致；
    /// epoch 绑定 daemon 与存储恢复世代；重启/恢复/存储更换即更换。
    KeyprovContractSnapshot compute_snapshot() {
        KeyprovContractSnapshot s;
        s.result_contract_version = V2cKeyProvisioningCapability::kContractVersion;
        s.query_semantics_version = 1;
        s.capability_epoch = epoch_src.epoch();
        s.storage_ready = storage_ready_;
        s.supports_atomic_dual_commit = cap.atomic_dual_purpose_commit_ready;
        // KL1 要求完整快照握手就绪（导入能力合取 + 存储健康 + 非治理）；
        // 缺 KL1 admission 能力时新 TSP 阻断，不走旧接口降级导入。
        s.supports_lease_admission = import_ready && epoch_src.epoch() != 0;
        s.kl1_profile_version = s.supports_lease_admission ? kKeyprovKl1ProfileVersion : 0;
        s.daemon_build_id = kKeyprovDaemonBuildId;
        s.sdk_build_id = kKeyprovSdkBuildId;
        return s;
    }

    V2cKeyProvisioningCapability compute_capability() {
        V2cKeyProvisioningCapability c;
        BusinessKeyProviderCapability pc = provider ? provider->capability()
                                                    : BusinessKeyProviderCapability{};
        // 构建期锁版（VEH-PROTO 2026-10-25 修订；本地 proto source hash /
        // DescriptorSet hash / protoc 35.1 / C++ 生成物 / fixture manifest hash
        // 由 test_keyprov_proto_lock.cpp 断言；构建期不一致即构建失败，fail-closed）。
        c.proto_release_matched = true;
        c.envelope_format_v1 = true;
        c.p256_ecdh = pc.p256_ecdh;
        c.hkdf_sha256 = pc.hkdf_sha256;
        c.aes256_gcm_decrypt_to_slot = pc.aes256_gcm_decrypt_to_slot;
        c.atomic_dual_slot_commit = pc.atomic_dual_slot_commit;
        c.ecdsa_p256_sha256_p1363 = pc.ecdsa_p256_sha256_p1363;
        c.secure_journal_ready = pc.secure_journal_ready;
        // TBOX-SEC-DSN-CR-021：NOT_FOUND 结果查询能力（仅可观测/灰度，不进 all()）
        c.business_key_import_result_not_found_v1 = true;
        // TBOX-TSP-DSN-CR-012 §8：显式门禁别名（语义与详细能力一致）
        c.envelope_v1_import_ready = c.envelope_format_v1;
        c.atomic_dual_purpose_commit_ready = c.atomic_dual_slot_commit;
        c.import_proof_sign_ecdsa_p256_v1_ready = c.ecdsa_p256_sha256_p1363;
        c.secure_journal_replay_ready = c.secure_journal_ready;
        BusinessKeyDeviceBinding b = probe_binding();
        // CR-020 §2.1/§11 修订：证书生产闭环 / 逻辑 Profile 门禁
        c.csr_key_usage_request_matched = true;  // CSR Builder 固定请求双 KU（test_csr_builder 断言 DER）
        c.identity_key_template_sign_derive = b.ready && b.identity_template_sign_derive;
        c.certificate_profile_matched =
            b.ready && b.active_cert_p256 && b.active_cert_key_agreement &&
            b.active_cert_digital_signature && b.active_cert_ca_false &&
            b.active_cert_eku_client_auth_only &&
            b.active_cert_critical_extensions_allowed;
        c.certificate_chain_and_key_match = b.ready && b.active_cert_chain_key_match;
        c.certificate_critical_extensions_allowed =
            b.ready && b.active_cert_critical_extensions_allowed;
        c.leaf_certificate_digest_bound = b.ready && b.active_cert_leaf_digest_bound;
        c.active_certificate_key_agreement =
            b.ready && b.active_cert_p256 && b.active_cert_key_agreement;
        c.active_certificate_digital_signature =
            b.ready && b.active_cert_p256 && b.active_cert_digital_signature;
        c.active_private_key_can_derive = b.ready && b.private_key_can_derive;
        c.active_private_key_can_sign = b.ready && b.private_key_can_sign;
        int64_t now = 0;
        c.trusted_time_ready = trusted_now_ms(now) == ErrorCode::SUCCESS;
        b.clearPublicKey();
        return c;
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

    ErrorCode validate_structure(const std::string& request_id, const std::string& domain,
                                 const std::vector<WrappedKeyItem>& items) {
        if (request_id.empty()) return ErrorCode::INVALID_PARAMETER;
        if (request_id.size() > 128) return ErrorCode::INVALID_PARAMETER;
        if (!contains(cfg.allowed_domains, domain)) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
        if (static_cast<int>(items.size()) != cfg.max_items)
            return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
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
            if (!contains(cfg.allowed_wrapping_suites, item.wrapping_suite))
                return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
            if (item.envelope_format != KeyEnvelopeFormat::ECDH_ES_P256_V1 ||
                !contains(cfg.allowed_envelope_formats,
                          key_envelope_format_to_string(item.envelope_format)))
                return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
            if (item.business_key_version == 0 ||
                item.business_key_version > ((1ULL << 63) - 1))
                return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.valid_from_ms <= 0 || item.valid_to_ms <= item.valid_from_ms)
                return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.wrapped_key.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
            if (static_cast<int64_t>(item.wrapped_key.size()) > cfg.max_wrapped_key_bytes)
                return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.parameters.empty()) return ErrorCode::WRAPPED_KEY_INVALID;
            if (static_cast<int64_t>(item.parameters.size()) > cfg.max_parameters_bytes)
                return ErrorCode::WRAPPED_KEY_INVALID;
            if (item.envelope_digest.size() != 32) return ErrorCode::WRAPPED_KEY_INVALID;
            if (!item.key_check_value_present) return ErrorCode::WRAPPED_KEY_INVALID;
        }
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

    /// §9 canonical requestDigest：覆盖域/元数据/Wrapped Key 摘要/信封与算法参数。
    std::string build_request_digest(const std::string& request_id, const std::string& domain,
                                     const std::vector<WrappedKeyItem>& items,
                                     const std::vector<ValidatedEnvelope>& validated) {
        struct Row {
            const WrappedKeyItem* item;
            const ValidatedEnvelope* v;
        };
        std::vector<Row> rows;
        for (size_t i = 0; i < items.size(); ++i) rows.push_back({&items[i], &validated[i]});
        std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
            return a.item->purpose < b.item->purpose;
        });

        std::vector<uint8_t> buf;
        canonical::appendString(buf, "openiov|keyprov-req|v1");
        canonical::appendString(buf, request_id);
        canonical::appendString(buf, domain);
        canonical::appendString(buf, provider->providerVersionDigest());
        for (const auto& r : rows) {
            const WrappedKeyItem& it = *r.item;
            uint64_t purpose_val = 0;
            purposeEnumValue(it.purpose, purpose_val);
            uint64_t suite_val = 0;
            wrappingSuiteEnumValue(it.wrapping_suite, suite_val);
            canonical::appendString(buf, it.purpose);
            canonical::appendString(buf, it.key_id);
            canonical::appendUint64be(buf, it.business_key_version);
            canonical::appendString(buf, it.algorithm);
            canonical::appendEnumVarint(buf, suite_val);
            canonical::appendEnumVarint(
                buf, static_cast<uint64_t>(it.envelope_format));
            canonical::appendBytes(
                buf, canonical::sha256(std::vector<uint8_t>(
                         it.wrapped_key.data(), it.wrapped_key.data() + it.wrapped_key.size())));
            canonical::appendBytes(
                buf, canonical::sha256(std::vector<uint8_t>(
                         it.parameters.data(), it.parameters.data() + it.parameters.size())));
            canonical::appendBytes(buf, r.v->envelope_digest);
            canonical::appendBytes(buf, std::vector<uint8_t>(it.key_check_value.begin(),
                                                             it.key_check_value.end()));
            canonical::appendBytes(buf, r.v->params.recipient_certificate_digest);
            canonical::appendUint64be(buf, r.v->params.root_key_version);
            canonical::appendString(buf, r.v->params.derivation_version);
            canonical::appendString(buf, r.v->params.operation_id);
            (void)purpose_val;
        }
        return canonical::toHex(canonical::sha256(buf));
    }

    /// 用最新 SUCCEEDED journal 条目补充 ACK 绑定字段（envelopeDigest/KCV/format）。
    void enrich_ack_fields(const std::string& purpose, BusinessKeyStatus& out) {
        for (const auto& e : provider->listJournal()) {
            if (e.phase != BusinessKeyImportPhase::SUCCEEDED) continue;
            for (const auto& it : e.items) {
                if (it.purpose == purpose &&
                    it.business_key_version == out.business_key_version) {
                    out.envelope_format = it.envelope_format;
                    out.envelope_digest = it.envelope_digest;
                    out.key_check_value = it.key_check_value;
                    out.key_check_value_present = it.key_check_value_present;
                    return;
                }
            }
        }
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
            enrich_ack_fields(purpose, out);
            return ErrorCode::SUCCESS;
        }
        out.state = BusinessKeyState::INVALID;
        out.business_key_version = slot.present ? slot.business_key_version : 0;
        out.key_id_digest = slot.key_id_digest;
        out.algorithm = slot.algorithm;
        return ErrorCode::SUCCESS;
    }

    ErrorCode build_committed_result(const BusinessKeyJournalEntry& entry, ImportResult& out) {
        out.business_domain = kBusinessDomainV2c;
        out.state = BusinessKeyImportState::COMMITTED;
        out.items = entry.items;
        out.committed_at_ms = entry.committed_at_ms;
        out.provider_version_digest = entry.provider_version_digest;
        // 原 ACK/proof：直接回传 journal 保存的非敏感 proof 原文，不重新签名。
        if (!entry.import_proof.empty()) {
            out.import_proof.assign(entry.import_proof);
        }
        out.proof_algorithm = entry.proof_algorithm;
        out.binding_certificate_digest = entry.binding_certificate_digest;
        return ErrorCode::SUCCESS;
    }

    void update_ledger(const std::string& domain, const BusinessKeyJournalEntry& entry,
                       uint64_t generation) {
        if (!ledger) return;
        for (const auto& it : entry.items) {
            BusinessKeyMetadata meta;
            meta.present = true;
            meta.business_domain = domain;
            meta.purpose = it.purpose;
            meta.key_id_digest = it.key_id_digest;
            meta.business_key_version = it.business_key_version;
            meta.algorithm = it.algorithm;
            meta.valid_from_ms = it.valid_from_ms;
            meta.valid_to_ms = it.valid_to_ms;
            meta.active_generation = generation;
            meta.request_id_digest = entry.request_id_digest;
            meta.created_at_ms = entry.created_at_ms;
            meta.committed_at_ms = entry.committed_at_ms;
            ledger->put(meta);
        }
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
            entry.phase = BusinessKeyImportPhase::SUCCEEDED;
            entry.committed_at_ms = now;
            entry.provider_version_digest = provider->providerVersionDigest();
            for (auto& it : entry.items) it.state = BusinessKeyState::ACTIVE;
            provider->saveJournal(entry);
            update_ledger(kBusinessDomainV2c, entry, entry.generation);
            return ErrorCode::SUCCESS;
        }
        // 未 commit：安全回滚，不得形成单用途 ACTIVE
        provider->rollbackStaging(kBusinessDomainV2c, entry.generation);
        entry.phase = BusinessKeyImportPhase::FAILED;
        entry.last_error = "BUSINESS_KEY_PARTIAL_ROLLBACK";
        provider->saveJournal(entry);
        return ErrorCode::SUCCESS;
    }

    ErrorCode recover_on_startup() {
        for (auto entry : provider->listJournal()) {
            if (entry.phase == BusinessKeyImportPhase::SUCCEEDED ||
                entry.phase == BusinessKeyImportPhase::FAILED) {
                continue;
            }
            recover_entry(entry);
        }
        return ErrorCode::SUCCESS;
    }

    /// 双用途导入管线（journal 建立 → 解封 → 复核 → 原子提交 → proof → ledger）。
    /// 调用方已完成全部准入与 envelope 校验；本方法不接触 binding 的明文公钥清理
    /// （由调用方在返回后 clearPublicKey）。返回 SUCCESS 时 out 已通过
    /// build_committed_result 填充；其余按既有语义返回（OUTCOME_UNKNOWN/其他错误）。
    ErrorCode run_pipeline(const std::string& request_id, const std::string& business_domain,
                           const std::vector<WrappedKeyItem>& items,
                           const std::vector<ValidatedEnvelope>& validated,
                           const BusinessKeyDeviceBinding& binding,
                           const std::string& rid_digest, const std::string& digest,
                           uint64_t generation, int64_t now, ImportResult& out) {
        // ---- journal：VALIDATED → PROCESSING ----
        BusinessKeyJournalEntry entry;
        entry.request_id_digest = rid_digest;
        entry.request_digest = digest;
        entry.phase = BusinessKeyImportPhase::VALIDATED;
        entry.generation = generation;
        entry.created_at_ms = now;
        entry.provider_version_digest = provider->providerVersionDigest();
        for (size_t i = 0; i < items.size(); ++i) {
            BusinessKeyStatus st;
            st.business_domain = business_domain;
            st.purpose = items[i].purpose;
            st.business_key_version = items[i].business_key_version;
            st.state = BusinessKeyState::STAGED;
            st.key_id = items[i].key_id;  // CR-012 Q3：journal 保存完整 key_id 以重建原 ACK
            st.key_id_digest = canonical::toHex(canonical::sha256(items[i].key_id));
            st.algorithm = items[i].algorithm;
            st.valid_from_ms = items[i].valid_from_ms;
            st.valid_to_ms = items[i].valid_to_ms;
            st.envelope_format = items[i].envelope_format;
            st.envelope_digest = validated[i].envelope_digest;
            st.key_check_value = items[i].key_check_value;
            st.key_check_value_present = items[i].key_check_value_present;
            entry.items.push_back(std::move(st));
        }
        entry.phase = BusinessKeyImportPhase::PROCESSING;
        provider->saveJournal(entry);

        // ---- §8：解封到 staging（双用途同一 generation）----
        std::vector<std::array<uint8_t, 3>> actual_kcv(items.size());
        std::string fp_hex = canonical::toHex(binding.active_cert_digest);
        for (size_t i = 0; i < items.size(); ++i) {
            std::string hkdf_info =
                canonical::buildHkdfInfoV1(request_id, business_domain, items[i].purpose,
                                           items[i].key_id, items[i].business_key_version, fp_hex);
            std::vector<uint8_t> info_bytes(hkdf_info.begin(), hkdf_info.end());
            ErrorCode rc = provider->unwrapToStaging(
                business_domain, items[i], validated[i].params, validated[i].canonical_aad,
                info_bytes, binding, generation, actual_kcv[i]);
            if (rc != ErrorCode::SUCCESS) {
                if (is_outcome_unknown(rc)) {
                    entry.phase = BusinessKeyImportPhase::OUTCOME_UNKNOWN;
                    entry.last_error = error_code_to_string(rc);
                    provider->saveJournal(entry);
                    out.state = BusinessKeyImportState::UNKNOWN;
                    return ErrorCode::BUSINESS_KEY_OUTCOME_UNKNOWN;
                }
                provider->rollbackStaging(business_domain, generation);
                entry.phase = BusinessKeyImportPhase::FAILED;
                entry.last_error = error_code_to_string(rc);
                provider->saveJournal(entry);
                out.state = BusinessKeyImportState::FAILED;
                return rc;
            }
            if (items[i].purpose == kBusinessPurposeUplinkAead)
                entry.phase = BusinessKeyImportPhase::UPLINK_STAGED;
            provider->saveJournal(entry);
        }
        entry.phase = BusinessKeyImportPhase::BOTH_STAGED;
        provider->saveJournal(entry);

        // ---- staging 复核 ----
        for (const auto& item : items) {
            ErrorCode rc = provider->verifyStaging(business_domain, item.purpose);
            if (rc != ErrorCode::SUCCESS) {
                provider->rollbackStaging(business_domain, generation);
                entry.phase = BusinessKeyImportPhase::FAILED;
                entry.last_error = error_code_to_string(rc);
                provider->saveJournal(entry);
                out.state = BusinessKeyImportState::FAILED;
                return rc;
            }
        }

        // ---- §8 原子提交 ----
        entry.phase = BusinessKeyImportPhase::COMMITTING;
        provider->saveJournal(entry);
        ErrorCode rc = provider->commitBatch(business_domain, generation);
        if (rc != ErrorCode::SUCCESS) {
            if (is_outcome_unknown(rc)) {
                entry.phase = BusinessKeyImportPhase::OUTCOME_UNKNOWN;
                entry.last_error = error_code_to_string(rc);
                provider->saveJournal(entry);
                out.state = BusinessKeyImportState::UNKNOWN;
                return ErrorCode::BUSINESS_KEY_OUTCOME_UNKNOWN;
            }
            provider->rollbackStaging(business_domain, generation);
            entry.phase = BusinessKeyImportPhase::FAILED;
            entry.last_error = error_code_to_string(rc);
            provider->saveJournal(entry);
            out.state = BusinessKeyImportState::FAILED;
            return rc;
        }

        // ---- §7.3/§US-020：结果元数据 + 逐 item Import Attestation + ledger ----
        int64_t committed_at = now;
        trusted_now_ms(committed_at);
        entry.phase = BusinessKeyImportPhase::SUCCEEDED;
        entry.committed_at_ms = committed_at;
        entry.provider_version_digest = provider->providerVersionDigest();
        entry.binding_certificate_digest = binding.active_cert_digest;
        entry.proof_algorithm = kImportProofAlgorithmP1363;
        bool proof_failed = false;
        for (size_t i = 0; i < items.size(); ++i) {
            BusinessKeyStatus& st = entry.items[i];
            st.state = BusinessKeyState::ACTIVE;
            st.key_check_value = actual_kcv[i];
            st.key_check_value_present = true;
            // CR-012 Q3：逐 item 返回绑定证书策略摘要，供 TSP 机械映射 ACK。
            st.recipient_certificate_digest = entry.binding_certificate_digest;

            std::vector<uint8_t> kcv(st.key_check_value.begin(), st.key_check_value.end());
            std::vector<uint8_t> proof;
            std::string palg;
            ErrorCode prc = provider->generateProof(
                business_domain, st.purpose, st.business_key_version, request_id, items[i].key_id,
                st.envelope_digest, kcv, proof, palg);
            if (prc == ErrorCode::SUCCESS && proof.size() == kImportProofSizeP1363) {
                st.import_proof = proof;
                st.proof_algorithm = palg;
            } else {
                proof_failed = true;
            }
            if (!proof.empty()) OPENSSL_cleanse(proof.data(), proof.size());
        }
        if (proof_failed) {
            // 安全签名调用结果不确定：标记 OUTCOME_UNKNOWN，由启动对账收敛，不返回 IMPORTED ACK。
            entry.phase = BusinessKeyImportPhase::OUTCOME_UNKNOWN;
            entry.last_error = "IMPORT_ATTESTATION_FAILED";
            provider->saveJournal(entry);
            out.state = BusinessKeyImportState::UNKNOWN;
            return ErrorCode::BUSINESS_KEY_OUTCOME_UNKNOWN;
        }
        provider->saveJournal(entry);
        update_ledger(business_domain, entry, generation);

        return build_committed_result(entry, out);
    }

    /// TBOX-SEC-DSN-CR-021 §3：残留事务核对。
    /// provider 侧（staging/commit marker/operation binding，fail-closed）或
    /// SecureMetadataLedger 中任一用途的 request_id_digest 绑定命中时返回 true。
    /// true 时服务层不得上报 NOT_FOUND（保持 UNKNOWN/稳定错误）。
    bool has_transaction_residue(const std::string& rid_digest) const {
        if (provider->hasTransactionResidue(rid_digest)) return true;
        if (ledger) {
            for (const auto& p : cfg.required_purposes) {
                BusinessKeyMetadata meta;
                if (ledger->get(kBusinessDomainV2c, p, meta) && meta.present &&
                    !meta.request_id_digest.empty() && meta.request_id_digest == rid_digest) {
                    return true;
                }
            }
        }
        return false;
    }

    /// 脱敏日志：仅记录 request_id_digest / journal_load_status / import_state /
    /// provider_error_class / 耗时；禁止 wrappedKey、proof、完整 requestId、证书、slotRef。
    void log_journal_load_outcome(const std::string& rid_digest, JournalLoadStatus status,
                                  const char* import_state, ErrorCode provider_error,
                                  bool security_event) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0_)
                            .count();
        auto fields = {
            tbox::fw::log::Field("request_id_digest",
                tbox::fw::log::FieldValue::makeString(rid_digest)),
            tbox::fw::log::Field("journal_load_status",
                tbox::fw::log::FieldValue::makeString(journal_load_status_to_string(status))),
            tbox::fw::log::Field("import_state",
                tbox::fw::log::FieldValue::makeString(import_state)),
            tbox::fw::log::Field("provider_error_class",
                tbox::fw::log::FieldValue::makeString(error_code_to_string(provider_error))),
            tbox::fw::log::Field("duration_ms",
                tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(ms)))};
        if (security_event) {
            SecLogAdapter::business_key().error("sec.business_key.journal_load_failed",
                "导入结果查询：journal 读取失败（fail-closed，按 UNKNOWN 处理）", fields);
        } else {
            SecLogAdapter::business_key().warn("sec.business_key.residue_unknown",
                "导入结果查询：journal 无记录但存在事务残留，按 UNKNOWN 处理", fields);
        }
    }

    std::chrono::steady_clock::time_point t0_;

    /// KL1 查询判定（TBOX-SEC-DSN-CR-023 §12.11.2；只读，同 import 锁）。
    /// attach 非空时填充同一快照（epoch/contract/存储健康）与已有 request 身份/证据摘要。
    /// NOT_FOUND 仅在强 NF 全部条件成立时返回：存储健康、恢复完成、无残留、非治理。
    ErrorCode query_result(const std::string& request_id, ImportResult& out,
                           KeyprovResultAttachment* attach) {
        out = ImportResult{};
        out.request_id = request_id;
        // 注：shutting_down_ 为外层服务成员，由外层入口（getImportResult/getImportResultKl1）先行检查。
        if (!cfg.enabled || !provider_ready) return ErrorCode::BUSINESS_KEY_NOT_READY;
        if (request_id.empty()) return ErrorCode::INVALID_PARAMETER;
        if (request_id.size() > 128) return ErrorCode::INVALID_PARAMETER;

        const std::string rid_digest = rid_digest_of(request_id);
        t0_ = std::chrono::steady_clock::now();
        if (attach != nullptr) {
            attach->snapshot = compute_snapshot();
            attach->queried_at_ms = 0;
            trusted_now_ms(attach->queried_at_ms);
        }

        // 结构化 journal 读取（CR-021 §3）：不再把任意 false 直接解释为不存在。
        JournalLoadResult lr = provider->loadJournalEx(rid_digest);
        switch (lr.status) {
            case JournalLoadStatus::FOUND: {
                if (!lr.entry) {  // 防御：FOUND 必须携带条目
                    log_journal_load_outcome(rid_digest, lr.status, "UNKNOWN",
                                             ErrorCode::STORAGE_CORRUPTION, true);
                    out.business_domain = kBusinessDomainV2c;
                    out.state = BusinessKeyImportState::UNKNOWN;
                    return ErrorCode::SUCCESS;
                }
                const BusinessKeyJournalEntry& entry = *lr.entry;
                if (attach != nullptr) attach->request_identity_digest = entry.request_digest;
                if (entry.phase == BusinessKeyImportPhase::SUCCEEDED) {
                    return build_committed_result(entry, out);
                }
                // 其余 phase 按权威 phase 派生；OUTCOME_UNKNOWN 必须保持 UNKNOWN。
                out.business_domain = kBusinessDomainV2c;
                out.state = import_state_from_phase(entry.phase);
                out.items = entry.items;
                out.provider_version_digest = entry.provider_version_digest;
                return ErrorCode::SUCCESS;
            }
            case JournalLoadStatus::NOT_FOUND: {
                // 残留核对 + 治理：无 staging/commit marker/operation binding/ledger 痕迹
                // 且存储未被清空/更换时才返回 NOT_FOUND；其余 → UNKNOWN（fail-closed）。
                out.business_domain = kBusinessDomainV2c;
                if (governance_required_) {
                    // 存储被清空/更换且旧世代副作用无法排除：epoch 变化不是洗白，
                    // 禁止扫描空目录即恢复 proven；不得上报 NOT_FOUND。
                    log_journal_load_outcome(rid_digest, lr.status, "UNKNOWN",
                                             ErrorCode::SUCCESS, true);
                    out.state = BusinessKeyImportState::UNKNOWN;
                } else if (has_transaction_residue(rid_digest)) {
                    log_journal_load_outcome(rid_digest, lr.status, "UNKNOWN",
                                             ErrorCode::SUCCESS, false);
                    out.state = BusinessKeyImportState::UNKNOWN;
                } else {
                    out.state = BusinessKeyImportState::NOT_FOUND;
                }
                return ErrorCode::SUCCESS;
            }
            case JournalLoadStatus::AUTH_FAILED:
            case JournalLoadStatus::CORRUPT:
            case JournalLoadStatus::UNSUPPORTED_VERSION: {
                // 安全事件 + UNKNOWN；MAC 失败不是“不存在”。
                log_journal_load_outcome(rid_digest, lr.status, "UNKNOWN",
                                         lr.provider_error, true);
                out.business_domain = kBusinessDomainV2c;
                out.state = BusinessKeyImportState::UNKNOWN;
                return ErrorCode::SUCCESS;
            }
            case JournalLoadStatus::IO_ERROR:
            default: {
                // 稳定错误；调用方 fail-closed；存储不健康不得制造 NF。
                log_journal_load_outcome(rid_digest, lr.status, "UNKNOWN",
                                         lr.provider_error, true);
                out.business_domain = kBusinessDomainV2c;
                out.state = BusinessKeyImportState::UNKNOWN;
                return lr.provider_error != ErrorCode::SUCCESS ? lr.provider_error
                                                               : ErrorCode::STORAGE_READ_FAILED;
            }
        }
    }
};

// ============================================================
// Construction
// ============================================================

BusinessKeyProvisioningService::BusinessKeyProvisioningService(
    BusinessKeyProvisioningConfig config, std::unique_ptr<BusinessKeyProvider> provider,
    std::shared_ptr<TrustedTimeProvider> trusted_time, std::unique_ptr<SecureMetadataLedger> ledger,
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
    if (impl_->cfg.allowed_algorithms.empty())
        impl_->cfg.allowed_algorithms = {kDefaultKeyAlgorithm};
    if (impl_->cfg.allowed_wrapping_suites.empty())
        impl_->cfg.allowed_wrapping_suites = {kWrappingSuiteEcdhEsP256};
    if (impl_->cfg.allowed_envelope_formats.empty())
        impl_->cfg.allowed_envelope_formats = {kKeyEnvelopeFormatEcdhEsP256V1};
}

BusinessKeyProvisioningService::~BusinessKeyProvisioningService() = default;

ErrorCode BusinessKeyProvisioningService::initialize() {
    std::lock_guard<std::mutex> lock(impl_->mtx);

    if (!impl_->cfg.enabled) {
        impl_->provider_ready = false;
        impl_->import_ready = false;
        SecLogAdapter::business_key().info("sec.business_key.disabled",
                                           "业务密钥开通未启用（保持 NOT_READY）");
        return ErrorCode::SUCCESS;
    }
    if (!impl_->provider || !impl_->ledger || !impl_->trusted_time) {
        impl_->provider_ready = false;
        impl_->import_ready = false;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    if (impl_->provider->initialize() != ErrorCode::SUCCESS) {
        impl_->provider_ready = false;
        impl_->import_ready = false;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    if (impl_->ledger->load() != ErrorCode::SUCCESS) {
        impl_->provider_ready = false;
        impl_->import_ready = false;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    impl_->recover_on_startup();

    // KL1：恢复完成后固化存储世代；检测到存储被清空/更换 → 治理标志
    // （epoch 变化不是洗白：旧 generation 副作用无法排除时不得上报 NOT_FOUND）。
    if (impl_->provider->storageReplaced()) {
        impl_->epoch_src.bumpStorageReplacement();
        impl_->governance_required_ = true;
    } else {
        impl_->epoch_src.bumpRecovery();
    }
    impl_->provider_ready = impl_->provider->isReady();
    impl_->storage_ready_ = impl_->provider_ready && !impl_->governance_required_;
    impl_->cap = impl_->compute_capability();
    impl_->import_ready = impl_->provider_ready && impl_->cap.all() && impl_->storage_ready_;

    if (!impl_->import_ready) {
        SecLogAdapter::business_key().warn(
            "sec.business_key.capability_not_ready",
            "业务密钥开通能力未就绪（fail-closed，仅允许状态查询）");
    }
    return ErrorCode::SUCCESS;
}

void BusinessKeyProvisioningService::beginShutdown() { shutting_down_.store(true); }

bool BusinessKeyProvisioningService::isReady() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->import_ready && !shutting_down_.load();
}

V2cKeyProvisioningCapability BusinessKeyProvisioningService::capability() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->cap;
}

KeyprovContractSnapshot BusinessKeyProvisioningService::contractSnapshot() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->compute_snapshot();
}

// ============================================================
// Status
// ============================================================

ErrorCode BusinessKeyProvisioningService::getStatus(const std::string& business_domain,
                                                    const std::vector<std::string>& purposes,
                                                    BusinessKeyStatusSet& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out.items.clear();
    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->cfg.enabled || !impl_->provider_ready)
        return ErrorCode::BUSINESS_KEY_NOT_READY;
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

ErrorCode BusinessKeyProvisioningService::import(const std::string& request_id,
                                                 const std::string& business_domain,
                                                 const std::vector<WrappedKeyItem>& items,
                                                 ImportResult& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out = ImportResult{};
    out.request_id = request_id;
    out.business_domain = business_domain;
    ImportLogGuard log_guard{rid_digest_of(request_id), out, std::chrono::steady_clock::now()};

    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->cfg.enabled) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->import_ready) {
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }

    // §6.1 结构/格式/suite/算法 allowlist（不执行密码操作）
    ErrorCode rc = impl_->validate_structure(request_id, business_domain, items);
    if (rc != ErrorCode::SUCCESS) {
        out.state = BusinessKeyImportState::FAILED;
        return rc;
    }

    // §6.5 设备解封装身份 + 证书 KU/私钥 derive 门禁
    BusinessKeyDeviceBinding binding = impl_->probe_binding();
    if (!impl_->binding_agreement_ok(binding)) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }

    // §6.2..§6.8 信封校验（解封前全部完成；任何失败不执行密码操作）
    std::vector<ValidatedEnvelope> validated(items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        EnvelopeContext ctx;
        ctx.request_id = request_id;
        ctx.business_domain = business_domain;
        ctx.purpose = items[i].purpose;
        ctx.active_cert_digest = binding.active_cert_digest;
        ctx.active_cert_p256 = binding.active_cert_p256;
        ctx.active_cert_key_agreement = binding.active_cert_key_agreement;
        ctx.active_cert_digital_signature = binding.active_cert_digital_signature;
        ctx.private_key_can_derive = binding.private_key_can_derive;
        ctx.private_key_can_sign = binding.private_key_can_sign;
        // CR-020 §2.1/§6.5 修订门禁传导
        ctx.active_cert_ca_false = binding.active_cert_ca_false;
        ctx.active_cert_eku_client_auth_only = binding.active_cert_eku_client_auth_only;
        ctx.active_cert_critical_extensions_allowed =
            binding.active_cert_critical_extensions_allowed;
        ctx.active_cert_leaf_digest_bound = binding.active_cert_leaf_digest_bound;
        ctx.active_cert_chain_key_match = binding.active_cert_chain_key_match;
        ctx.identity_template_sign_derive = binding.identity_template_sign_derive;
        EnvelopeLimits limits;
        limits.max_parameters = static_cast<size_t>(impl_->cfg.max_parameters_bytes);
        limits.max_wrapped_key = static_cast<size_t>(impl_->cfg.max_wrapped_key_bytes);
        rc = validateEnvelope(items[i], ctx, limits, validated[i]);
        if (rc != ErrorCode::SUCCESS) {
            binding.clearPublicKey();
            out.state = BusinessKeyImportState::FAILED;
            return rc;
        }
    }

    const std::string rid_digest = rid_digest_of(request_id);
    const std::string digest =
        impl_->build_request_digest(request_id, business_domain, items, validated);

    // ---- §9/§10 幂等 / 冲突 / 恢复 ----
    BusinessKeyJournalEntry existing;
    if (impl_->provider->loadJournal(rid_digest, existing)) {
        if (!existing.request_digest.empty() && existing.request_digest != digest) {
            out.state = BusinessKeyImportState::FAILED;
            return ErrorCode::BUSINESS_KEY_CONFLICT;
        }
        if (existing.phase == BusinessKeyImportPhase::SUCCEEDED) {
            return impl_->build_committed_result(existing, out);
        }
        if (existing.phase == BusinessKeyImportPhase::FAILED) {
            out.state = BusinessKeyImportState::FAILED;
            out.items = existing.items;
            return ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN;
        }
        // 未终结：收敛恢复，不新建第二次安全操作
        impl_->recover_entry(existing);
        if (existing.phase == BusinessKeyImportPhase::SUCCEEDED) {
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

    const uint64_t generation = impl_->next_generation();
    int64_t now = 0;
    impl_->trusted_now_ms(now);

    // 共享导入管线（journal 建立 → 解封 → 复核 → 原子提交 → proof → ledger）。
    ErrorCode prc = impl_->run_pipeline(request_id, business_domain, items, validated,
                                        binding, rid_digest, digest, generation, now, out);
    binding.clearPublicKey();
    return prc;
}

// ============================================================
// KL1 import（TBOX-SEC-DSN-CR-023 §12.11.1/§12.11.3）
// ============================================================

ErrorCode BusinessKeyProvisioningService::importKl1(
    const std::string& request_id, const std::string& business_domain,
    const std::vector<WrappedKeyItem>& items, const KeyprovImportContext& context,
    ImportResult& out, KeyprovResultAttachment& attach) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    out = ImportResult{};
    attach = KeyprovResultAttachment{};
    attach.snapshot = impl_->compute_snapshot();
    out.request_id = request_id;
    out.business_domain = business_domain;
    ImportLogGuard log_guard{rid_digest_of(request_id), out, std::chrono::steady_clock::now()};

    // ---- 0) 服务级门禁（fail-closed；缺 KL1 admission 能力时新 TSP 阻断）----
    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->cfg.enabled) return ErrorCode::BUSINESS_KEY_NOT_READY;
    if (!impl_->import_ready) {
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;  // 1025：能力/存储/时间不健康
    }
    if (!attach.snapshot.supports_lease_admission) {
        // 快照握手未就绪：不得把旧接口成功当作 KL1 能力，也不得降级调用旧 import。
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    if (context.kl1_profile_version != kKeyprovKl1ProfileVersion ||
        context.capability_epoch == 0) {
        // profile 未知/缺失、epoch 缺失：一律视为未 probe → 不可用，不是支持。
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }

    const std::string rid_digest = rid_digest_of(request_id);

    // ---- 1) 结构/schema/大小/item 数/requestId（不执行密码操作）----
    ErrorCode rc = impl_->validate_structure(request_id, business_domain, items);
    if (rc != ErrorCode::SUCCESS) {
        out.state = BusinessKeyImportState::FAILED;
        return rc;  // 1021/1023
    }

    // ---- 2) 设备解封装身份 + 证书 KU/私钥 derive 门禁（信封校验上下文所需）----
    BusinessKeyDeviceBinding binding = impl_->probe_binding();
    if (!impl_->binding_agreement_ok(binding)) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::BUSINESS_KEY_NOT_READY;  // 1025
    }

    // ---- 3) 信封校验（解封前全部完成；任何失败不执行密码操作）----
    std::vector<ValidatedEnvelope> validated(items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        EnvelopeContext ctx;
        ctx.request_id = request_id;
        ctx.business_domain = business_domain;
        ctx.purpose = items[i].purpose;
        ctx.active_cert_digest = binding.active_cert_digest;
        ctx.active_cert_p256 = binding.active_cert_p256;
        ctx.active_cert_key_agreement = binding.active_cert_key_agreement;
        ctx.active_cert_digital_signature = binding.active_cert_digital_signature;
        ctx.private_key_can_derive = binding.private_key_can_derive;
        ctx.private_key_can_sign = binding.private_key_can_sign;
        ctx.active_cert_ca_false = binding.active_cert_ca_false;
        ctx.active_cert_eku_client_auth_only = binding.active_cert_eku_client_auth_only;
        ctx.active_cert_critical_extensions_allowed =
            binding.active_cert_critical_extensions_allowed;
        ctx.active_cert_leaf_digest_bound = binding.active_cert_leaf_digest_bound;
        ctx.active_cert_chain_key_match = binding.active_cert_chain_key_match;
        ctx.identity_template_sign_derive = binding.identity_template_sign_derive;
        EnvelopeLimits limits;
        limits.max_parameters = static_cast<size_t>(impl_->cfg.max_parameters_bytes);
        limits.max_wrapped_key = static_cast<size_t>(impl_->cfg.max_wrapped_key_bytes);
        rc = validateEnvelope(items[i], ctx, limits, validated[i]);
        if (rc != ErrorCode::SUCCESS) {
            binding.clearPublicKey();
            out.state = BusinessKeyImportState::FAILED;
            return rc;
        }
    }

    const std::string digest =
        impl_->build_request_digest(request_id, business_domain, items, validated);

    // ---- 4) journal 绑定检查（同 operation 既有事实优先；不同内容同 rid 冲突）----
    JournalLoadResult lr = impl_->provider->loadJournalEx(rid_digest);
    switch (lr.status) {
        case JournalLoadStatus::FOUND: {
            if (!lr.entry) {
                out.state = BusinessKeyImportState::UNKNOWN;
                return ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN;  // 1024
            }
            BusinessKeyJournalEntry entry = *lr.entry;
            attach.request_identity_digest = entry.request_digest;
            if (!entry.request_digest.empty() && entry.request_digest != digest) {
                // 同 rid 不同业务 digest：冲突，不覆盖原证据（§12.11.2/3；LC08）。
                out.state = BusinessKeyImportState::FAILED;
                return ErrorCode::BUSINESS_KEY_CONFLICT;  // 1022
            }
            if (entry.phase == BusinessKeyImportPhase::SUCCEEDED) {
                // 已 COMMITTED：恢复原结果/proof；旧 E 过期不否定事实，不重签。
                return impl_->build_committed_result(entry, out);
            }
            if (entry.phase == BusinessKeyImportPhase::FAILED) {
                out.state = BusinessKeyImportState::FAILED;
                out.items = entry.items;
                return ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN;  // 1024
            }
            // STAGED/PROCESSING/OUTCOME_UNKNOWN/RECOVERING：恢复/对账，不建第二 operation。
            impl_->recover_entry(entry);
            if (entry.phase == BusinessKeyImportPhase::SUCCEEDED) {
                return impl_->build_committed_result(entry, out);
            }
            out.state = BusinessKeyImportState::FAILED;
            out.items = entry.items;
            return ErrorCode::BUSINESS_KEY_PARTIAL_ROLLBACK;  // 1026
        }
        case JournalLoadStatus::NOT_FOUND: {
            if (impl_->has_transaction_residue(rid_digest)) {
                // 可疑残留：交恢复/对账，不创建第二 operation。
                out.state = BusinessKeyImportState::UNKNOWN;
                return ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN;  // 1024
            }
            break;  // 确属新 operation，进入准入。
        }
        case JournalLoadStatus::AUTH_FAILED:
        case JournalLoadStatus::CORRUPT:
        case JournalLoadStatus::UNSUPPORTED_VERSION:
            out.state = BusinessKeyImportState::UNKNOWN;
            return ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN;  // 1024（不是 NF，不是无副作用）
        case JournalLoadStatus::IO_ERROR:
        default:
            out.state = BusinessKeyImportState::UNKNOWN;
            return ErrorCode::BUSINESS_KEY_NOT_READY;  // 1025：存储不可读/不健康
    }

    // ---- 5) 新 operation 准入（事实优先级：1025 → 1030 → 1029 → 1023）----
    // 可信时间健康（KL1 门禁：TRUSTED、uncertainty≤1000ms、freshness≤300000ms），
    // U = utc_ms + uncertainty_ms。
    int64_t U = 0;
    rc = impl_->kl1_trusted_upper_now(U);
    if (rc != ErrorCode::SUCCESS) {
        out.state = BusinessKeyImportState::FAILED;
        return rc;  // 1025：可信时间不健康（LC21）
    }
    // 调用方 probe 所见 epoch 与当前 SEC epoch 一致，否则 1030。
    if (context.capability_epoch != impl_->epoch_src.epoch()) {
        attach.snapshot = impl_->compute_snapshot();  // 携带当前 epoch 供诊断
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::KL1_CAPABILITY_EPOCH_MISMATCH;  // 1030
    }
    // 租约未到期：仅 U<E 可新启动，U==E 必拒绝（LC02.0/.1）。
    if (U >= context.admission_expire_at_ms) {
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::KL1_ADMISSION_REJECTED;  // 1029
    }
    // item 安全有效期须覆盖 E（LC20.item 派生；valid_from≤U 且 valid_to≥E）。
    for (const auto& item : items) {
        if (item.valid_from_ms > U || item.valid_to_ms < context.admission_expire_at_ms) {
            out.state = BusinessKeyImportState::FAILED;
            return ErrorCode::WRAPPED_KEY_INVALID;  // 1023
        }
    }
    // 证书有效期覆盖 E（LC20.cert 派生）。
    if (binding.active_cert_valid_from_ms > U ||
        binding.active_cert_valid_to_ms < context.admission_expire_at_ms) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::WRAPPED_KEY_INVALID;  // 1023
    }

    // ---- 6) 版本单调/有效期/可信时间（与旧导入一致）----
    rc = impl_->validate_version_and_time(business_domain, items);
    if (rc != ErrorCode::SUCCESS) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return rc;
    }

    // ---- 7) 取操作锁后、建立新 journal 前再次校验（排队越界：时间/epoch 在
    //        校验期间可能已变化）。仍按 1025 → 1030 → 1029 归类。----
    rc = impl_->kl1_trusted_upper_now(U);
    if (rc != ErrorCode::SUCCESS) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return rc;  // 1025
    }
    if (context.capability_epoch != impl_->epoch_src.epoch()) {
        attach.snapshot = impl_->compute_snapshot();
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::KL1_CAPABILITY_EPOCH_MISMATCH;  // 1030
    }
    if (U >= context.admission_expire_at_ms) {
        binding.clearPublicKey();
        out.state = BusinessKeyImportState::FAILED;
        return ErrorCode::KL1_ADMISSION_REJECTED;  // 1029
    }

    const uint64_t generation = impl_->next_generation();
    int64_t now = 0;
    impl_->trusted_now_ms(now);

    ErrorCode prc = impl_->run_pipeline(request_id, business_domain, items, validated,
                                        binding, rid_digest, digest, generation, now, out);
    binding.clearPublicKey();
    if (prc == ErrorCode::SUCCESS) {
        attach.request_identity_digest = digest;
        attach.queried_at_ms = now;
    }
    return prc;
}

// ============================================================
// Result query
// ============================================================

ErrorCode BusinessKeyProvisioningService::getImportResult(const std::string& request_id,
                                                          ImportResult& out) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    return impl_->query_result(request_id, out, nullptr);
}

ErrorCode BusinessKeyProvisioningService::getImportResultKl1(
    const std::string& request_id, ImportResult& out, KeyprovResultAttachment& attach) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (shutting_down_.load()) return ErrorCode::BUSINESS_KEY_NOT_READY;
    attach = KeyprovResultAttachment{};
    return impl_->query_result(request_id, out, &attach);
}

} // namespace sec
} // namespace tbox

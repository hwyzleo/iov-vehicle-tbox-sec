//
// TBOX-SEC-DSN-CR-017 / TBOX-SEC-DSN-CR-024：可信时间生产契约实现。
//
// CR-017：CompositeTrustedTimeProvider 为 production 唯一可信时间注入点：
// 平台同步时间 → 硬件 RTC；freshness（单调计龄）/uncertainty/回拨保护全部
// fail-closed。真实平台/RTC 后端未落地前 fail-closed。
//
// CR-024：PlatformTimeAdapter 经 TIME 正式 client 读取/订阅真实事实；Composite
// 扩展为 SYNCHRONIZED + 认证证据绑定 + 契约完整 + 门限 + 回拨 + 短租约；
// TrustedTimeMonitor 自主监测/事件/到期撤销/请求 token。
//
// 单跳 RTT 记账（CR-024 §4）：TIME client 已测 rtt_ms 但**未扣减**任何字段；
// SEC 记录 received_boot_ms，在 gate 中一次性扣减（freshness 加、remaining 减），
// 禁止重复扣；跨进程不比较 monotonic 绝对值，消费方再扣自身一跳。
//

#include "trusted_time.h"

#include <algorithm>

#include "tbox/time/time_client.h"  // tbox::time::TimeClient / ClientError（TIME 公开 SDK）

#if defined(__linux__)
#include <time.h>
#else
#include <time.h>
#endif

namespace tbox {
namespace sec {

namespace {

int64_t bootNowMs() {
    struct timespec ts;
#if defined(CLOCK_BOOTTIME)
    clock_gettime(CLOCK_BOOTTIME, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

/// 认证绑定：verified 必须绑定已批准策略版本 + 受控证据引用 + （配置的）已批准来源。
bool authBound(const TimeFactSnapshot& f, const TrustedTimeConfig& cfg) {
    if (f.auth_status != TimeAuthStatus::Verified) return false;
    const bool policy_ok = std::find(cfg.approved_policy_versions.begin(),
                                     cfg.approved_policy_versions.end(),
                                     f.policy_version) != cfg.approved_policy_versions.end();
    if (!policy_ok) return false;
    if (cfg.require_evidence && f.evidence_ref.empty()) return false;
    if (!cfg.approved_sources.empty() &&
        std::find(cfg.approved_sources.begin(), cfg.approved_sources.end(),
                  f.source_id) == cfg.approved_sources.end()) {
        return false;
    }
    return true;
}

/// 契约完整性：缺少漂移/误差增长界、契约版本、能力、来源代次、策略版本等
/// 任一关键语义 → 不完整（Unknown(PlatformContractIncomplete)）。
bool contractComplete(const TimeFactSnapshot& f) {
    if (!f.validated) return false;
    if (f.contract_version == 0) return false;
    // 能力描述必须声明 snapshot 能力（TIME capabilities="snapshot,v1"）
    if (f.capabilities.find("snapshot") == std::string::npos) return false;
    if (f.time_daemon_epoch == 0) return false;
    if (f.source_id.empty()) return false;
    if (f.source_kind == TimeSourceKind::None) return false;
    if (f.policy_version.empty()) return false;
    // 漂移/误差增长界必须可界定（不能外推/增长 uncertainty 则拒绝）
    if (f.drift_bound_ppm <= 0) return false;
    if (f.remaining_validity_ms < 0) return false;
    if (f.freshness_age_ms < 0) return false;
    if (f.uncertainty_ms < 0) return false;
    return true;
}

TimeSyncState mapState(tbox::time::TimeState s) noexcept {
    switch (s) {
        case tbox::time::TimeState::kUnsynch: return TimeSyncState::Unsynch;
        case tbox::time::TimeState::kSyncing: return TimeSyncState::Syncing;
        case tbox::time::TimeState::kSynced: return TimeSyncState::Synced;
        case tbox::time::TimeState::kHoldover: return TimeSyncState::Holdover;
        case tbox::time::TimeState::kFault: return TimeSyncState::Fault;
    }
    return TimeSyncState::Unsynch;
}

TimeSourceKind mapKind(tbox::time::SourceKind k) noexcept {
    switch (k) {
        case tbox::time::SourceKind::kNtpNetwork: return TimeSourceKind::NtpNetwork;
        case tbox::time::SourceKind::kCellular: return TimeSourceKind::Cellular;
        case tbox::time::SourceKind::kGnss: return TimeSourceKind::Gnss;
        case tbox::time::SourceKind::kRtc: return TimeSourceKind::HardwareRtc;
        case tbox::time::SourceKind::kNone: return TimeSourceKind::None;
    }
    return TimeSourceKind::None;
}

TimeAuthStatus mapAuth(tbox::time::AuthStatus a) noexcept {
    switch (a) {
        case tbox::time::AuthStatus::kUnknown: return TimeAuthStatus::Unknown;
        case tbox::time::AuthStatus::kUnverified: return TimeAuthStatus::Unverified;
        case tbox::time::AuthStatus::kVerified: return TimeAuthStatus::Verified;
        case tbox::time::AuthStatus::kFailed: return TimeAuthStatus::Failed;
    }
    return TimeAuthStatus::Unknown;
}

/// 失败原因可行动性分级：决策性原因（NotAuthenticated/TooOld/ContractIncomplete 等）
/// > 通用不可用（InterfaceUnavailable/NotProvisioned）> NoSourceAvailable。
/// 用于双来源均失败时保留最可行动的诊断原因。
bool moreSpecific(TimeReason a, TimeReason b) {
    auto cls = [](TimeReason r) -> int {
        switch (r) {
            case TimeReason::NoSourceAvailable: return 0;
            case TimeReason::PlatformInterfaceUnavailable:
            case TimeReason::RtcInterfaceUnavailable:
                return 1;
            default: return 2;  // 决策性原因（NotAuthenticated/NotProvisioned/TooOld 等）
        }
    };
    return cls(a) > cls(b);
}

}  // namespace

// ============================================================================
// TimeClientBridge（生产：绑定 TIME 已发布 SDK）
// ============================================================================

namespace {

class TimeClientBridge final : public TimeSourceClient {
public:
    explicit TimeClientBridge(std::string socket_path)
        : client_(std::make_shared<tbox::time::TimeClient>(std::move(socket_path))) {}

    bool connect() override { return client_->connect(); }
    void disconnect() override { client_->disconnect(); }
    bool is_connected() const override { return client_->isConnected(); }

    QueryResult get_time_snapshot() override {
        QueryResult r;
        const auto res = client_->getTimeSnapshot();
        r.snapshot = res.snapshot;
        r.rtt_ms = std::max<int64_t>(0, res.rtt_ms);
        switch (res.error) {
            case tbox::time::ClientError::kOk:
                r.error = QueryResult::Error::kOk;
                break;
            case tbox::time::ClientError::kTimeUnavailable:
                r.error = QueryResult::Error::kTimeUnavailable;
                break;
            case tbox::time::ClientError::kServiceUnreachable:
                r.error = QueryResult::Error::kServiceUnreachable;
                break;
            case tbox::time::ClientError::kTimeout:
                r.error = QueryResult::Error::kTimeout;
                break;
            case tbox::time::ClientError::kUnsupported:
                r.error = QueryResult::Error::kUnsupported;
                break;
            case tbox::time::ClientError::kInvalidData:
                r.error = QueryResult::Error::kInvalidData;
                break;
            default:
                r.error = QueryResult::Error::kInternalError;
                break;
        }
        return r;
    }

    std::shared_ptr<void> subscribe_state_changed(
        std::function<void(const tbox::time::TimeStateEvent&)> cb) override {
        return client_->subscribeStateChanged(std::move(cb));
    }

private:
    std::shared_ptr<tbox::time::TimeClient> client_;
};

}  // namespace

// ============================================================================
// makeTimeClientBridge（生产：绑定 TIME 已发布 SDK）
// ============================================================================

std::shared_ptr<TimeSourceClient> makeTimeClientBridge(std::string socket_path) {
    return std::make_shared<TimeClientBridge>(std::move(socket_path));
}

// ============================================================================
// TrustedTimeResult → wire envelope
// ============================================================================

TrustedTimeEnvelope TrustedTimeResult::to_envelope() const noexcept {
    TrustedTimeEnvelope e;
    e.contract_version = contract_version;
    e.capabilities = capabilities;
    e.contract_complete = contract_complete;
    e.sec_daemon_epoch = sec_daemon_epoch;
    e.sec_time_event_sequence = sec_time_event_sequence;
    e.time_daemon_epoch = time_daemon_epoch;
    e.time_event_sequence = time_event_sequence;
    e.source_id = source_id;
    e.source_kind = timeSourceKindToString(source_kind);
    e.source_epoch = sample.source_epoch;
    e.policy_version = policy_version;
    e.trust_state = timeTrustStateToString(sample.trust_state);
    e.source = timeSourceToString(sample.source);
    e.reason = timeReasonToString(sample.reason);
    e.utc_valid = utc_valid;
    // utc_now 为绝对 wall-clock time_point：直接取 sample.utc_now 的 epoch 毫秒
    e.utc_epoch_ms = utc_valid
                         ? std::chrono::duration_cast<std::chrono::milliseconds>(
                               sample.utc_now.time_since_epoch())
                               .count()
                         : 0;
    e.freshness_age_ms = sample.freshness_age.count();
    e.uncertainty_valid = utc_valid;
    e.uncertainty_ms = sample.uncertainty.count();
    e.remaining_validity_ms = remaining_validity_ms;
    e.drift_bound_ppm = drift_bound_ppm;
    e.system_clock_aligned = system_clock_aligned;
    e.alignment_error_ms = alignment_error_ms;
    e.auth_status = timeAuthStatusToString(auth_status);
    e.evidence_ref = evidence_ref;
    e.valid = error_class.empty();
    e.error_class = error_class;
    return e;
}

// ============================================================================
// CompositeTrustedTimeProvider（CR-017 §2/§4.3 + CR-024 §3）
// ============================================================================

CompositeTrustedTimeProvider::CompositeTrustedTimeProvider(
    PlatformTimeSource* platform, HardwareRtcSource* hw_rtc,
    TrustedTimeConfig cfg)
    : platform_(platform), hw_rtc_(hw_rtc), cfg_(cfg) {}

TrustedTimeSample CompositeTrustedTimeProvider::now() noexcept {
    return query().sample;
}

TrustedTimeResult CompositeTrustedTimeProvider::query() noexcept {
    // 按优先级尝试平台 → RTC；失败原因取最近尝试来源（日志可判定/可行动）。
    TrustedTimeResult fallback;
    fallback.sample.trust_state = TimeTrustState::Untrusted;
    fallback.sample.reason = TimeReason::NoSourceAvailable;
    fallback.sample.source = TimeSource::None;

    if (cfg_.platform_enabled && platform_) {
        const TimeFactSnapshot f = platform_->query();
        TrustedTimeResult g = gatePlatform(f);
        if (g.sample.trust_state == TimeTrustState::Trusted) {
            acceptAsKnownGood(g.sample);
            return g;
        }
        fallback = g;
    }

    if (cfg_.hw_rtc_enabled && hw_rtc_) {
        const TrustedTimeSample s = hw_rtc_->query();
        TrustedTimeResult g = gateHardwareRtc(s);
        if (g.sample.trust_state == TimeTrustState::Trusted) {
            acceptAsKnownGood(g.sample);
            return g;
        }
        // 保留最可行动的失败原因：决策性原因 > 通用不可用 > NoSourceAvailable；
        // 同级别保留平台（首次）原因——RTC 的通用不可用不得掩盖平台的
        // PlatformNotAuthenticated 等决策性原因（CR-024 AT-01）。
        if (moreSpecific(g.sample.reason, fallback.sample.reason)) {
            fallback = g;
        }
    }

    return fallback;
}

TrustedTimeResult CompositeTrustedTimeProvider::gatePlatform(
    const TimeFactSnapshot& f) noexcept {
    TrustedTimeResult out;
    out.sample.source = TimeSource::PlatformSync;

    // ---- 传输层可达性 ----
    if (!f.transport_ok) {
        out.sample.trust_state = TimeTrustState::Unknown;
        out.sample.reason = TimeReason::PlatformInterfaceUnavailable;
        out.contract_complete = false;
        return out;
    }

    // ---- 数据/契约非法（unsupported/invalid）：不默认支持（AT-02）----
    if (!f.validated) {
        out.sample.trust_state = TimeTrustState::Unknown;
        out.sample.reason = TimeReason::PlatformContractIncomplete;
        out.contract_complete = false;
        return out;
    }

    // 携带来源事实（诊断/事件用）
    out.contract_version = f.contract_version;
    out.capabilities = f.capabilities;
    out.time_daemon_epoch = f.time_daemon_epoch;
    out.time_event_sequence = f.time_event_sequence;
    out.source_id = f.source_id;
    out.source_kind = f.source_kind;
    out.sample.source_epoch = f.source_epoch;
    out.policy_version = f.policy_version;
    out.auth_status = f.auth_status;
    out.evidence_ref = f.evidence_ref;
    out.system_clock_aligned = f.system_clock_aligned;
    out.alignment_error_ms = f.alignment_error_ms;
    out.drift_bound_ppm = f.drift_bound_ppm;
    out.utc_valid = f.utc_valid;
    out.contract_complete = f.contract_complete;

    // ---- 同步状态（HOLDOVER 不满足平台 SYNCHRONIZED；先拒绝再考虑 RTC）----
    if (f.state != TimeSyncState::Synced) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::PlatformNotSynchronized;
        return out;
    }

    // ---- 契约完整性（缺少关键语义 → Unknown）----
    if (!contractComplete(f)) {
        out.contract_complete = false;
        out.sample.trust_state = TimeTrustState::Unknown;
        out.sample.reason = TimeReason::PlatformContractIncomplete;
        return out;
    }
    out.contract_complete = true;

    // ---- 认证证据绑定（verified 必须绑定已批准策略/证据/来源）----
    if (f.auth_status == TimeAuthStatus::Unverified ||
        f.auth_status == TimeAuthStatus::Failed) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::PlatformNotAuthenticated;
        return out;
    }
    if (!authBound(f, cfg_)) {
        out.sample.trust_state = TimeTrustState::Unknown;
        out.sample.reason = TimeReason::PlatformAuthUnverifiable;
        return out;
    }

    // ---- UTC/误差有效 ----
    if (!f.utc_valid || !f.uncertainty_valid) {
        out.sample.trust_state = TimeTrustState::Unknown;
        out.sample.reason = TimeReason::PlatformContractIncomplete;
        return out;
    }

    // ---- 有效年龄（含本跳 RTT 与本地流逝；只扣一次）----
    const int64_t now_boot = cfg_.boot_clock ? cfg_.boot_clock() : bootNowMs();
    const int64_t elapsed = std::max<int64_t>(0, now_boot - f.received_boot_ms);
    const int64_t age_eff = f.freshness_age_ms + f.rtt_ms + elapsed;
    const int64_t u_eff =
        f.uncertainty_ms + f.drift_bound_ppm * age_eff / 1000000;
    const int64_t remain = f.remaining_validity_ms - f.rtt_ms - elapsed;
    // UTC 估计推进到当前参考时刻（有可信增长界才外推；contractComplete 已保证 drift>0）
    const int64_t utc_eff = f.utc_epoch_ms + age_eff;

    // ---- 门限 ----
    if (age_eff > cfg_.max_freshness.count()) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::PlatformTooOld;
        return out;
    }
    if (u_eff > cfg_.max_uncertainty.count()) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::PlatformUncertaintyTooHigh;
        return out;
    }

    // ---- 回拨保护（CR-017 §4.3）----
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (has_lkg_ &&
            utc_eff <
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    last_known_good_.time_since_epoch())
                        .count() -
                    cfg_.rollback_tolerance.count()) {
            out.sample.trust_state = TimeTrustState::Untrusted;
            out.sample.reason = TimeReason::PlatformRollbackDetected;
            return out;
        }
    }

    // ---- 短租约（CR-024 §4）：≤ min(lease_max, 剩余有效期, freshness/uncertainty 预算) ----
    const int64_t freshness_budget = cfg_.max_freshness.count() - age_eff;
    const int64_t uncertainty_budget = cfg_.max_uncertainty.count() - u_eff;
    const int64_t lease =
        std::max<int64_t>(0, std::min(cfg_.lease_max.count(),
                                      std::min(remain, std::min(freshness_budget,
                                                               uncertainty_budget))));
    if (lease <= 0) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::PlatformValidityExpired;
        return out;
    }

    // ---- Trusted ----
    out.sample.trust_state = TimeTrustState::Trusted;
    out.sample.reason = TimeReason::PlatformSynced;
    out.sample.utc_now =
        std::chrono::system_clock::time_point(std::chrono::milliseconds(utc_eff));
    out.sample.freshness_age = std::chrono::milliseconds(age_eff);
    out.sample.uncertainty = std::chrono::milliseconds(u_eff);
    out.remaining_validity_ms = lease;
    return out;
}

TrustedTimeResult CompositeTrustedTimeProvider::gateHardwareRtc(
    const TrustedTimeSample& s) noexcept {
    TrustedTimeResult out;
    out.sample = s;
    out.contract_complete = false;
    if (out.sample.trust_state != TimeTrustState::Trusted) return out;
    if (out.sample.source != TimeSource::HardwareRtc) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::PlatformMalformed;
        return out;
    }
    // RTC 不套用 300s freshness（CR-017 §4.2），但 uncertainty 仍需受限
    if (cfg_.hw_rtc_require_provisioned &&
        out.sample.reason != TimeReason::RtcProvisioned) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::RtcNotProvisioned;
        return out;
    }
    if (out.sample.uncertainty.count() > cfg_.max_uncertainty.count()) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::RtcNotHealthy;
        return out;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (has_lkg_ &&
            out.sample.utc_now < last_known_good_ - cfg_.rollback_tolerance) {
            out.sample.trust_state = TimeTrustState::Untrusted;
            out.sample.reason = TimeReason::RtcRollbackDetected;
            return out;
        }
    }
    // RTC 租约：不机械套用平台 300s；用 uncertainty 预算 + 上限
    const int64_t u = out.sample.uncertainty.count();
    const int64_t lease = std::max<int64_t>(
        0, std::min(cfg_.lease_max.count(), cfg_.max_uncertainty.count() - u));
    if (lease <= 0) {
        out.sample.trust_state = TimeTrustState::Untrusted;
        out.sample.reason = TimeReason::RtcNotHealthy;
        return out;
    }
    out.remaining_validity_ms = lease;
    return out;
}

void CompositeTrustedTimeProvider::acceptAsKnownGood(
    const TrustedTimeSample& s) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (!has_lkg_ || s.utc_now > last_known_good_) {
        last_known_good_ = s.utc_now;
    }
    has_lkg_ = true;
    if (!has_epoch_ || s.source_epoch != last_epoch_) {
        last_epoch_ = s.source_epoch;
    }
    has_epoch_ = true;
}

// ============================================================================
// PlatformTimeAdapter（CR-017 §7 占位 → CR-024 真实 TIME client 接入）
// ============================================================================

PlatformTimeAdapter::PlatformTimeAdapter(std::shared_ptr<TimeSourceClient> client,
                                         std::function<int64_t()> boot_clock)
    : client_(std::move(client)), boot_clock_(std::move(boot_clock)) {}

bool PlatformTimeAdapter::connect() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (!client_) return false;
    if (!client_->connect()) return false;
    connection_generation_++;
    ever_connected_ = true;
    return true;
}

void PlatformTimeAdapter::disconnect() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (client_) client_->disconnect();
}

bool PlatformTimeAdapter::is_connected() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return client_ && client_->is_connected();
}

uint64_t PlatformTimeAdapter::connection_generation() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return connection_generation_;
}

std::shared_ptr<void> PlatformTimeAdapter::subscribe(std::function<void()> on_change) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!client_) return nullptr;
    auto forward = [on_change](const tbox::time::TimeStateEvent&) {
        if (on_change) on_change();
    };
    return client_->subscribe_state_changed(std::move(forward));
}

TimeFactSnapshot PlatformTimeAdapter::mapSnapshot(
    const tbox::time::TimeSnapshot& snap, int64_t rtt_ms) noexcept {
    TimeFactSnapshot f;
    f.received_boot_ms = boot_clock_ ? boot_clock_() : bootNowMs();
    f.rtt_ms = std::max<int64_t>(0, rtt_ms);
    f.transport_ok = true;
    f.validated = snap.validate();
    f.contract_version = snap.contract_version;
    f.capabilities = snap.capabilities;
    f.time_daemon_epoch = snap.daemon_epoch;
    f.time_event_sequence = snap.event_sequence;
    f.state = mapState(snap.state);
    f.source_id = snap.source_id;
    f.source_kind = mapKind(snap.source_kind);
    f.source_epoch = snap.source_epoch;
    f.utc_valid = snap.utc_valid;
    f.utc_epoch_ms = snap.utc_epoch_ms;
    f.system_clock_aligned = snap.system_clock_aligned;
    f.alignment_error_ms = snap.alignment_error_ms;
    f.freshness_age_ms = snap.freshness_age_ms;
    f.uncertainty_valid = snap.uncertainty_valid;
    f.uncertainty_ms = snap.uncertainty_ms;
    f.remaining_validity_ms = snap.remaining_validity_ms;
    f.drift_bound_ppm = snap.drift_bound_ppm;
    f.auth_status = mapAuth(snap.auth_status);
    f.evidence_ref = snap.evidence_ref;
    f.policy_version = snap.policy_version;
    f.contract_complete = contractComplete(f);
    return f;
}

TimeFactSnapshot PlatformTimeAdapter::query() noexcept {
    TimeFactSnapshot f;
    f.received_boot_ms = boot_clock_ ? boot_clock_() : bootNowMs();
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!client_ || !client_->is_connected()) {
            f.transport_ok = false;
            f.validated = false;
            f.error_detail = "time client not connected";
            return f;
        }
    }
    const auto r = client_->get_time_snapshot();
    switch (r.error) {
        case TimeSourceClient::QueryResult::Error::kOk:
        case TimeSourceClient::QueryResult::Error::kTimeUnavailable:
            // 时间不可用仍返回明确快照（状态语义由 Composite 判定）
            return mapSnapshot(r.snapshot, r.rtt_ms);
        case TimeSourceClient::QueryResult::Error::kUnsupported:
            // 版本/能力不支持：契约缺口 → Unknown(PlatformContractIncomplete)
            f.transport_ok = true;
            f.validated = false;
            f.contract_complete = false;
            f.error_detail = "time contract unsupported";
            return f;
        case TimeSourceClient::QueryResult::Error::kServiceUnreachable:
        case TimeSourceClient::QueryResult::Error::kTimeout:
        case TimeSourceClient::QueryResult::Error::kInvalidData:
        case TimeSourceClient::QueryResult::Error::kInternalError:
        default:
            f.transport_ok = false;
            f.validated = false;
            f.error_detail = "time query failed";
            return f;
    }
}

// ============================================================================
// HardwareRtcAdapter（CR-017 §7 占位实现）
//
// 平台 RTC 证据（provision 标记/健康/回拨检查）落地前固定返回不可用，
// 确保生产 fail-closed、绝不回退墙钟。CR-024 保持：RTC 缺证据不得 Trusted。
// ============================================================================

TrustedTimeSample HardwareRtcAdapter::query() noexcept {
    TrustedTimeSample s;
    s.trust_state = TimeTrustState::Untrusted;
    s.source = TimeSource::HardwareRtc;
    s.reason = TimeReason::RtcInterfaceUnavailable;
    return s;
}

// ============================================================================
// TrustedTimeMonitor（CR-024 §5/§6）
// ============================================================================

struct TrustedTimeMonitor::SubSlot {
    std::function<void(const TrustedTimeResult&)> cb;
};

TrustedTimeMonitor::TrustedTimeMonitor(PlatformTimeAdapter* platform,
                                       HardwareRtcSource* hw_rtc,
                                       TrustedTimeConfig cfg)
    : platform_(platform),
      hw_rtc_(hw_rtc),
      cfg_(cfg),
      composite_(std::make_shared<CompositeTrustedTimeProvider>(platform, hw_rtc,
                                                                cfg)) {
    // SEC 实例标识（重启改变；非安全秘密，作查询 token 基准）
    sec_daemon_epoch_ = 1 + static_cast<uint64_t>(bootNowMs());
}

TrustedTimeMonitor::~TrustedTimeMonitor() { stop(); }

bool TrustedTimeMonitor::start() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (running_) return true;
    tokens_invalidated_ = false;
    running_ = true;
    // 不在 start 时阻塞连接：TIME 未运行不影响 SEC 启动（非时间能力保持运行），
    // 由监测循环按 2s 间隔有界重试连接（CR-024 §5/§8）。
    loop_thread_ = std::thread([this]() { runLoop(); });
    return true;
}

void TrustedTimeMonitor::stop() noexcept {
    std::thread t;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (running_) {
            running_ = false;
            tokens_invalidated_ = true;   // 失效查询 token
            has_cached_ = false;          // 撤销缓存
            time_sub_.reset();            // 取消 TIME 订阅
        } else {
            tokens_invalidated_ = true;
            has_cached_ = false;
        }
    }
    if (loop_thread_.joinable()) loop_thread_.join();
    if (platform_) platform_->disconnect();  // 关闭 client（有界）
}

int64_t TrustedTimeMonitor::nowBootMs() const noexcept {
    return cfg_.boot_clock ? cfg_.boot_clock() : bootNowMs();
}

void TrustedTimeMonitor::refresh_now() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    refresh_pending_ = true;
}

std::shared_ptr<TrustedTimeProvider> TrustedTimeMonitor::provider() const noexcept {
    return composite_;
}

uint64_t TrustedTimeMonitor::sec_daemon_epoch() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return sec_daemon_epoch_;
}

std::shared_ptr<void> TrustedTimeMonitor::subscribe(
    std::function<void(const TrustedTimeResult&)> cb) {
    auto slot = std::make_shared<SubSlot>();
    slot->cb = std::move(cb);
    std::lock_guard<std::mutex> lk(mu_);
    subscribers_.push_back(slot);
    return slot;
}

void TrustedTimeMonitor::runLoop() noexcept {
    while (true) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_) break;
            const int64_t now = nowBootMs();
            // 连接管理：TIME 未连接 → 有界重试（2s）；连接/重连后重建订阅并立即刷新
            if (cfg_.platform_enabled && platform_) {
                if (!platform_->is_connected()) {
                    if (now - last_connect_attempt_ms_ >= 2000) {
                        last_connect_attempt_ms_ = now;
                        if (platform_->connect()) {
                            connection_generation_ =
                                platform_->connection_generation();
                            time_sub_ = platform_->subscribe(
                                [this]() { refresh_now(); });
                            refresh_pending_ = true;
                        }
                    }
                } else if (!time_sub_) {
                    time_sub_ =
                        platform_->subscribe([this]() { refresh_now(); });
                    refresh_pending_ = true;
                }
            }
            if (refresh_pending_) {
                refresh_pending_ = false;
                refreshLocked();
            } else if (now - last_refresh_boot_ms_ >=
                       cfg_.monitor_refresh_interval.count()) {
                refreshLocked();  // 正常监测/提前刷新（无人查询也运行）
            } else if (has_cached_ &&
                       cached_.sample.trust_state == TimeTrustState::Trusted &&
                       now - last_refresh_boot_ms_ >=
                           cached_.remaining_validity_ms) {
                revokeLocked(TimeReason::TimeExpired);  // 到期撤销（仅对有效缓存）
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void TrustedTimeMonitor::refreshLocked() noexcept {
    const int64_t now = nowBootMs();
    TrustedTimeResult r = composite_->query();
    r.sec_daemon_epoch = sec_daemon_epoch_;
    r.sec_time_event_sequence = sec_time_event_sequence_;
    // 到期/不可信：无人查询也撤销旧有效状态
    if (r.sample.trust_state == TimeTrustState::Trusted &&
        r.remaining_validity_ms <= 0) {
        r.sample.trust_state = TimeTrustState::Untrusted;
        r.sample.reason = TimeReason::PlatformValidityExpired;
        r.remaining_validity_ms = 0;
    }
    has_cached_ = true;
    last_refresh_boot_ms_ = now;
    cached_ = r;
    publishIfChangedLocked(r);
}

void TrustedTimeMonitor::revokeLocked(TimeReason reason) noexcept {
    const int64_t now = nowBootMs();
    TrustedTimeResult r = cached_;
    r.sample.trust_state = TimeTrustState::Untrusted;
    r.sample.reason = reason;
    r.remaining_validity_ms = 0;
    r.sec_daemon_epoch = sec_daemon_epoch_;
    r.sec_time_event_sequence = sec_time_event_sequence_;
    has_cached_ = true;
    last_refresh_boot_ms_ = now;
    cached_ = r;
    publishIfChangedLocked(r);
}

namespace {

/// 仅信任/来源/代次/对齐/契约变化才发事件（高频数值不逐次广播）。
bool factChanged(const TrustedTimeResult& a, const TrustedTimeResult& b) {
    return a.sample.trust_state != b.sample.trust_state ||
           a.sample.source != b.sample.source ||
           a.source_id != b.source_id ||
           a.sample.source_epoch != b.sample.source_epoch ||
           a.time_daemon_epoch != b.time_daemon_epoch ||
           a.system_clock_aligned != b.system_clock_aligned ||
           a.contract_version != b.contract_version ||
           a.sample.reason != b.sample.reason;
}

}  // namespace

void TrustedTimeMonitor::publishIfChangedLocked(
    const TrustedTimeResult& r) noexcept {
    if (has_published_ && !factChanged(last_published_, r)) {
        return;  // 无事实变化：不递增序列、不广播
    }
    sec_time_event_sequence_++;
    last_published_ = r;
    last_published_.sec_time_event_sequence = sec_time_event_sequence_;
    has_published_ = true;
    // 通知订阅者（拷贝结果，回调不得持有锁）
    std::vector<std::shared_ptr<SubSlot>> slots;
    slots.reserve(subscribers_.size());
    for (auto& w : subscribers_) {
        if (auto s = w.lock()) slots.push_back(s);
    }
    for (auto& s : slots) {
        if (s->cb) s->cb(last_published_);
    }
}

TrustedTimeResult TrustedTimeMonitor::get(uint64_t request_token) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    // 请求 token 拒绝迟到响应（SEC 重启/停机后旧 token）
    if (request_token != 0 &&
        (request_token != sec_daemon_epoch_ || tokens_invalidated_)) {
        TrustedTimeResult r;
        r.sample.trust_state = TimeTrustState::Unknown;
        r.sample.source = TimeSource::None;
        r.sample.reason = TimeReason::PlatformMalformed;
        r.sec_daemon_epoch = sec_daemon_epoch_;
        r.error_class = "stale";
        return r;
    }
    if (!has_cached_) {
        refreshLocked();
    }
    TrustedTimeResult r = cached_;
    // 扣减本地流逝：租约参考时刻 = last_refresh_boot_ms_（只扣一次）
    if (r.sample.trust_state == TimeTrustState::Trusted) {
        const int64_t elapsed = std::max<int64_t>(0, nowBootMs() - last_refresh_boot_ms_);
        r.remaining_validity_ms = cached_.remaining_validity_ms - elapsed;
        if (r.remaining_validity_ms <= 0) {
            r.sample.trust_state = TimeTrustState::Untrusted;
            r.sample.reason = TimeReason::TimeExpired;
            r.remaining_validity_ms = 0;
        }
    }
    return r;
}

// ============================================================================
// FakeTrustedTimeProvider（dev/test only）
// ============================================================================

FakeTrustedTimeProvider::FakeTrustedTimeProvider(TrustedTimeSample sample,
                                                 bool track_wall_clock)
    : sample_(sample), track_wall_clock_(track_wall_clock) {}

TrustedTimeSample FakeTrustedTimeProvider::now() noexcept {
    if (!track_wall_clock_) return sample_;
    // dev/test 车端 profile：当前墙钟即注入事实。不固定为进程启动瞬间的墙钟
    // （CR-024 AT-11 坏初始时钟 bootstrap：启动快照会被一次 NTP 调时作废）。
    TrustedTimeSample s = sample_;
    s.utc_now = std::chrono::system_clock::now();
    s.freshness_age = std::chrono::milliseconds(0);
    // 只刷新墙钟事实，不提升信任状态（注入样本的 trust/reason 保持不变）
    return s;
}

void FakeTrustedTimeProvider::set_now(TrustedTimeSample sample) noexcept {
    sample_ = sample;
}

// ============================================================================
// FakeTrustedTimeSnapshotSource（dev/test only，CR-024 §4/§6 契约）
// ============================================================================

struct FakeTrustedTimeSnapshotSource::SubSlot {
    std::function<void(const TrustedTimeResult&)> cb;
};

FakeTrustedTimeSnapshotSource::FakeTrustedTimeSnapshotSource(
    std::shared_ptr<TrustedTimeProvider> provider, TrustedTimeConfig cfg)
    : provider_(std::move(provider)), cfg_(std::move(cfg)) {}

uint64_t FakeTrustedTimeSnapshotSource::sec_daemon_epoch() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return sec_daemon_epoch_;
}

TrustedTimeResult FakeTrustedTimeSnapshotSource::snapshotLocked() noexcept {
    TrustedTimeResult r;
    // 契约/能力与生产 monitor 的 wire 语义保持一致（MQTT 侧只认契约，不认实现）
    r.contract_version = 1;
    r.capabilities = "snapshot,v1";
    r.contract_complete = true;
    r.sec_daemon_epoch = sec_daemon_epoch_;
    r.sec_time_event_sequence = sec_time_event_sequence_;
    r.source_id = "dev-test-fake";
    r.source_kind = TimeSourceKind::None;
    r.policy_version = "dev_test_fake";
    r.drift_bound_ppm = 0;
    // 执行时钟对齐：fake 样本本身就取自墙钟，故与自身对齐误差为零。
    r.system_clock_aligned = true;
    r.alignment_error_ms = 0;
    // 不伪造认证证据：fake 仍标记 unverified，避免被误读为已认证来源。
    r.auth_status = TimeAuthStatus::Unverified;
    r.evidence_ref = "dev_test_fake_profile";
    if (provider_) {
        r.sample = provider_->now();
    }
    r.sample.source = TimeSource::FakeTest;
    r.sample.source_epoch = 1;
    r.sample.freshness_age = std::chrono::milliseconds(0);
    r.sample.uncertainty = std::chrono::milliseconds(0);
    r.utc_valid = true;
    if (r.sample.trust_state == TimeTrustState::Trusted) {
        r.sample.reason = TimeReason::FakeTest;
        // 短租约：fake 无外部事实来源，按 lease_max 每次查询现算（§4）。
        r.remaining_validity_ms = std::max<int64_t>(0, cfg_.lease_max.count());
    } else {
        // 注入样本失信：如实报告业务状态，不授权。
        r.remaining_validity_ms = 0;
    }
    return r;
}

void FakeTrustedTimeSnapshotSource::publishIfChangedLocked(
    const TrustedTimeResult& r) noexcept {
    if (has_published_ && !factChanged(last_published_, r)) {
        return;  // 无事实变化：不递增序列、不广播
    }
    sec_time_event_sequence_++;
    last_published_ = r;
    last_published_.sec_time_event_sequence = sec_time_event_sequence_;
    has_published_ = true;
    std::vector<std::shared_ptr<SubSlot>> slots;
    slots.reserve(subscribers_.size());
    for (auto& w : subscribers_) {
        if (auto s = w.lock()) slots.push_back(s);
    }
    for (auto& s : slots) {
        if (s->cb) s->cb(last_published_);
    }
}

bool FakeTrustedTimeSnapshotSource::start() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (running_) return true;
    running_ = true;
    tokens_invalidated_ = false;
    if (sec_daemon_epoch_ == 0) {
        sec_daemon_epoch_ = 1 + static_cast<uint64_t>(bootNowMs());
    }
    TrustedTimeResult r = snapshotLocked();
    publishIfChangedLocked(r);  // 首帧：事件订阅握手基线
    return true;
}

void FakeTrustedTimeSnapshotSource::stop() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    running_ = false;
    tokens_invalidated_ = true;  // 失效查询 token
    subscribers_.clear();
}

TrustedTimeResult FakeTrustedTimeSnapshotSource::get(
    uint64_t request_token) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    // 请求 token 拒绝迟到响应（SEC 重启/停机后旧 token）——与 monitor 同语义
    if (request_token != 0 &&
        (request_token != sec_daemon_epoch_ || tokens_invalidated_)) {
        TrustedTimeResult r;
        r.sample.trust_state = TimeTrustState::Unknown;
        r.sample.source = TimeSource::None;
        r.sample.reason = TimeReason::PlatformMalformed;
        r.sec_daemon_epoch = sec_daemon_epoch_;
        r.error_class = "stale";
        return r;
    }
    TrustedTimeResult r = snapshotLocked();
    publishIfChangedLocked(r);
    r.sec_time_event_sequence = sec_time_event_sequence_;
    return r;
}

std::shared_ptr<void> FakeTrustedTimeSnapshotSource::subscribe(
    std::function<void(const TrustedTimeResult&)> cb) {
    auto slot = std::make_shared<SubSlot>();
    slot->cb = std::move(cb);
    std::lock_guard<std::mutex> lk(mu_);
    subscribers_.push_back(slot);
    return slot;
}

// ============================================================================
// 稳定字符串化（日志脱敏字段 / wire 稳定符号）
// ============================================================================

const char* timeTrustStateToString(TimeTrustState s) noexcept {
    switch (s) {
        case TimeTrustState::Trusted: return "trusted";
        case TimeTrustState::Untrusted: return "untrusted";
        case TimeTrustState::Unknown: return "unknown";
    }
    return "unknown";
}

const char* timeSourceToString(TimeSource s) noexcept {
    switch (s) {
        case TimeSource::PlatformSync: return "platform_sync";
        case TimeSource::HardwareRtc: return "hardware_rtc";
        case TimeSource::FakeTest: return "fake_test";
        case TimeSource::None: return "none";
    }
    return "none";
}

const char* timeReasonToString(TimeReason r) noexcept {
    switch (r) {
        case TimeReason::PlatformSynced: return "platform_synced";
        case TimeReason::PlatformNotSynchronized: return "platform_not_synchronized";
        case TimeReason::PlatformNotAuthenticated: return "platform_not_authenticated";
        case TimeReason::PlatformAuthUnverifiable: return "platform_auth_unverifiable";
        case TimeReason::PlatformContractIncomplete: return "platform_contract_incomplete";
        case TimeReason::PlatformTooOld: return "platform_too_old";
        case TimeReason::PlatformUncertaintyTooHigh: return "platform_uncertainty_too_high";
        case TimeReason::PlatformRollbackDetected: return "platform_rollback_detected";
        case TimeReason::PlatformValidityExpired: return "platform_validity_expired";
        case TimeReason::PlatformInterfaceUnavailable: return "platform_interface_unavailable";
        case TimeReason::PlatformMalformed: return "platform_malformed";
        case TimeReason::RtcProvisioned: return "rtc_provisioned";
        case TimeReason::RtcNotProvisioned: return "rtc_not_provisioned";
        case TimeReason::RtcNotHealthy: return "rtc_not_healthy";
        case TimeReason::RtcOutOfRange: return "rtc_out_of_range";
        case TimeReason::RtcRollbackDetected: return "rtc_rollback_detected";
        case TimeReason::RtcReadError: return "rtc_read_error";
        case TimeReason::RtcInterfaceUnavailable: return "rtc_interface_unavailable";
        case TimeReason::NoSourceAvailable: return "no_source_available";
        case TimeReason::TimeExpired: return "time_expired";
        case TimeReason::FakeTest: return "fake_test";
    }
    return "no_source_available";
}

const char* timeSyncStateToString(TimeSyncState s) noexcept {
    switch (s) {
        case TimeSyncState::Unsynch: return "unsynchronized";
        case TimeSyncState::Syncing: return "synchronizing";
        case TimeSyncState::Synced: return "synchronized";
        case TimeSyncState::Holdover: return "holdover";
        case TimeSyncState::Fault: return "fault";
    }
    return "unsynchronized";
}

const char* timeSourceKindToString(TimeSourceKind k) noexcept {
    switch (k) {
        case TimeSourceKind::None: return "none";
        case TimeSourceKind::NtpNetwork: return "ntp_network";
        case TimeSourceKind::Cellular: return "cellular";
        case TimeSourceKind::Gnss: return "gnss";
        case TimeSourceKind::HardwareRtc: return "hardware_rtc";
    }
    return "none";
}

const char* timeAuthStatusToString(TimeAuthStatus a) noexcept {
    switch (a) {
        case TimeAuthStatus::Unknown: return "unknown";
        case TimeAuthStatus::Unverified: return "unverified";
        case TimeAuthStatus::Verified: return "verified";
        case TimeAuthStatus::Failed: return "failed";
    }
    return "unknown";
}

} // namespace sec
} // namespace tbox

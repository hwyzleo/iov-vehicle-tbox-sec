//
// TBOX-SEC-DSN-CR-017：可信时间生产契约实现。
//
// CompositeTrustedTimeProvider 为 production 唯一可信时间注入点：
// 平台同步时间 → 硬件 RTC；freshness（单调计龄）/uncertainty/回拨保护全部
// fail-closed。真实平台/RTC 后端为平台团队阻塞项（CR-017 §9），未落地前
// PlatformTimeAdapter / HardwareRtcAdapter 返回不可用 → 注入 fail-closed。
//

#include "trusted_time.h"

namespace tbox {
namespace sec {

// ============================================================================
// CompositeTrustedTimeProvider
// ============================================================================

CompositeTrustedTimeProvider::CompositeTrustedTimeProvider(
    PlatformTimeSource* platform, HardwareRtcSource* hw_rtc,
    TrustedTimeConfig cfg)
    : platform_(platform), hw_rtc_(hw_rtc), cfg_(cfg) {}

TrustedTimeSample CompositeTrustedTimeProvider::now() noexcept {
    // 按优先级尝试平台 → RTC；失败原因取最近尝试来源（日志可判定/可行动）。
    TrustedTimeSample fallback;
    fallback.trust_state = TimeTrustState::Untrusted;
    fallback.reason = TimeReason::NoSourceAvailable;
    fallback.source = TimeSource::None;

    if (cfg_.platform_enabled && platform_) {
        TrustedTimeSample s = platform_->query();
        TrustedTimeSample g = gatePlatform(s);
        if (g.trust_state == TimeTrustState::Trusted) {
            acceptAsKnownGood(g);
            return g;
        }
        fallback = g;
    }

    if (cfg_.hw_rtc_enabled && hw_rtc_) {
        TrustedTimeSample s = hw_rtc_->query();
        TrustedTimeSample g = gateHardwareRtc(s);
        if (g.trust_state == TimeTrustState::Trusted) {
            acceptAsKnownGood(g);
            return g;
        }
        // 仅当 RTC 失败原因更具体时覆盖平台失败原因
        // （generic NoSourceAvailable 不掩盖平台的 PlatformTooOld 等具体原因）
        if (g.reason != TimeReason::NoSourceAvailable ||
            fallback.reason == TimeReason::NoSourceAvailable) {
            fallback = g;
        }
    }

    return fallback;
}

TrustedTimeSample CompositeTrustedTimeProvider::gatePlatform(
    const TrustedTimeSample& s) const noexcept {
    TrustedTimeSample out = s;
    if (out.trust_state != TimeTrustState::Trusted) return out;  // 来源已判不可信
    if (out.source != TimeSource::PlatformSync) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::PlatformMalformed;
        return out;
    }
    // 单调计龄（CR-017 §4.1）：freshness_age 由来源侧 steady_clock 计算
    if (out.freshness_age > cfg_.max_freshness) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::PlatformTooOld;
        return out;
    }
    if (out.uncertainty > cfg_.max_uncertainty) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::PlatformUncertaintyTooHigh;
        return out;
    }
    // 回拨保护（CR-017 §4.3）
    std::lock_guard<std::mutex> lk(mu_);
    if (has_lkg_ && out.utc_now < last_known_good_ - cfg_.rollback_tolerance) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::PlatformRollbackDetected;
        return out;
    }
    return out;
}

TrustedTimeSample CompositeTrustedTimeProvider::gateHardwareRtc(
    const TrustedTimeSample& s) const noexcept {
    TrustedTimeSample out = s;
    if (out.trust_state != TimeTrustState::Trusted) return out;
    if (out.source != TimeSource::HardwareRtc) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::PlatformMalformed;
        return out;
    }
    // RTC 不套用 300s freshness（CR-017 §4.2），但 uncertainty 仍需受限
    if (cfg_.hw_rtc_require_provisioned &&
        out.reason != TimeReason::RtcProvisioned) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::RtcNotProvisioned;
        return out;
    }
    if (out.uncertainty > cfg_.max_uncertainty) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::RtcNotHealthy;
        return out;
    }
    std::lock_guard<std::mutex> lk(mu_);
    if (has_lkg_ && out.utc_now < last_known_good_ - cfg_.rollback_tolerance) {
        out.trust_state = TimeTrustState::Untrusted;
        out.reason = TimeReason::RtcRollbackDetected;
        return out;
    }
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
// PlatformTimeAdapter / HardwareRtcAdapter（CR-017 §7 占位实现）
//
// 平台时间服务 / 硬件 RTC 真实查询后端为平台团队实施前阻塞项（CR-017 §9），
// 未落地前固定返回不可用，确保生产证书注入 fail-closed、绝不回退墙钟。
// ============================================================================

TrustedTimeSample PlatformTimeAdapter::query() noexcept {
    TrustedTimeSample s;
    s.trust_state = TimeTrustState::Untrusted;
    s.source = TimeSource::PlatformSync;
    s.reason = TimeReason::PlatformInterfaceUnavailable;
    return s;
}

TrustedTimeSample HardwareRtcAdapter::query() noexcept {
    TrustedTimeSample s;
    s.trust_state = TimeTrustState::Untrusted;
    s.source = TimeSource::HardwareRtc;
    s.reason = TimeReason::RtcInterfaceUnavailable;
    return s;
}

// ============================================================================
// FakeTrustedTimeProvider（dev/test only）
// ============================================================================

FakeTrustedTimeProvider::FakeTrustedTimeProvider(TrustedTimeSample sample)
    : sample_(sample) {}

TrustedTimeSample FakeTrustedTimeProvider::now() noexcept { return sample_; }

void FakeTrustedTimeProvider::set_now(TrustedTimeSample sample) noexcept {
    sample_ = sample;
}

// ============================================================================
// 稳定字符串化（日志脱敏字段）
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
        case TimeReason::PlatformTooOld: return "platform_too_old";
        case TimeReason::PlatformUncertaintyTooHigh: return "platform_uncertainty_too_high";
        case TimeReason::PlatformRollbackDetected: return "platform_rollback_detected";
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
        case TimeReason::FakeTest: return "fake_test";
    }
    return "no_source_available";
}

} // namespace sec
} // namespace tbox

//
// TBOX-SEC-DSN-CR-017 / TBOX-SEC-DSN-CR-024：CompositeTrustedTimeProvider 单元测试。
//
// CR-017 覆盖：来源优先级、freshness（300s 缺省门限）、uncertainty 上限、回拨保护、
// 来源切换、RTC 不套用 freshness、fail-closed（无来源/双失败）。
//
// CR-024 覆盖（验收矩阵 AT-01/02/03/04/06/07）：
//   - 未认证 NTP（unverified/failed）即使 SYNCHRONIZED 仍 Untrusted（AT-01）；
//   - verified 必须绑定已批准策略/证据/来源，否则 Unknown（AT-02）；
//   - 契约不完整/缺漂移增长界 → Unknown(PlatformContractIncomplete)（AT-02）；
//   - HOLDOVER/UNSYNCHRONIZED 不满足平台 synchronized → Untrusted 后走 RTC（AT-06）；
//   - freshness=300s/300s+1ms、uncertainty=2s/2s+1ms、租约≤1000ms 且≤0 不授权（AT-03）；
//   - 单跳 RTT/本地流逝只扣一次，UTC 推进、uncertainty 含漂移增长（AT-04）；
//   - source_trusted 与 system_clock_aligned 分离（AT-07）。
//

#include <gtest/gtest.h>

#include "trusted_time.h"

#include <chrono>

using namespace tbox::sec;
using namespace std::chrono_literals;

namespace {

// 固定测试单调钟（BOOTTIME 语义）；事实的 received_boot_ms 与 cfg.boot_clock 一致，
// 使 age_eff = freshness_age + rtt + 0（elapsed 可控）。
constexpr int64_t kTestBootMs = 1'000'000;

constexpr int64_t kUtcBase = 1'700'000'000'000;  // epoch 毫秒（UTC 基准）

class FakePlatformSource final : public PlatformTimeSource {
public:
    TimeFactSnapshot next;
    TimeFactSnapshot query() noexcept override { return next; }
};

class FakeRtcSource final : public HardwareRtcSource {
public:
    TrustedTimeSample next;
    TrustedTimeSample query() noexcept override { return next; }
};

/// 构造完整可判定、认证绑定的平台事实（CR-024 语义：verified+策略+证据+来源）。
TimeFactSnapshot make_platform(std::chrono::system_clock::time_point utc,
                               std::chrono::milliseconds age,
                               std::chrono::milliseconds uncertainty,
                               uint64_t epoch = 1,
                               TimeAuthStatus auth = TimeAuthStatus::Verified,
                               int64_t remaining_validity = 299'000,
                               TimeSyncState state = TimeSyncState::Synced) {
    TimeFactSnapshot f;
    f.transport_ok = true;
    f.validated = true;
    f.contract_complete = true;
    f.contract_version = 1;
    f.capabilities = "snapshot,v1";
    f.time_daemon_epoch = 1;
    f.time_event_sequence = 1;
    f.state = state;
    f.source_id = "ntp-verified-1";
    f.source_kind = TimeSourceKind::NtpNetwork;
    f.source_epoch = epoch;
    f.utc_valid = true;
    f.utc_epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        utc.time_since_epoch()).count();
    f.system_clock_aligned = true;
    f.alignment_error_ms = 0;
    f.freshness_age_ms = age.count();
    f.uncertainty_valid = true;
    f.uncertainty_ms = uncertainty.count();
    f.remaining_validity_ms = remaining_validity;
    f.drift_bound_ppm = 100;
    f.auth_status = auth;
    f.evidence_ref = auth == TimeAuthStatus::Verified ? "ev:1" : "";
    f.policy_version = "1";
    f.rtt_ms = 0;
    f.received_boot_ms = kTestBootMs;
    return f;
}

TrustedTimeSample make_rtc(std::chrono::system_clock::time_point now,
                           std::chrono::milliseconds uncertainty) {
    TrustedTimeSample s;
    s.utc_now = now;
    s.trust_state = TimeTrustState::Trusted;
    s.source = TimeSource::HardwareRtc;
    s.uncertainty = uncertainty;
    s.reason = TimeReason::RtcProvisioned;
    return s;
}

TrustedTimeSample make_untrusted(TimeReason reason, TimeSource source) {
    TrustedTimeSample s;
    s.trust_state = TimeTrustState::Untrusted;
    s.source = source;
    s.reason = reason;
    return s;
}

TrustedTimeConfig test_cfg() {
    TrustedTimeConfig cfg;
    cfg.boot_clock = [] { return kTestBootMs; };
    cfg.approved_sources = {"ntp-verified-1"};
    return cfg;
}

}  // namespace

// ============================================================================
// CR-017 移植
// ============================================================================

TEST(TrustedTimeTest, PlatformPreferredOverRtc) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1);
    r.next = make_rtc(now + 1s, 0ms);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::PlatformSync);
}

TEST(TrustedTimeTest, FallsBackToRtcWhenPlatformUnavailable) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Unverified);  // 未认证 → 拒
    r.next = make_rtc(now, 0ms);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
}

// 双来源均失败 → fail-closed；失败原因取最可行动的决策性原因（平台 NotAuthenticated
// 不被 RTC 通用不可用覆盖，CR-024 AT-01）
TEST(TrustedTimeTest, BothSourcesFail_LastAttemptedReason) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Unverified);
    r.next = make_untrusted(TimeReason::RtcNotProvisioned, TimeSource::HardwareRtc);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.source, TimeSource::PlatformSync);
    EXPECT_EQ(s.reason, TimeReason::PlatformNotAuthenticated);
}

// 生产缺少可信适配器时 fail-closed（CR-017 §5）
TEST(TrustedTimeTest, NullSourcesFailClosed) {
    CompositeTrustedTimeProvider c(nullptr, nullptr, test_cfg());
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.reason, TimeReason::NoSourceAvailable);
}

// 缺省 freshness 300s（CR-017 §4.1 / CR-024 AT-03 租约边界）：
//   age=299s（预算剩余）→ Trusted；
//   age=300s 恰好 → age 门限通过（非 TooOld）但 freshness 剩余预算耗尽 → 不授权；
//   age=300s+1ms → PlatformTooOld。
TEST(TrustedTimeTest, FreshnessGate) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    TrustedTimeConfig cfg = test_cfg();

    p.next = make_platform(now, 299000ms, 0ms, 1);
    CompositeTrustedTimeProvider c1(&p, &r, cfg);
    EXPECT_EQ(c1.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now, cfg.max_freshness, 0ms, 1);
    CompositeTrustedTimeProvider c2(&p, &r, cfg);
    const auto s2 = c2.now();
    EXPECT_EQ(s2.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s2.reason, TimeReason::PlatformValidityExpired);

    p.next = make_platform(now, cfg.max_freshness + 1ms, 0ms, 1);
    CompositeTrustedTimeProvider c3(&p, &r, cfg);
    const auto s3 = c3.now();
    EXPECT_EQ(s3.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s3.reason, TimeReason::PlatformTooOld);
}

// uncertainty 上限（CR-017 §3/§4.1 / CR-024 AT-03 租约边界）：
//   u=1999（预算剩余）→ Trusted；u=2000 恰好 → 预算耗尽不授权；u=2001 → TooHigh
TEST(TrustedTimeTest, UncertaintyGate) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    TrustedTimeConfig cfg = test_cfg();  // max_uncertainty = 2000ms

    p.next = make_platform(now, 0ms, 1999ms, 1);
    CompositeTrustedTimeProvider c1(&p, &r, cfg);
    EXPECT_EQ(c1.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now, 0ms, cfg.max_uncertainty, 1);
    CompositeTrustedTimeProvider c2(&p, &r, cfg);
    const auto s2 = c2.now();
    EXPECT_EQ(s2.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s2.reason, TimeReason::PlatformValidityExpired);

    p.next = make_platform(now, 0ms, cfg.max_uncertainty + 1ms, 1);
    CompositeTrustedTimeProvider c3(&p, &r, cfg);
    const auto s3 = c3.now();
    EXPECT_EQ(s3.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s3.reason, TimeReason::PlatformUncertaintyTooHigh);
}

// 回拨保护：新 UTC 低于 last-known-good - 容差 → 拒绝（CR-017 §4.3）
TEST(TrustedTimeTest, RollbackRejected) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));

    p.next = make_platform(now, 0ms, 0ms, 1);
    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);

    // 回拨 3s > 缺省 2s 容差
    p.next = make_platform(now - 3s, 0ms, 0ms, 1);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.reason, TimeReason::PlatformRollbackDetected);
}

// RTC 不套用 300s freshness（CR-017 §4.2）：龄期很大仍可信
TEST(TrustedTimeTest, RtcNoFreshnessRequirement) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Unverified);

    r.next = make_rtc(now, 0ms);
    r.next.freshness_age = 999999ms;  // 远大于 300s

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
}

// 来源切换（平台→RTC）时间向前 → 接受（CR-017 §4.3）
TEST(TrustedTimeTest, SourceSwitchForwardAccepted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));

    p.next = make_platform(now, 0ms, 0ms, 1);
    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now, 301000ms, 0ms, 1, TimeAuthStatus::Unverified);
    r.next = make_rtc(now + 1s, 0ms);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
}

// source_epoch 变化（来源重置）但时间向前 → 接受
TEST(TrustedTimeTest, EpochChangeForwardAccepted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));

    p.next = make_platform(now, 0ms, 0ms, 1);
    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now + 1s, 0ms, 0ms, 2);  // 新 epoch，时间向前
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);
}

// 硬件 RTC 信任必须可判定：require_provisioned 时 reason 非 RtcProvisioned 拒绝
// （平台不可用 → RTC 分支；RTC 声称可信但状态不可判定 → RtcNotProvisioned）
TEST(TrustedTimeTest, RtcRequireProvisioned) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = TimeFactSnapshot{};  // 平台传输不可用 → Unknown(PlatformInterfaceUnavailable)

    TrustedTimeConfig cfg = test_cfg();  // hw_rtc_require_provisioned = true
    r.next = make_rtc(now, 0ms);
    r.next.reason = TimeReason::RtcOutOfRange;  // 声称可信但状态不可判定

    CompositeTrustedTimeProvider c(&p, &r, cfg);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.reason, TimeReason::RtcNotProvisioned);
}

// FakeTrustedTimeProvider：时间与属性由测试注入（CR-017 §5/§8）
TEST(TrustedTimeTest, FakeProviderControllable) {
    const auto now = std::chrono::system_clock::now();
    TrustedTimeSample sample;
    sample.utc_now = now;
    sample.trust_state = TimeTrustState::Trusted;
    sample.source = TimeSource::FakeTest;
    sample.reason = TimeReason::FakeTest;

    FakeTrustedTimeProvider fake(sample);
    auto s = fake.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::FakeTest);
    EXPECT_EQ(s.utc_now, now);

    // 可拨回（模拟产线 RTC 场景）
    sample.trust_state = TimeTrustState::Untrusted;
    sample.reason = TimeReason::RtcNotProvisioned;
    fake.set_now(sample);
    EXPECT_EQ(fake.now().trust_state, TimeTrustState::Untrusted);
}

// 字符串化稳定（日志脱敏字段）
TEST(TrustedTimeTest, StableStringification) {
    EXPECT_STREQ(timeTrustStateToString(TimeTrustState::Trusted), "trusted");
    EXPECT_STREQ(timeSourceToString(TimeSource::PlatformSync), "platform_sync");
    EXPECT_STREQ(timeReasonToString(TimeReason::PlatformTooOld), "platform_too_old");
    EXPECT_STREQ(timeReasonToString(TimeReason::NoSourceAvailable), "no_source_available");
    // CR-024 新增稳定符号
    EXPECT_STREQ(timeReasonToString(TimeReason::PlatformNotAuthenticated),
                 "platform_not_authenticated");
    EXPECT_STREQ(timeReasonToString(TimeReason::PlatformContractIncomplete),
                 "platform_contract_incomplete");
    EXPECT_STREQ(timeSyncStateToString(TimeSyncState::Holdover), "holdover");
    EXPECT_STREQ(timeSourceKindToString(TimeSourceKind::NtpNetwork), "ntp_network");
    EXPECT_STREQ(timeAuthStatusToString(TimeAuthStatus::Verified), "verified");
}

// ============================================================================
// CR-024：认证绑定 / 契约完整性 / 状态判定（AT-01/02/06）
// ============================================================================

// AT-01：TIME SYNCHRONIZED + unverified NTP 仍 Untrusted（不提升信任）
TEST(TrustedTimeTest, UnverifiedNtpSyncedStillUntrusted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Unverified);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformNotAuthenticated);
    EXPECT_EQ(s.contract_complete, true);
}

// AT-01：认证失败（failed）→ Untrusted
TEST(TrustedTimeTest, AuthFailedUntrusted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Failed);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    EXPECT_EQ(c.now().reason, TimeReason::PlatformNotAuthenticated);
}

// AT-02：verified 但策略版本未批准 → Unknown（不能只信 auth_status 字符串）
TEST(TrustedTimeTest, VerifiedButUnapprovedPolicyUnknown) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified);
    p.next.policy_version = "9";  // 不在 approved_policy_versions={"1"}

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformAuthUnverifiable);
}

// AT-02：verified 但缺受控证据引用 → Unknown
TEST(TrustedTimeTest, VerifiedWithoutEvidenceUnknown) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified);
    p.next.evidence_ref.clear();

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformAuthUnverifiable);
}

// AT-02：verified 但来源不在已批准列表 → Unknown（生产默认列表空 → 安全离线）
TEST(TrustedTimeTest, VerifiedButUnapprovedSourceUnknown) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified);
    p.next.source_id = "ntp-unapproved";

    TrustedTimeConfig cfg = test_cfg();  // approved_sources={"ntp-verified-1"}
    CompositeTrustedTimeProvider c(&p, &r, cfg);
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformAuthUnverifiable);
}

// AT-02：契约不完整（缺漂移增长界）→ Unknown（不猜值/不外推）
TEST(TrustedTimeTest, ContractIncompleteUnknown) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1);
    p.next.drift_bound_ppm = 0;  // 漂移/误差增长界缺失

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformContractIncomplete);
    EXPECT_EQ(s.contract_complete, false);
}

// AT-02：能力描述缺失 → Unknown
TEST(TrustedTimeTest, CapabilityMissingUnknown) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1);
    p.next.capabilities = "";

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    EXPECT_EQ(c.now().reason, TimeReason::PlatformContractIncomplete);
}

// AT-06：HOLDOVER 不满足平台 SYNCHRONIZED → Untrusted 后尝试 RTC
TEST(TrustedTimeTest, HoldoverNotTrustedThenRtc) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified,
                           0, TimeSyncState::Holdover);

    // 无 RTC → Untrusted(PlatformNotSynchronized)
    CompositeTrustedTimeProvider c1(&p, &r, test_cfg());
    const auto s1 = c1.query();
    EXPECT_EQ(s1.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s1.sample.reason, TimeReason::PlatformNotSynchronized);

    // 有合格 RTC → 平台拒绝分支后才考虑 RTC
    r.next = make_rtc(now, 0ms);
    CompositeTrustedTimeProvider c2(&p, &r, test_cfg());
    const auto s2 = c2.now();
    EXPECT_EQ(s2.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s2.source, TimeSource::HardwareRtc);
}

// AT-06：UNSYNCHRONIZED 不放行
TEST(TrustedTimeTest, UnsynchNotTrusted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified,
                           0, TimeSyncState::Unsynch);
    p.next.utc_valid = false;

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    EXPECT_EQ(c.now().reason, TimeReason::PlatformNotSynchronized);
}

// AT-02：接口不可用（传输层）→ Unknown(PlatformInterfaceUnavailable)
TEST(TrustedTimeTest, TransportUnavailableUnknown) {
    FakePlatformSource p;
    FakeRtcSource r;
    p.next = TimeFactSnapshot{};  // transport_ok=false

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformInterfaceUnavailable);
}

// ============================================================================
// CR-024：租约 / RTT 单跳扣减 / 对齐分离（AT-03/04/07）
// ============================================================================

// AT-03：租约 ≤ min(1000ms, 剩余有效期, freshness/uncertainty 预算)
TEST(TrustedTimeTest, LeaseCappedAt1000) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified, 5'000);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.remaining_validity_ms, 1000);  // 上限 1000ms
}

// AT-03：剩余有效期 < 上限时取较小值
TEST(TrustedTimeTest, LeaseTakesRemainingValidity) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified, 500);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.remaining_validity_ms, 500);
}

// AT-03/04：扣减后 ≤0 不授权（rtt+elapsed 一次性扣减，不重复不遗漏）
TEST(TrustedTimeTest, LeaseExhaustedNotAuthorized) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified, 500);
    p.next.rtt_ms = 200;                       // TIME client 已测（未扣减）
    p.next.received_boot_ms = kTestBootMs - 300;  // SEC 收到 300ms 前

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    // remain = 500 - 200 - 300 = 0 → 不授权
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.sample.reason, TimeReason::PlatformValidityExpired);
}

// AT-04：RTT + 本地流逝进入有效年龄（只扣一次）；UTC 推进；uncertainty 含漂移增长
TEST(TrustedTimeTest, RttAndElapsedAppliedOnce) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 100ms, 50ms, 1, TimeAuthStatus::Verified, 30'000);
    p.next.rtt_ms = 50;
    p.next.received_boot_ms = kTestBootMs - 100;  // elapsed=100

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    ASSERT_EQ(s.sample.trust_state, TimeTrustState::Trusted);
    // age_eff = 100 + 50 + 100 = 250ms
    EXPECT_EQ(s.sample.freshness_age, 250ms);
    // utc 推进 = base + 250ms
    EXPECT_EQ(s.sample.utc_now, now + 250ms);
    // uncertainty 含漂移增长：50 + 100ppm*250ms/1e6 = 50（<1ms 忽略，仍为 50）
    EXPECT_EQ(s.sample.uncertainty, 50ms);
    // 租约 ≤ 1000，且不把 300s 窗口在一跳重置（remain=30000-50-100=29850 → 仍被 1000 封顶）
    EXPECT_LE(s.remaining_validity_ms, 1000);
    EXPECT_GT(s.remaining_validity_ms, 0);
}

// AT-07：来源可信 ≠ 系统钟对齐（Trusted+aligned=false 可并存，消费者不得只查 Trusted）
TEST(TrustedTimeTest, TrustedButClockNotAligned) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1);
    p.next.system_clock_aligned = false;
    p.next.alignment_error_ms = 350;

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    const auto s = c.query();
    EXPECT_EQ(s.sample.trust_state, TimeTrustState::Trusted);  // 来源可信
    EXPECT_EQ(s.system_clock_aligned, false);                   // 墙钟未对齐
    EXPECT_EQ(s.alignment_error_ms, 350);
}

// to_envelope：稳定符号 + valid 语义
TEST(TrustedTimeTest, EnvelopeConversion) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(kUtcBase));
    p.next = make_platform(now, 0ms, 0ms, 1, TimeAuthStatus::Verified, 900);

    CompositeTrustedTimeProvider c(&p, &r, test_cfg());
    TrustedTimeResult res = c.query();
    res.sec_daemon_epoch = 42;
    res.sec_time_event_sequence = 7;
    const auto e = res.to_envelope();
    EXPECT_EQ(e.trust_state, "trusted");
    EXPECT_EQ(e.reason, "platform_synced");
    EXPECT_EQ(e.source_kind, "ntp_network");
    EXPECT_EQ(e.auth_status, "verified");
    EXPECT_EQ(e.sec_daemon_epoch, 42u);
    EXPECT_EQ(e.sec_time_event_sequence, 7u);
    EXPECT_EQ(e.remaining_validity_ms, 900);
    EXPECT_EQ(e.utc_valid, true);
    EXPECT_EQ(e.utc_epoch_ms, kUtcBase);
    EXPECT_EQ(e.valid, true);
    EXPECT_EQ(e.error_class, "");
}

// ============================================================
// CR-024 修订：dev/test fake 只读快照源
//   §4 短租约 / §5 事件与 token / §6 wire 契约；生产隔离由组合根测试覆盖。
// ============================================================

namespace {

TrustedTimeSample make_fake_sample(std::chrono::system_clock::time_point utc) {
    TrustedTimeSample s;
    s.utc_now = utc;
    s.trust_state = TimeTrustState::Trusted;
    s.source = TimeSource::FakeTest;
    s.reason = TimeReason::FakeTest;
    return s;
}

int64_t utc_ms(const TrustedTimeResult& r) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               r.sample.utc_now.time_since_epoch())
        .count();
}

}  // namespace

// 契约字段齐备：MQTT 侧不得判 SampleMalformed/SampleExpired（回归 SEC-8004）
TEST(FakeSnapshotSourceTest, EnvelopeContractComplete) {
    auto provider = std::make_shared<FakeTrustedTimeProvider>(
        make_fake_sample(std::chrono::system_clock::now()), true);
    TrustedTimeConfig cfg;
    FakeTrustedTimeSnapshotSource src(provider, cfg);
    ASSERT_TRUE(src.start());

    const auto r = src.get(0);
    const auto e = r.to_envelope();
    EXPECT_EQ(e.valid, true);
    EXPECT_EQ(e.error_class, "");
    EXPECT_EQ(e.contract_complete, true);
    EXPECT_EQ(e.contract_version, 1u);
    EXPECT_EQ(e.capabilities, "snapshot,v1");
    EXPECT_EQ(e.trust_state, "trusted");
    EXPECT_EQ(e.source, "fake_test");
    EXPECT_EQ(e.reason, "fake_test");
    EXPECT_EQ(e.utc_valid, true);
    EXPECT_EQ(e.uncertainty_valid, true);
    EXPECT_EQ(e.system_clock_aligned, true);
    EXPECT_EQ(e.alignment_error_ms, 0);
    // fake 不得伪造认证证据
    EXPECT_EQ(e.auth_status, "unverified");
    EXPECT_EQ(e.evidence_ref, "dev_test_fake_profile");
    // §4 短租约：≤ lease_max 且 > 0
    EXPECT_GT(e.remaining_validity_ms, 0);
    EXPECT_LE(e.remaining_validity_ms, cfg.lease_max.count());
    EXPECT_GT(e.sec_daemon_epoch, 0u);
}

// 墙钟跟随：UTC ≈ 查询时刻，freshness 恒 0（修掉“启动瞬间固定快照”缺陷）
TEST(FakeSnapshotSourceTest, UtcTracksWallClockNotStartupSnapshot) {
    // 注入一个 10 分钟前的启动快照（模拟坏初始时钟）
    auto provider = std::make_shared<FakeTrustedTimeProvider>(
        make_fake_sample(std::chrono::system_clock::now() - 10min), true);
    TrustedTimeConfig cfg;
    FakeTrustedTimeSnapshotSource src(provider, cfg);
    ASSERT_TRUE(src.start());

    const int64_t before = utc_ms(src.get(0));
    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    EXPECT_LE(std::llabs(now - before), 2000);  // 不是 10 分钟前的旧快照
    EXPECT_EQ(src.get(0).sample.freshness_age.count(), 0);
}

// 静态模式（默认）保持既有夹具的确定性：不以墙钟覆盖注入样本
TEST(FakeSnapshotSourceTest, StaticProviderKeepsInjectedSample) {
    const auto fixed = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(kUtcBase));
    FakeTrustedTimeProvider fixed_provider(make_fake_sample(fixed));
    EXPECT_EQ(fixed_provider.now().utc_now, fixed);

    FakeTrustedTimeProvider wall_provider(make_fake_sample(fixed), true);
    EXPECT_NE(wall_provider.now().utc_now, fixed);
}

// 请求 token：0/当前 daemon_epoch 接受；其他 → stale（valid=false）
TEST(FakeSnapshotSourceTest, TokenSemantics) {
    auto provider = std::make_shared<FakeTrustedTimeProvider>(
        make_fake_sample(std::chrono::system_clock::now()), true);
    FakeTrustedTimeSnapshotSource src(provider);
    ASSERT_TRUE(src.start());
    const uint64_t epoch = src.sec_daemon_epoch();
    ASSERT_GT(epoch, 0u);

    EXPECT_EQ(src.get(0).to_envelope().valid, true);
    EXPECT_EQ(src.get(epoch).to_envelope().valid, true);

    const auto stale = src.get(epoch + 1);
    EXPECT_EQ(stale.to_envelope().valid, false);
    EXPECT_EQ(stale.to_envelope().error_class, "stale");
    EXPECT_EQ(stale.sample.trust_state, TimeTrustState::Unknown);
}

// stop() 后 token 失效且不再授权（CR-024 §5 生命周期）
TEST(FakeSnapshotSourceTest, StopInvalidatesToken) {
    auto provider = std::make_shared<FakeTrustedTimeProvider>(
        make_fake_sample(std::chrono::system_clock::now()), true);
    FakeTrustedTimeSnapshotSource src(provider);
    ASSERT_TRUE(src.start());
    const uint64_t epoch = src.sec_daemon_epoch();
    src.stop();

    const auto r = src.get(epoch);
    EXPECT_EQ(r.to_envelope().valid, false);
    EXPECT_EQ(r.to_envelope().error_class, "stale");
}

// 事件：start 发布首帧；高频查询不递增序列（事实未变）
TEST(FakeSnapshotSourceTest, EventSequenceOnlyOnFactChange) {
    auto provider = std::make_shared<FakeTrustedTimeProvider>(
        make_fake_sample(std::chrono::system_clock::now()), true);
    FakeTrustedTimeSnapshotSource src(provider);
    int events = 0;
    auto sub = src.subscribe([&events](const TrustedTimeResult&) { ++events; });
    ASSERT_TRUE(src.start());
    EXPECT_GE(events, 1);  // 首帧基线
    const uint64_t seq = src.get(0).sec_time_event_sequence;
    EXPECT_GT(seq, 0u);
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(src.get(0).sec_time_event_sequence, seq);
    }
    EXPECT_EQ(events, 1);
}

// 注入样本失信：如实 Untrusted，且不授权（不因 fake 实现而放宽）
TEST(FakeSnapshotSourceTest, UntrustedSampleNotAuthorized) {
    auto provider = std::make_shared<FakeTrustedTimeProvider>(
        make_fake_sample(std::chrono::system_clock::now()), true);
    TrustedTimeSample untrusted = provider->now();
    untrusted.trust_state = TimeTrustState::Untrusted;
    untrusted.reason = TimeReason::PlatformNotAuthenticated;
    provider->set_now(untrusted);

    FakeTrustedTimeSnapshotSource src(provider);
    ASSERT_TRUE(src.start());
    const auto r = src.get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(r.remaining_validity_ms, 0);
    EXPECT_EQ(r.to_envelope().trust_state, "untrusted");
}

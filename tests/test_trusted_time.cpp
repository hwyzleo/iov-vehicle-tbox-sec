//
// TBOX-SEC-DSN-CR-017：CompositeTrustedTimeProvider 单元测试。
// 覆盖：来源优先级、freshness（300s 缺省门限）、uncertainty 上限、回拨保护、
// 来源切换、RTC 不套用 freshness、fail-closed（无来源/双失败）。
//

#include <gtest/gtest.h>

#include "trusted_time.h"

#include <chrono>

using namespace tbox::sec;
using namespace std::chrono_literals;

namespace {

class FakePlatformSource final : public PlatformTimeSource {
public:
    TrustedTimeSample next;
    TrustedTimeSample query() noexcept override { return next; }
};

class FakeRtcSource final : public HardwareRtcSource {
public:
    TrustedTimeSample next;
    TrustedTimeSample query() noexcept override { return next; }
};

TrustedTimeSample make_platform(std::chrono::system_clock::time_point now,
                                std::chrono::milliseconds age,
                                std::chrono::milliseconds uncertainty,
                                uint64_t epoch) {
    TrustedTimeSample s;
    s.utc_now = now;
    s.trust_state = TimeTrustState::Trusted;
    s.source = TimeSource::PlatformSync;
    s.freshness_age = age;
    s.uncertainty = uncertainty;
    s.reason = TimeReason::PlatformSynced;
    s.source_epoch = epoch;
    return s;
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

}  // namespace

TEST(TrustedTimeTest, PlatformPreferredOverRtc) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();
    p.next = make_platform(now, 0ms, 0ms, 1);
    r.next = make_rtc(now + 1s, 0ms);

    CompositeTrustedTimeProvider c(&p, &r);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::PlatformSync);
}

TEST(TrustedTimeTest, FallsBackToRtcWhenPlatformUnavailable) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();
    p.next = make_untrusted(TimeReason::PlatformInterfaceUnavailable,
                            TimeSource::PlatformSync);
    r.next = make_rtc(now, 0ms);

    CompositeTrustedTimeProvider c(&p, &r);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
}

// 双来源均失败 → fail-closed；失败原因取最近尝试来源（RTC）
TEST(TrustedTimeTest, BothSourcesFail_LastAttemptedReason) {
    FakePlatformSource p;
    FakeRtcSource r;
    p.next = make_untrusted(TimeReason::PlatformInterfaceUnavailable,
                            TimeSource::PlatformSync);
    r.next = make_untrusted(TimeReason::RtcNotProvisioned,
                            TimeSource::HardwareRtc);

    CompositeTrustedTimeProvider c(&p, &r);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
    EXPECT_EQ(s.reason, TimeReason::RtcNotProvisioned);
}

// 生产缺少可信适配器时 fail-closed（CR-017 §5）
TEST(TrustedTimeTest, NullSourcesFailClosed) {
    CompositeTrustedTimeProvider c(nullptr, nullptr);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.reason, TimeReason::NoSourceAvailable);
}

// 缺省 freshness 300s：300s 通过、300s+1ms 拒绝（CR-017 §4.1）
TEST(TrustedTimeTest, FreshnessGate) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();
    TrustedTimeConfig cfg;

    p.next = make_platform(now, cfg.max_freshness, 0ms, 1);
    CompositeTrustedTimeProvider c1(&p, &r);
    EXPECT_EQ(c1.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now, cfg.max_freshness + 1ms, 0ms, 1);
    CompositeTrustedTimeProvider c2(&p, &r);
    const auto s = c2.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.reason, TimeReason::PlatformTooOld);
}

// uncertainty 超上限拒绝（CR-017 §3/§4.1）
TEST(TrustedTimeTest, UncertaintyGate) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();
    TrustedTimeConfig cfg;  // max_uncertainty = 2000ms

    p.next = make_platform(now, 0ms, cfg.max_uncertainty, 1);
    CompositeTrustedTimeProvider c1(&p, &r);
    EXPECT_EQ(c1.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now, 0ms, cfg.max_uncertainty + 1ms, 1);
    CompositeTrustedTimeProvider c2(&p, &r);
    const auto s = c2.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(s.reason, TimeReason::PlatformUncertaintyTooHigh);
}

// 回拨保护：新 UTC 低于 last-known-good - 容差 → 拒绝（CR-017 §4.3）
TEST(TrustedTimeTest, RollbackRejected) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();

    p.next = make_platform(now, 0ms, 0ms, 1);
    CompositeTrustedTimeProvider c(&p, &r);
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
    const auto now = std::chrono::system_clock::now();
    p.next = make_untrusted(TimeReason::PlatformInterfaceUnavailable,
                            TimeSource::PlatformSync);

    r.next = make_rtc(now, 0ms);
    r.next.freshness_age = 999999ms;  // 远大于 300s

    CompositeTrustedTimeProvider c(&p, &r);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
}

// 来源切换（平台→RTC）时间向前 → 接受（CR-017 §4.3）
TEST(TrustedTimeTest, SourceSwitchForwardAccepted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();

    p.next = make_platform(now, 0ms, 0ms, 1);
    CompositeTrustedTimeProvider c(&p, &r);
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);

    p.next = make_untrusted(TimeReason::PlatformTooOld, TimeSource::PlatformSync);
    r.next = make_rtc(now + 1s, 0ms);
    const auto s = c.now();
    EXPECT_EQ(s.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(s.source, TimeSource::HardwareRtc);
}

// source_epoch 变化（来源重置）但时间向前 → 接受
TEST(TrustedTimeTest, EpochChangeForwardAccepted) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();

    p.next = make_platform(now, 0ms, 0ms, 1);
    CompositeTrustedTimeProvider c(&p, &r);
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);

    p.next = make_platform(now + 1s, 0ms, 0ms, 2);  // 新 epoch，时间向前
    EXPECT_EQ(c.now().trust_state, TimeTrustState::Trusted);
}

// 硬件 RTC 信任必须可判定：require_provisioned 时 reason 非 RtcProvisioned 拒绝
TEST(TrustedTimeTest, RtcRequireProvisioned) {
    FakePlatformSource p;
    FakeRtcSource r;
    const auto now = std::chrono::system_clock::now();
    p.next = make_untrusted(TimeReason::PlatformInterfaceUnavailable,
                            TimeSource::PlatformSync);

    TrustedTimeConfig cfg;  // hw_rtc_require_provisioned = true
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
}

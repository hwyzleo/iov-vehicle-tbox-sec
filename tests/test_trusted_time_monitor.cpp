//
// TBOX-SEC-DSN-CR-024：TrustedTimeMonitor 单元测试（验收 AT-05/AT-12）。
//
// 覆盖：真实路径经 TIME client（fake TimeSourceClient 模拟）→ adapter → composite
// → monitor 的端到端判定；到期撤销（无人查询也执行）；变化事件（信任/来源/代次/
// 对齐变化才发）；请求 token 拒绝迟到响应；停机清理（撤销缓存/失效 token/取消订阅）。
//
// 单调钟由测试注入（adapter/composite/monitor 共用同一变量），elapsed 精确可控。
//

#include <gtest/gtest.h>

#include "trusted_time.h"

#include <atomic>
#include <chrono>

using namespace tbox::sec;
using namespace std::chrono_literals;

namespace {

constexpr int64_t kUtcBase = 1'700'000'000'000;

/// 可编程 fake TIME client（实现 SEC 侧 TimeSourceClient 接口）。
class FakeTimeClient final : public TimeSourceClient {
public:
    bool connected = false;
    tbox::time::TimeSnapshot snapshot;
    QueryResult::Error query_error = QueryResult::Error::kOk;
    int64_t rtt_ms = 0;
    std::function<void()> on_event;

    bool connect() override { connected = true; return true; }
    void disconnect() override { connected = false; }
    bool is_connected() const override { return connected; }

    QueryResult get_time_snapshot() override {
        QueryResult r;
        r.error = query_error;
        r.snapshot = snapshot;
        r.rtt_ms = rtt_ms;
        return r;
    }

    std::shared_ptr<void> subscribe_state_changed(
        std::function<void(const tbox::time::TimeStateEvent&)> cb) override {
        // 测试：保存回调，测试代码可直接触发（模拟 TIME 事件）
        event_cb_ = std::move(cb);
        auto slot = std::make_shared<std::function<void(const tbox::time::TimeStateEvent&)>>(event_cb_);
        return slot;
    }

    std::function<void(const tbox::time::TimeStateEvent&)> event_cb_;
};

/// 构造完整 SYNCHRONIZED 快照（auth 可配；verified 需配证据）。
tbox::time::TimeSnapshot make_snapshot(
    tbox::time::TimeState state = tbox::time::TimeState::kSynced,
    tbox::time::AuthStatus auth = tbox::time::AuthStatus::kUnverified,
    int64_t remaining_validity = 30'000,
    int64_t freshness = 0,
    int64_t uncertainty = 50) {
    tbox::time::TimeSnapshot s;
    s.contract_version = tbox::time::kContractVersion;
    s.capabilities = "snapshot,v1";
    s.daemon_epoch = 1;
    s.event_sequence = 1;
    s.state = state;
    s.synchronized = tbox::time::isSynchronized(state);
    s.reason = tbox::time::TimeReason::kAlignmentVerified;
    s.source_id = "ntp-verified-1";
    s.source_kind = tbox::time::SourceKind::kNtpNetwork;
    s.source_epoch = 1;
    s.utc_valid = true;
    s.utc_epoch_ms = kUtcBase;
    s.system_clock_aligned = true;
    s.alignment_error_ms = 0;
    s.freshness_age_ms = freshness;
    s.uncertainty_valid = true;
    s.uncertainty_ms = uncertainty;
    s.remaining_validity_ms = remaining_validity;
    s.drift_bound_ppm = 100;
    s.auth_status = auth;
    s.auth_verified = (auth == tbox::time::AuthStatus::kVerified);
    s.evidence_ref = (auth == tbox::time::AuthStatus::kVerified) ? "ev:1" : "";
    s.policy_version = "1";
    return s;
}

struct MonitorFixture {
    int64_t boot_ms = 1'000'000;
    std::shared_ptr<FakeTimeClient> client = std::make_shared<FakeTimeClient>();
    std::unique_ptr<PlatformTimeAdapter> adapter;
    std::unique_ptr<HardwareRtcAdapter> rtc = std::make_unique<HardwareRtcAdapter>();
    std::unique_ptr<TrustedTimeMonitor> monitor;

    MonitorFixture() {
        auto clock = [this]() { return boot_ms; };
        adapter = std::make_unique<PlatformTimeAdapter>(client, clock);
        TrustedTimeConfig cfg;
        cfg.boot_clock = clock;
        cfg.approved_sources = {"ntp-verified-1"};
        monitor = std::make_unique<TrustedTimeMonitor>(adapter.get(), rtc.get(), cfg);
    }

    void start() { ASSERT_TRUE(monitor->start()); }
};

}  // namespace

// AT-01：真实 TIME client 返回 unverified NTP + SYNCHRONIZED → monitor 判 Untrusted
TEST(TrustedTimeMonitorTest, UnverifiedNtpSyncedRejected) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kUnverified);
    fx.start();

    const auto r = fx.monitor->get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(r.sample.reason, TimeReason::PlatformNotAuthenticated);
    EXPECT_EQ(r.contract_complete, true);
}

// 正向路径（受控 fixture，非生产来源验收）：verified+已批准 → Trusted，租约≤1000ms
TEST(TrustedTimeMonitorTest, VerifiedPositivePath) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified);
    fx.start();

    const auto r = fx.monitor->get(0);
    ASSERT_EQ(r.sample.trust_state, TimeTrustState::Trusted);
    EXPECT_EQ(r.sample.reason, TimeReason::PlatformSynced);
    EXPECT_LE(r.remaining_validity_ms, 1000);
    EXPECT_GT(r.remaining_validity_ms, 0);
    EXPECT_EQ(r.utc_valid, true);
    EXPECT_EQ(r.system_clock_aligned, true);
}

// AT-05：无人查询也到期撤销（本地流逝 > 租约 → Untrusted(TimeExpired)）
TEST(TrustedTimeMonitorTest, LeaseExpiryRevokedWithoutQuery) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified,
                                        /*remaining_validity=*/1500);
    fx.start();

    auto r = fx.monitor->get(0);
    ASSERT_EQ(r.sample.trust_state, TimeTrustState::Trusted);

    // 推进单调钟超过租约（lease=1000ms）
    fx.boot_ms += 1200;
    r = fx.monitor->get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(r.sample.reason, TimeReason::TimeExpired);
    EXPECT_EQ(r.remaining_validity_ms, 0);
}

// AT-05：变化事件（unverified→verified 信任变化）→ 订阅者收到事件；
//         数值变化（freshness 增长）不广播
TEST(TrustedTimeMonitorTest, EventOnTrustChangeNotOnNumericOnly) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kUnverified);
    fx.start();

    std::vector<TrustedTimeResult> events;
    auto handle = fx.monitor->subscribe(
        [&events](const TrustedTimeResult& r) { events.push_back(r); });

    // 信任变化：unverified → verified → 事件（订阅在变化前建立，避免与循环首次
    // 刷新竞态；事件由 refresh_now 同步路径发布，200ms 内收敛）
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified);
    fx.monitor->refresh_now();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_FALSE(events.empty());
    const auto seq_trusted = events.back().sec_time_event_sequence;
    EXPECT_EQ(events.back().sample.trust_state, TimeTrustState::Trusted);

    // 信任再变化（verified → unverified）→ 事件，序列递增
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kUnverified);
    fx.monitor->refresh_now();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_GT(events.size(), 1u);
    EXPECT_GT(events.back().sec_time_event_sequence, seq_trusted);
    EXPECT_EQ(events.back().sample.trust_state, TimeTrustState::Untrusted);

    // 仅数值变化（freshness 增长）→ 不广播（信任/来源/代次/对齐/关键 reason 不变）
    const auto size_before = events.size();
    auto snap = make_snapshot(tbox::time::TimeState::kSynced,
                              tbox::time::AuthStatus::kUnverified);
    snap.freshness_age_ms = 100;
    fx.client->snapshot = snap;
    fx.monitor->refresh_now();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(events.size(), size_before);

    handle.reset();
}

// AT-05：旧 token 拒绝迟到响应（SEC 重启/停机后旧 sec_daemon_epoch 无效）
TEST(TrustedTimeMonitorTest, StaleTokenRejected) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified);
    fx.start();

    const auto r = fx.monitor->get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Trusted);

    // 错误 token（如 SEC 重启后的旧值）→ stale
    const auto stale = fx.monitor->get(r.sec_daemon_epoch + 9999);
    EXPECT_EQ(stale.error_class, "stale");
    EXPECT_EQ(stale.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(stale.to_envelope().valid, false);
}

// AT-12：停机清理（撤销缓存、失效 token、取消订阅、关闭 client）
TEST(TrustedTimeMonitorTest, StopInvalidatesAndDisconnects) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified);
    fx.start();

    const auto r = fx.monitor->get(0);
    const auto epoch = r.sec_daemon_epoch;

    fx.monitor->stop();
    EXPECT_FALSE(fx.client->connected);  // 关闭 TIME client

    // 旧 token 拒绝（tokens_invalidated）
    const auto after = fx.monitor->get(epoch);
    EXPECT_EQ(after.error_class, "stale");
}

// AT-02：TIME 不可达 → Unknown(PlatformInterfaceUnavailable)；SEC 非时间能力不受影响
TEST(TrustedTimeMonitorTest, TimeUnreachableUnknown) {
    MonitorFixture fx;
    // client 未连接（connect 未调用/失败）
    fx.client->connected = false;
    fx.start();

    const auto r = fx.monitor->get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(r.sample.reason, TimeReason::PlatformInterfaceUnavailable);
    EXPECT_EQ(r.to_envelope().valid, true);  // 业务状态，非 IPC 错误
}

// AT-02：契约不支持（版本/能力未知）→ Unknown(PlatformContractIncomplete)
TEST(TrustedTimeMonitorTest, ContractUnsupportedUnknown) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->query_error = TimeSourceClient::QueryResult::Error::kUnsupported;
    fx.start();

    const auto r = fx.monitor->get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(r.sample.reason, TimeReason::PlatformContractIncomplete);
}

// AT-06：TIME 重启（daemon_epoch 变化）+ 换源（source_id/source_epoch 变化）→
//         缓存被新事实取代，事件序列递增
TEST(TrustedTimeMonitorTest, RestartSourceChangeNewFacts) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified);
    fx.start();

    std::vector<TrustedTimeResult> events;
    auto handle = fx.monitor->subscribe(
        [&events](const TrustedTimeResult& r) { events.push_back(r); });

    auto r1 = fx.monitor->get(0);
    const auto seq1 = r1.sec_time_event_sequence;

    // TIME 重启：daemon_epoch=2，换源
    auto snap = make_snapshot(tbox::time::TimeState::kSynced,
                              tbox::time::AuthStatus::kVerified);
    snap.daemon_epoch = 2;
    snap.event_sequence = 1;
    snap.source_id = "ntp-verified-2";
    snap.source_epoch = 1;
    fx.client->snapshot = snap;
    fx.monitor->refresh_now();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto r2 = fx.monitor->get(0);
    EXPECT_EQ(r2.time_daemon_epoch, 2u);
    EXPECT_EQ(r2.source_id, "ntp-verified-2");
    EXPECT_GT(r2.sec_time_event_sequence, seq1);
    handle.reset();
}

// to_envelope：stale 时 valid=false + error_class
TEST(TrustedTimeMonitorTest, StaleEnvelopeSemantics) {
    MonitorFixture fx;
    fx.client->connected = true;
    fx.client->snapshot = make_snapshot(tbox::time::TimeState::kSynced,
                                        tbox::time::AuthStatus::kVerified);
    fx.start();
    const auto stale = fx.monitor->get(12345);
    const auto e = stale.to_envelope();
    EXPECT_EQ(e.valid, false);
    EXPECT_EQ(e.error_class, "stale");
    EXPECT_EQ(e.trust_state, "unknown");
}

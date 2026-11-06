//
// TBOX-SEC-DSN-CR-024：只读可信时间 IPC/SDK wire 单元测试（验收 AT-02/AT-12）。
//
// 覆盖：
//   - envelope ↔ JSON 编解码与 golden 字段（稳定符号；Unknown/Untrusted 为可查询
//     业务状态，与 error_class 分离）；
//   - MethodId 24 (GET_TRUSTED_TIME) / 25 (SUBSCRIBE_TRUSTED_TIME_CHANGED) 路由；
//   - ACL：peer allowlist（tbox-mqtt.service）放行，其他身份拒绝（ACL_DENIED）；
//   - 未注入 monitor → NOT_IMPLEMENTED；畸形请求 → TRUSTED_TIME_MALFORMED。
//

#include <gtest/gtest.h>

#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "ipc_protocol.h"
#include "peer_credential.h"
#include "trusted_time.h"
#include "tbox/sec/time.h"
#include "tbox/sec/errors.h"
#include <nlohmann/json.hpp>

using namespace tbox::sec;
using json = nlohmann::json;

namespace {

class FixedPeerResolver : public PeerCredentialResolver {
public:
    explicit FixedPeerResolver(PeerIdentity id) : id_(std::move(id)) {}
    PeerIdentity resolve(int) override { return id_; }
private:
    PeerIdentity id_;
};

class FakeTimeClient final : public TimeSourceClient {
public:
    tbox::time::TimeSnapshot snapshot;
    bool connected = true;
    bool connect() override { connected = true; return true; }
    void disconnect() override { connected = false; }
    bool is_connected() const override { return connected; }
    QueryResult get_time_snapshot() override {
        QueryResult r;
        r.error = QueryResult::Error::kOk;
        r.snapshot = snapshot;
        return r;
    }
    std::shared_ptr<void> subscribe_state_changed(
        std::function<void(const tbox::time::TimeStateEvent&)> cb) override {
        auto slot = std::make_shared<std::function<void(const tbox::time::TimeStateEvent&)>>(std::move(cb));
        return slot;
    }
};

tbox::time::TimeSnapshot make_verified_snapshot() {
    tbox::time::TimeSnapshot s;
    s.contract_version = tbox::time::kContractVersion;
    s.capabilities = "snapshot,v1";
    s.daemon_epoch = 1;
    s.event_sequence = 1;
    s.state = tbox::time::TimeState::kSynced;
    s.synchronized = true;
    s.reason = tbox::time::TimeReason::kAlignmentVerified;
    s.source_id = "ntp-verified-1";
    s.source_kind = tbox::time::SourceKind::kNtpNetwork;
    s.source_epoch = 1;
    s.utc_valid = true;
    s.utc_epoch_ms = 1'700'000'000'000;
    s.system_clock_aligned = true;
    s.freshness_age_ms = 0;
    s.uncertainty_valid = true;
    s.uncertainty_ms = 50;
    s.remaining_validity_ms = 30'000;
    s.drift_bound_ppm = 100;
    s.auth_status = tbox::time::AuthStatus::kVerified;
    s.auth_verified = true;
    s.evidence_ref = "ev:1";
    s.policy_version = "1";
    return s;
}

}  // namespace

// ============================================================
// envelope ↔ JSON（wire 契约）
// ============================================================

TEST(TrustedTimeWireTest, EnvelopeJsonRoundTrip) {
    TrustedTimeEnvelope e;
    e.contract_version = 1;
    e.capabilities = "snapshot,v1";
    e.contract_complete = true;
    e.sec_daemon_epoch = 42;
    e.sec_time_event_sequence = 7;
    e.time_daemon_epoch = 1;
    e.time_event_sequence = 1;
    e.source_id = "ntp-verified-1";
    e.source_kind = "ntp_network";
    e.source_epoch = 1;
    e.policy_version = "1";
    e.trust_state = "trusted";
    e.source = "platform_sync";
    e.reason = "platform_synced";
    e.utc_valid = true;
    e.utc_epoch_ms = 1'700'000'000'000;
    e.freshness_age_ms = 250;
    e.uncertainty_valid = true;
    e.uncertainty_ms = 60;
    e.remaining_validity_ms = 900;
    e.drift_bound_ppm = 100;
    e.system_clock_aligned = true;
    e.alignment_error_ms = 0;
    e.auth_status = "verified";
    e.evidence_ref = "ev:1";
    e.valid = true;
    e.error_class = "";

    const json j = trusted_time_envelope_to_json(e);
    // golden 字段（稳定符号）
    EXPECT_EQ(j["trust_state"], "trusted");
    EXPECT_EQ(j["reason"], "platform_synced");
    EXPECT_EQ(j["source_kind"], "ntp_network");
    EXPECT_EQ(j["auth_status"], "verified");
    EXPECT_EQ(j["remaining_validity_ms"], 900);

    TrustedTimeEnvelope out;
    ASSERT_TRUE(trusted_time_envelope_from_json(j, &out));
    EXPECT_EQ(out.contract_version, e.contract_version);
    EXPECT_EQ(out.sec_daemon_epoch, e.sec_daemon_epoch);
    EXPECT_EQ(out.sec_time_event_sequence, e.sec_time_event_sequence);
    EXPECT_EQ(out.source_id, e.source_id);
    EXPECT_EQ(out.trust_state, e.trust_state);
    EXPECT_EQ(out.reason, e.reason);
    EXPECT_EQ(out.utc_epoch_ms, e.utc_epoch_ms);
    EXPECT_EQ(out.freshness_age_ms, e.freshness_age_ms);
    EXPECT_EQ(out.remaining_validity_ms, e.remaining_validity_ms);
    EXPECT_EQ(out.system_clock_aligned, true);
    EXPECT_EQ(out.valid, true);
}

// Unknown 是可查询业务状态：valid=true + trust_state=unknown，error_class 独立
TEST(TrustedTimeWireTest, UnknownIsQueryableState) {
    TrustedTimeEnvelope e;
    e.trust_state = "unknown";
    e.reason = "platform_contract_incomplete";
    e.valid = true;
    const json j = trusted_time_envelope_to_json(e);
    EXPECT_EQ(j["trust_state"], "unknown");
    EXPECT_EQ(j["valid"], true);
}

// 畸形 JSON → from_json 失败（TRUSTED_TIME_MALFORMED 语义）
TEST(TrustedTimeWireTest, MalformedJsonRejected) {
    TrustedTimeEnvelope out;
    EXPECT_FALSE(trusted_time_envelope_from_json(json::parse("42"), &out));
    EXPECT_FALSE(trusted_time_envelope_from_json(json::parse("{}"), &out));
}

// ============================================================
// IPC 路由与 ACL（MethodId 24/25，EventId 2）
// ============================================================

namespace {

struct DispatcherHarness {
    SecService service;
    SecIpcDispatcher dispatcher{&service};
    std::shared_ptr<FakeTimeClient> client = std::make_shared<FakeTimeClient>();
    std::unique_ptr<PlatformTimeAdapter> adapter;
    std::unique_ptr<HardwareRtcAdapter> rtc = std::make_unique<HardwareRtcAdapter>();
    std::unique_ptr<TrustedTimeMonitor> monitor;

    PeerIdentity mqtt_peer;
    PeerIdentity tsp_peer;

    int last_subscribed_event = -1;
    bool subscribe_ok = true;

    DispatcherHarness() {
        adapter = std::make_unique<PlatformTimeAdapter>(client);
        TrustedTimeConfig cfg;
        cfg.approved_sources = {"ntp-verified-1"};
        monitor = std::make_unique<TrustedTimeMonitor>(adapter.get(), rtc.get(), cfg);
        dispatcher.setTrustedTimeSource(monitor.get());

        mqtt_peer.valid = true;
        mqtt_peer.service_name = "tbox-mqtt.service";
        tsp_peer.valid = true;
        tsp_peer.service_name = "tbox-tsp.service";

        dispatcher.setPeerCredentialResolver(
            std::make_shared<FixedPeerResolver>(mqtt_peer));
        dispatcher.setAddSubscriptionCallback(
            [this](int, uint32_t ev) -> bool {
                last_subscribed_event = static_cast<int>(ev);
                return subscribe_ok;
            });
    }

    /// 先设置 fake 快照再启动监测，避免循环线程与快照赋值竞态。
    void start() { monitor->start(); }

    std::pair<int32_t, std::string> call(uint32_t method, const std::string& params) {
        const json resp = json::parse(dispatcher.dispatch(method, params, 0));
        return {resp.value("status", -1), resp.dump()};
    }
};

}  // namespace

// GET_TRUSTED_TIME：monitor + 已批准来源 → envelope.trusted
TEST(TrustedTimeIpcTest, GetTrustedTimePositive) {
    DispatcherHarness h;
    h.client->snapshot = make_verified_snapshot();
    h.start();

    const auto [status, body] = h.call(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), "{\"request_token\":0}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::SUCCESS));
    const json j = json::parse(body);
    const auto env = j["envelope"];
    EXPECT_EQ(env["trust_state"], "trusted");
    EXPECT_EQ(env["reason"], "platform_synced");
    EXPECT_EQ(env["contract_complete"], true);
    EXPECT_EQ(env["remaining_validity_ms"].get<int64_t>() > 0, true);
    EXPECT_EQ(env["sec_daemon_epoch"].get<uint64_t>() > 0, true);
    EXPECT_EQ(env["valid"], true);
}

// GET_TRUSTED_TIME：未认证 NTP（SYNCHRONIZED）→ envelope.untrusted（可查询业务状态）
TEST(TrustedTimeIpcTest, GetTrustedTimeUnverifiedNtpUntrusted) {
    DispatcherHarness h;
    h.client->snapshot = make_verified_snapshot();
    h.client->snapshot.auth_status = tbox::time::AuthStatus::kUnverified;
    h.client->snapshot.auth_verified = false;
    h.client->snapshot.evidence_ref.clear();
    h.start();

    const auto [status, body] = h.call(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), "{\"request_token\":0}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::SUCCESS));
    const json j = json::parse(body);
    EXPECT_EQ(j["envelope"]["trust_state"], "untrusted");
    EXPECT_EQ(j["envelope"]["reason"], "platform_not_authenticated");
}

// GET_TRUSTED_TIME：ACL 拒绝（非 allowlist 身份）→ ACL_DENIED
TEST(TrustedTimeIpcTest, GetTrustedTimeAclDenied) {
    DispatcherHarness h;
    h.dispatcher.setPeerCredentialResolver(
        std::make_shared<FixedPeerResolver>(h.tsp_peer));  // 非 mqtt
    h.start();

    const auto [status, body] = h.call(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), "{\"request_token\":0}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::ACL_DENIED));
    const json j = json::parse(body);
    EXPECT_EQ(j["envelope"]["error_class"], "acl_denied");
    EXPECT_EQ(j["envelope"]["valid"], false);
}

// GET_TRUSTED_TIME：未注入 monitor → NOT_IMPLEMENTED
TEST(TrustedTimeIpcTest, GetTrustedTimeNoMonitor) {
    SecService service;
    SecIpcDispatcher d(&service);
    const json resp = json::parse(d.dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), "{}", 0));
    EXPECT_EQ(resp.value("status", -1),
              static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED));
}

// GET_TRUSTED_TIME：畸形请求 → TRUSTED_TIME_MALFORMED
TEST(TrustedTimeIpcTest, GetTrustedTimeMalformedRequest) {
    DispatcherHarness h;
    h.start();
    const auto [status, body] = h.call(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), "{not-json");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::TRUSTED_TIME_MALFORMED));
    const json j = json::parse(body);
    EXPECT_EQ(j["envelope"]["error_class"], "malformed");
}

// SUBSCRIBE_TRUSTED_TIME_CHANGED：注册 EventId=2 + 返回当前快照基线
TEST(TrustedTimeIpcTest, SubscribeTrustedTimeChanged) {
    DispatcherHarness h;
    h.client->snapshot = make_verified_snapshot();
    h.start();

    const auto [status, body] = h.call(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TRUSTED_TIME_CHANGED), "{}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::SUCCESS));
    EXPECT_EQ(h.last_subscribed_event,
              static_cast<int>(ipc::EventId::TRUSTED_TIME_CHANGED));
    const json j = json::parse(body);
    EXPECT_EQ(j["event_type"], static_cast<int>(ipc::EventId::TRUSTED_TIME_CHANGED));
    EXPECT_EQ(j["envelope"]["trust_state"], "trusted");
}

// SUBSCRIBE_TRUSTED_TIME_CHANGED：ACL 拒绝
TEST(TrustedTimeIpcTest, SubscribeTrustedTimeChangedAclDenied) {
    DispatcherHarness h;
    h.dispatcher.setPeerCredentialResolver(
        std::make_shared<FixedPeerResolver>(h.tsp_peer));
    h.start();
    const auto [status, body] = h.call(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TRUSTED_TIME_CHANGED), "{}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::ACL_DENIED));
    (void)body;
}

// 方法号登记核对：24/25 与 EventId 2 与协议枚举一致（additive，未占用）
TEST(TrustedTimeIpcTest, MethodAndEventIdsRegistered) {
    EXPECT_EQ(static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), 24u);
    EXPECT_EQ(static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TRUSTED_TIME_CHANGED), 25u);
    EXPECT_EQ(static_cast<uint32_t>(ipc::EventId::TRUSTED_TIME_CHANGED), 2u);
    // 不与既有编号冲突
    EXPECT_NE(static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME),
              static_cast<uint32_t>(ipc::MethodId::GET_KEYPROV_CONTRACT_SNAPSHOT));
}

// ============================================================
// CR-024 修订：dev/test fake 快照源走同一 24/25 只读契约
// ============================================================

namespace {

struct FakeSourceHarness {
    SecService service;
    SecIpcDispatcher dispatcher{&service};
    std::shared_ptr<FakeTrustedTimeProvider> provider;
    std::unique_ptr<FakeTrustedTimeSnapshotSource> source;

    PeerIdentity mqtt_peer;
    PeerIdentity tsp_peer;
    int last_subscribed_event = -1;

    FakeSourceHarness() {
        TrustedTimeSample sample;
        sample.utc_now = std::chrono::system_clock::now();
        sample.trust_state = TimeTrustState::Trusted;
        sample.source = TimeSource::FakeTest;
        sample.reason = TimeReason::FakeTest;
        // 注入 10 分钟前的启动快照，验证查询时刻现算墙钟
        sample.utc_now = std::chrono::system_clock::now() -
                         std::chrono::minutes(10);
        provider = std::make_shared<FakeTrustedTimeProvider>(sample, true);
        source = std::make_unique<FakeTrustedTimeSnapshotSource>(provider);
        dispatcher.setTrustedTimeSource(source.get());

        mqtt_peer.valid = true;
        mqtt_peer.service_name = "tbox-mqtt.service";
        tsp_peer.valid = true;
        tsp_peer.service_name = "tbox-tsp.service";

        dispatcher.setPeerCredentialResolver(
            std::make_shared<FixedPeerResolver>(mqtt_peer));
        dispatcher.setAddSubscriptionCallback(
            [this](int, uint32_t ev) -> bool {
                last_subscribed_event = static_cast<int>(ev);
                return true;
            });
        source->start();
    }

    std::pair<int32_t, json> call(uint32_t method, const std::string& params) {
        const json resp = json::parse(dispatcher.dispatch(method, params, 0));
        return {resp.value("status", -1), resp};
    }
};

}  // namespace

// GET_TRUSTED_TIME：fake profile 也返回 SUCCESS + 可判定 envelope（回归 SEC-8004）
TEST(TrustedTimeIpcTest, GetTrustedTimeFakeSourcePositive) {
    FakeSourceHarness h;
    const auto [status, j] = h.call(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME),
        "{\"request_token\":0}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::SUCCESS));
    const auto env = j["envelope"];
    EXPECT_EQ(env["valid"], true);
    EXPECT_EQ(env["contract_complete"], true);
    EXPECT_EQ(env["trust_state"], "trusted");
    EXPECT_EQ(env["source"], "fake_test");
    EXPECT_EQ(env["system_clock_aligned"], true);
    EXPECT_EQ(env["auth_status"], "unverified");  // 不伪造认证
    EXPECT_GT(env["remaining_validity_ms"].get<int64_t>(), 0);
    EXPECT_GT(env["sec_daemon_epoch"].get<uint64_t>(), 0u);
    // UTC 取查询时刻（不是注入的 10 分钟前快照）
    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    EXPECT_LE(std::llabs(now_ms - env["utc_epoch_ms"].get<int64_t>()), 2000);
}

// SUBSCRIBE_TRUSTED_TIME_CHANGED：fake 源同样返回快照基线 + 登记事件
TEST(TrustedTimeIpcTest, SubscribeTrustedTimeChangedFakeSource) {
    FakeSourceHarness h;
    const auto [status, j] = h.call(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TRUSTED_TIME_CHANGED), "{}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::SUCCESS));
    EXPECT_EQ(h.last_subscribed_event,
              static_cast<int>(ipc::EventId::TRUSTED_TIME_CHANGED));
    EXPECT_EQ(j["event_type"], static_cast<int>(ipc::EventId::TRUSTED_TIME_CHANGED));
    EXPECT_EQ(j["envelope"]["trust_state"], "trusted");
}

// ACL 不因 fake 实现而放宽：非 tbox-mqtt.service 仍拒绝
TEST(TrustedTimeIpcTest, FakeSourceAclDeniedForOtherPeer) {
    FakeSourceHarness h;
    h.dispatcher.setPeerCredentialResolver(
        std::make_shared<FixedPeerResolver>(h.tsp_peer));
    const auto [status, j] = h.call(
        static_cast<uint32_t>(ipc::MethodId::GET_TRUSTED_TIME), "{}");
    EXPECT_EQ(status, static_cast<int32_t>(ErrorCode::ACL_DENIED));
    EXPECT_EQ(j["envelope"]["error_class"], "acl_denied");
}

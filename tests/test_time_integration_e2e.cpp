//
// TBOX-SEC-DSN-CR-024 Level B：真实进程拒绝路径联调。
//
// 链路（真实）：本地 UDP mock NTP 服务器（RFC 5905，未认证）→ **真实 tbox_time
// daemon 进程**（mock 校时后端）→ TIME IPC socket → SEC TimeClientBridge →
// PlatformTimeAdapter → CompositeTrustedTimeMonitor → SEC framework-ipc Server →
// **SecClient SDK**（tbox::sec::SecClient::get_trusted_time / subscribe）。
//
// 断言（验收 AT-01/AT-10 的 SEC 侧拒绝路径）：TIME SYNCHRONIZED + 未认证 NTP →
// SEC 仍 Untrusted(platform_not_authenticated)；SDK 查询同样 untrusted；
// 生产默认无已批准认证来源（approved_sources 空）→ 安全离线是预期。
// 本测试不宣称生产可信正向闭环（AT-11 待真实认证来源/ORIN 验收）。
//
// 依赖：真实 TIME daemon 二进制（TIME_DAEMON_BIN，CMake 注入）。
//

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>

#include "ipc.h"  // tbox::fw::ipc（framework SDK）

#include "trusted_time.h"
#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "peer_credential.h"
#include "ipc_protocol.h"
#include "tbox/sec/client.h"
#include "tbox/sec/time.h"
#include "tbox/sec/errors.h"
#include "tbox/time/time_client.h"
#include "tbox/time/types.h"

using namespace tbox::sec;
using namespace std::chrono_literals;

namespace {

#ifndef TIME_DAEMON_BIN
#define TIME_DAEMON_BIN "/tmp/nonexistent-tbox_time"
#endif

int64_t realtimeMs() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#pragma pack(push, 1)
struct NtpPacket {
    uint8_t li_vn_mode;
    uint8_t stratum;
    int8_t poll;
    int8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint32_t ref_time_sec;
    uint32_t ref_time_frac;
    uint32_t orig_time_sec;
    uint32_t orig_time_frac;
    uint32_t rx_time_sec;
    uint32_t rx_time_frac;
    uint32_t tx_time_sec;
    uint32_t tx_time_frac;
};
#pragma pack(pop)

void encodeNtp(uint32_t* sec, uint32_t* frac, int64_t unix_ms) {
    *sec = static_cast<uint32_t>(unix_ms / 1000 + 2208988800LL);
    *frac = static_cast<uint32_t>(((unix_ms % 1000) << 32) / 1000);
}

/// 本地 UDP mock NTP 服务器（未认证语义：无 NTS/对称密钥）。
class MockNtpServer {
public:
    MockNtpServer() {
        fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_ < 0) throw std::runtime_error("socket failed");
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
            throw std::runtime_error("bind failed");
        socklen_t len = sizeof(addr);
        getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        running_ = true;
        struct timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        thread_ = std::thread(&MockNtpServer::loop, this);
    }
    ~MockNtpServer() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        if (fd_ >= 0) ::close(fd_);
    }
    MockNtpServer(const MockNtpServer&) = delete;
    MockNtpServer& operator=(const MockNtpServer&) = delete;
    uint16_t port() const { return port_; }

private:
    void loop() {
        char buf[512];
        while (running_.load()) {
            sockaddr_in from{};
            socklen_t flen = sizeof(from);
            const ssize_t n = recvfrom(fd_, buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr*>(&from), &flen);
            if (n < 48) continue;
            NtpPacket resp{};
            const int64_t now = realtimeMs();
            resp.li_vn_mode = (4 << 3) | 4;
            resp.stratum = 1;
            resp.poll = 6;
            resp.precision = -6;
            encodeNtp(&resp.ref_time_sec, &resp.ref_time_frac, 1'700'000'000'000);
            resp.orig_time_sec = reinterpret_cast<NtpPacket*>(buf)->tx_time_sec;
            resp.orig_time_frac = reinterpret_cast<NtpPacket*>(buf)->tx_time_frac;
            encodeNtp(&resp.rx_time_sec, &resp.rx_time_frac, now - 1);
            encodeNtp(&resp.tx_time_sec, &resp.tx_time_frac, now);
            sendto(fd_, &resp, sizeof(resp), 0,
                   reinterpret_cast<sockaddr*>(&from), flen);
        }
    }

    int fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace

class TimeIntegrationE2eTest : public ::testing::Test {
protected:
    MockNtpServer ntp_;
    std::string tmp_dir_;
    std::string time_socket_;
    std::string sec_socket_;
    pid_t time_pid_ = -1;

    void SetUp() override {
        const auto pid = ::getpid();
        tmp_dir_ = "/tmp/tbox-time-e2e-" + std::to_string(pid);
        time_socket_ = tmp_dir_ + "/time.sock";
        sec_socket_ = tmp_dir_ + "/sec.sock";
        ::system(("rm -rf " + tmp_dir_ + " && mkdir -p " + tmp_dir_ + "/config").c_str());

        // ---- 生成 TIME daemon 测试配置（真实 daemon 进程使用）----
        {
            std::ofstream cfg(tmp_dir_ + "/config/time.yaml");
            cfg << "common:\n"
                << "  log:\n"
                << "    schema_version: 1\n"
                << "    level: INFO\n"
                << "    strict: false\n"
                << "    format: standard\n"
                << "    console:\n      enabled: true\n"
                << "    file:\n      enabled: false\n"
                << "time:\n"
                << "  profile: test\n"
                << "  ipc:\n"
                << "    socket_path: " << time_socket_ << "\n"
                << "  backend:\n"
                << "    mode: mock\n"
                << "  core:\n"
                << "    max_source_age_ms: 300000\n"
                << "    max_source_error_ms: 500\n"
                << "    step_threshold_ms: 1000\n"
                << "    slew_threshold_ms: 50\n"
                << "    alignment_tolerance_ms: 50\n"
                << "    holdover_max_ms: 3600000\n"
                << "    holdover_max_error_ms: 1000\n"
                << "    drift_bound_ppm: 100\n"
                << "    monitor_interval_ms: 200\n"
                << "    synchronizing_timeout_ms: 15000\n"
                << "  sources:\n"
                << "    ntp:\n"
                << "      enabled: true\n"
                << "      servers:\n"
                << "        - id: ntp0\n"
                << "          host: 127.0.0.1\n"
                << "          port: " << ntp_.port() << "\n"
                << "          timeout_ms: 500\n"
                << "          poll_interval_ms: 300\n"
                << "          queueing_budget_ms: 20\n"
                << "    cellular:\n      enabled: false\n"
                << "    gnss:\n      enabled: false\n"
                << "    rtc:\n      enabled: false\n";
        }

        // ---- 启动真实 TIME daemon 进程（CWD = 临时目录，读取 ./config/time.yaml）----
        const pid_t child_pid = ::fork();
        ASSERT_GE(child_pid, 0);
        if (child_pid == 0) {
            ::chdir(tmp_dir_.c_str());
            ::execl(TIME_DAEMON_BIN, "tbox_time", static_cast<char*>(nullptr));
            ::_exit(127);
        }
        time_pid_ = child_pid;

        // ---- 等待 TIME IPC socket 出现（daemon 就绪）----
        const auto deadline = std::chrono::steady_clock::now() + 15s;
        while (std::chrono::steady_clock::now() < deadline) {
            struct stat st;
            if (::stat(time_socket_.c_str(), &st) == 0) return;
            std::this_thread::sleep_for(100ms);
        }
        FAIL() << "TIME daemon did not create IPC socket within 15s";
    }

    void TearDown() override {
        if (time_pid_ > 0) {
            ::kill(time_pid_, SIGTERM);
            int status = 0;
            ::waitpid(time_pid_, &status, WNOHANG);
            std::this_thread::sleep_for(200ms);
            ::kill(time_pid_, SIGKILL);
            ::waitpid(time_pid_, &status, 0);
        }
        ::system(("rm -rf " + tmp_dir_).c_str());
    }

    /// 等待 TIME 达到 SYNCHRONIZED（轮询真实 TIME client）。
    bool waitSynchronized(const std::string& socket_path, int timeout_ms = 20000) {
        tbox::time::TimeClient c(socket_path);
        if (!c.connect()) return false;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            auto res = c.getTimeSnapshot();
            if (res.error == tbox::time::ClientError::kOk &&
                res.snapshot.state == tbox::time::TimeState::kSynced &&
                res.snapshot.utc_valid) {
                return true;
            }
            std::this_thread::sleep_for(200ms);
        }
        return false;
    }
};

// AT-01/AT-10（SEC 侧拒绝路径）：真实 TIME SYNCHRONIZED + 未认证 NTP → SEC Untrusted
TEST_F(TimeIntegrationE2eTest, RealTimeDaemonUnverifiedNtpRejected) {
    ASSERT_TRUE(waitSynchronized(time_socket_))
        << "TIME daemon did not reach SYNCHRONIZED (unverified NTP)";

    // SEC 栈：真实 TimeClientBridge → adapter → composite → monitor。
    // 生产默认 approved_sources 为空 → 未认证 NTP 即使 SYNCHRONIZED 仍拒绝。
    auto client = makeTimeClientBridge(time_socket_);
    auto adapter = std::make_unique<PlatformTimeAdapter>(client);
    auto rtc = std::make_unique<HardwareRtcAdapter>();
    TrustedTimeConfig cfg;
    cfg.approved_sources = {};
    auto monitor = std::make_unique<TrustedTimeMonitor>(adapter.get(), rtc.get(), cfg);
    ASSERT_TRUE(monitor->start());

    // 等待 monitor 完成首次连接+刷新（连接由监测循环 2s 有界重试建立）
    TrustedTimeResult r;
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (std::chrono::steady_clock::now() < deadline) {
        r = monitor->get(0);
        if (r.sample.reason != TimeReason::PlatformInterfaceUnavailable) break;
        std::this_thread::sleep_for(200ms);
    }
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Untrusted);
    EXPECT_EQ(r.sample.reason, TimeReason::PlatformNotAuthenticated);
    EXPECT_EQ(r.contract_complete, true);
    EXPECT_EQ(r.sample.source, TimeSource::PlatformSync);
}

// AT-10（SEC 侧）：经真实 SecClient SDK 查询同样 untrusted；订阅基线可建立
TEST_F(TimeIntegrationE2eTest, RealSdkGetTrustedTimeRejected) {
    ASSERT_TRUE(waitSynchronized(time_socket_));

    auto client = makeTimeClientBridge(time_socket_);
    auto adapter = std::make_unique<PlatformTimeAdapter>(client);
    auto rtc = std::make_unique<HardwareRtcAdapter>();
    TrustedTimeConfig cfg;
    cfg.approved_sources = {};
    auto monitor = std::make_unique<TrustedTimeMonitor>(adapter.get(), rtc.get(), cfg);
    ASSERT_TRUE(monitor->start());

    // ---- 真实 SEC IPC server + dispatcher（dev peer resolver：macOS 无 SO_PEERCRED）----
    auto server = std::make_unique<tbox::fw::ipc::Server>(sec_socket_);
    auto* server_ptr = server.get();

    SecService service;
    SecIpcDispatcher dispatcher(&service);
    dispatcher.setTrustedTimeSource(monitor.get());
    dispatcher.setPeerCredentialResolver(
        std::make_shared<DevPeerCredentialResolver>("tbox-mqtt.service"));
    dispatcher.setAddSubscriptionCallback(
        [server_ptr](int client_fd, uint32_t event_type) -> bool {
            return server_ptr->add_subscription(client_fd, event_type);
        });
    auto* dispatcher_ptr = &dispatcher;
    const bool started = server->start(
        [dispatcher_ptr](uint32_t method_id, std::string_view params,
                         int client_fd) -> std::string {
            return dispatcher_ptr->dispatch(method_id, params, client_fd);
        },
        [](int) {});
    ASSERT_TRUE(started);

    // ---- SecClient SDK（真实 AF_UNIX IPC）----
    tbox::sec::SecClient sdk(sec_socket_);
    ASSERT_TRUE(sdk.connect());

    TrustedTimeEnvelope env;
    const ErrorCode rc = sdk.get_trusted_time(env);
    EXPECT_EQ(rc, ErrorCode::SUCCESS);  // 业务状态在 envelope，不伪装为 IPC 错误
    EXPECT_EQ(env.trust_state, "untrusted");
    EXPECT_EQ(env.reason, "platform_not_authenticated");
    EXPECT_EQ(env.source, "platform_sync");
    EXPECT_EQ(env.source_kind, "ntp_network");
    EXPECT_EQ(env.contract_complete, true);
    EXPECT_EQ(env.valid, true);
    EXPECT_EQ(env.error_class, "");
    EXPECT_EQ(env.utc_valid, true);  // TIME 已同步：UTC 事实存在但不信任
    EXPECT_GT(env.sec_daemon_epoch, 0u);

    // 订阅基线（先订阅再查询对账；RAII 句柄）
    std::atomic<int> event_count{0};
    auto sub = sdk.subscribe_trusted_time_changed(
        [&event_count](const TrustedTimeEnvelope&) { event_count++; });
    ASSERT_TRUE(sub.isActive());

    // 再次查询：token = 上次 sec_daemon_epoch
    TrustedTimeEnvelope env2;
    const ErrorCode rc2 = sdk.get_trusted_time(env.sec_daemon_epoch, env2);
    EXPECT_EQ(rc2, ErrorCode::SUCCESS);
    EXPECT_EQ(env2.trust_state, "untrusted");

    // 停机清理
    sub.cancel();
    sdk.disconnect();
    server->stop();
    monitor->stop();
}

// AT-02：TIME daemon 未运行 → SEC Unknown(PlatformInterfaceUnavailable)（非时间能力不受影响）
TEST_F(TimeIntegrationE2eTest, TimeDaemonAbsentUnknown) {
    // 不等待/不依赖 daemon：直接指向不存在的 socket
    const std::string dead_socket = tmp_dir_ + "/nonexistent.sock";
    auto client = makeTimeClientBridge(dead_socket);
    auto adapter = std::make_unique<PlatformTimeAdapter>(client);
    auto rtc = std::make_unique<HardwareRtcAdapter>();
    TrustedTimeConfig cfg;
    cfg.approved_sources = {};
    auto monitor = std::make_unique<TrustedTimeMonitor>(adapter.get(), rtc.get(), cfg);
    ASSERT_TRUE(monitor->start());

    const auto r = monitor->get(0);
    EXPECT_EQ(r.sample.trust_state, TimeTrustState::Unknown);
    EXPECT_EQ(r.sample.reason, TimeReason::PlatformInterfaceUnavailable);
    EXPECT_EQ(r.to_envelope().valid, true);  // 业务状态，非 IPC 错误
}

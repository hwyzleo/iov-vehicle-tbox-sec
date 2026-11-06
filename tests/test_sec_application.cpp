//
// TBOX-SEC-DSN-CR-011 §10.1: SecApplication 单元测试。
// 覆盖信号集合、initialize 各阶段成功/失败与逆序清理、execute 退出、cleanup 幂等。
//

#include <gtest/gtest.h>
#include "sec_application.h"
#include "sec_service.h"
#include "prov_service_interface.h"
#include "config.h"
#include "store.h"
#include "application.h"

#include <csignal>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

using namespace tbox::sec;

namespace {

/// 模拟 PROV 服务（脱离真实 PROV daemon 依赖）
class MockProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override { return ErrorCode::SUCCESS; }
    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.ecu_uid = "TESTDEVICE001";
        return ErrorCode::SUCCESS;
    }
    bool is_connected() const override { return true; }
    std::string get_service_status() const override { return "Connected"; }
};

/// 暴露 protected 钩子便于单测直接驱动生命周期阶段（不经过 run() 的信号安装）。
class TestableSecApplication : public SecApplication {
public:
    using SecApplication::SecApplication;
    std::string serviceName() const { return getServiceName(); }
    std::vector<int> gracefulSigs() const { return gracefulSignals(); }
    std::vector<int> ignoredSigs() const { return ignoredSignals(); }
    std::vector<int> fatalSigs() const { return fatalSignals(); }
    bool doLoadConfig(const std::string& root) {
        return hwyz::config::ConfigManager::instance().load("sec", root)
               == hwyz::config::ConfigError::kOk;
    }
    bool doInitialize() { return initialize(); }
    void doCleanup() { cleanup(); }
    int doExecute() { return execute(); }
    void doRequestShutdown() { requestShutdown(); }
    // CR-024 修订：白盒观测可信时间只读快照源（生产 monitor / dev-test fake）
    TrustedTimeSnapshotSource* timeSource() const { return SecApplication::timeSource(); }
    static bool fakeAllowed(const std::string& provider, bool is_production) {
        return SecApplication::allowDevTestFakeTime(provider, is_production);
    }
protected:
    // 注入 MockProvService，避免单测依赖真实 PROV daemon
    std::shared_ptr<ProvServiceInterface> createProvClient(const std::string&) override {
        return std::make_shared<MockProvService>();
    }
};

std::string makeConfig(const std::string& dir,
                       const std::string& store_root,
                       const std::string& socket_path,
                       const std::string& sec_extra = "",
                       const std::string& top_extra = "") {
    std::filesystem::create_directories(std::string(dir) + "/conf.d");
    {
        std::ofstream f(std::string(dir) + "/common.yaml");
        f << "common:\n  store:\n    root: \"" << store_root << "\"\n"
          << "  log:\n    level: info\n"
          << "  ipc:\n    max_frame_bytes: 10485760\n"
          << "    receive_timeout_ms: 60000\n"
          << "    connect_timeout_ms: 3000\n"
          << "    listen_backlog: 5\n";
    }
    {
        std::ofstream f(std::string(dir) + "/conf.d/sec.yaml");
        f << "sec:\n  ipc:\n    socket_path: \"" << socket_path << "\"\n"
          << sec_extra
          << "hsm:\n  type: \"soft_file\"\n"
          << "key_provisioning:\n  mode: \"soft_file\"\n"
          << "soft_key:\n  path: \"" << store_root << "\"\n"
          << "cloud:\n  endpoint: \"https://test.example.com\"\n"
          << "  timeout_ms: 1000\n  retry_count: 1\n  retry_delay_ms: 100\n";
        if (!top_extra.empty()) f << top_extra;
    }
    return dir;
}

} // namespace

class SecApplicationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/sec_app_test_" +
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::filesystem::create_directories(test_dir_);
        store_dir_ = test_dir_ + "/store";
        socket_path_ = test_dir_ + "/test.sock";
        // 切换到测试目录加载配置，避免项目根 config/dev/sec.yaml 的项目层覆盖
        // （PathResolver 会无条件加载 ./config/<svc>.yaml，见框架 path_resolver）
        orig_cwd_ = std::filesystem::current_path();
        std::filesystem::current_path(test_dir_);
    }
    void TearDown() override {
        if (!orig_cwd_.empty()) {
            std::filesystem::current_path(orig_cwd_);
        }
        std::filesystem::remove_all(test_dir_);
    }
    std::string test_dir_;
    std::string store_dir_;
    std::string socket_path_;
    std::filesystem::path orig_cwd_;
};

// ============================================================
// 信号集合与服务标识
// ============================================================

TEST_F(SecApplicationTest, ServiceNameIsSec) {
    TestableSecApplication app;
    EXPECT_EQ(app.serviceName(), "sec");
}

TEST_F(SecApplicationTest, DefaultGracefulSignals) {
    TestableSecApplication app;
    auto sigs = app.gracefulSigs();
    // CR-011 §6: SIGINT/SIGTERM graceful（沿用 Application 默认）
    EXPECT_NE(std::find(sigs.begin(), sigs.end(), SIGINT), sigs.end());
    EXPECT_NE(std::find(sigs.begin(), sigs.end(), SIGTERM), sigs.end());
}

TEST_F(SecApplicationTest, IgnoredSignalsIncludeSigpipe) {
    TestableSecApplication app;
    auto sigs = app.ignoredSigs();
    EXPECT_NE(std::find(sigs.begin(), sigs.end(), SIGPIPE), sigs.end());
}

TEST_F(SecApplicationTest, FatalSignalsIncludeSegvAbrot) {
    TestableSecApplication app;
    auto sigs = app.fatalSigs();
    EXPECT_NE(std::find(sigs.begin(), sigs.end(), SIGSEGV), sigs.end());
    EXPECT_NE(std::find(sigs.begin(), sigs.end(), SIGABRT), sigs.end());
}

TEST_F(SecApplicationTest, SignalSetsValidAndMutuallyExclusive) {
    TestableSecApplication app;
    auto g = app.gracefulSigs();
    auto f = app.fatalSigs();
    auto i = app.ignoredSigs();
    // 集合合法、去重、无跨集合冲突
    EXPECT_TRUE(hwyz::Application::validateSignalSets(g, f, i).empty());
    // SIGKILL/SIGSTOP 不得出现
    for (int s : g) { EXPECT_NE(s, SIGKILL); EXPECT_NE(s, SIGSTOP); }
    for (int s : f) { EXPECT_NE(s, SIGKILL); EXPECT_NE(s, SIGSTOP); }
    for (int s : i) { EXPECT_NE(s, SIGKILL); EXPECT_NE(s, SIGSTOP); }
}

// ============================================================
// initialize 成功与逆序清理
// ============================================================

TEST_F(SecApplicationTest, InitializeSuccessStartsIpc) {
    makeConfig(test_dir_, store_dir_, socket_path_);
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    ASSERT_TRUE(app.doInitialize());
    // IPC server 启动后应创建 socket 文件
    EXPECT_TRUE(std::filesystem::exists(socket_path_));

    app.doCleanup();
    // cleanup 后 socket 路径不得残留（CR-011 §4.3）
    EXPECT_FALSE(std::filesystem::exists(socket_path_));
}

TEST_F(SecApplicationTest, CleanupIsIdempotent) {
    makeConfig(test_dir_, store_dir_, socket_path_);
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    ASSERT_TRUE(app.doInitialize());

    app.doCleanup();
    // 重复 cleanup 必须安全（幂等，不重复业务操作）
    EXPECT_NO_THROW(app.doCleanup());
    EXPECT_NO_THROW(app.doCleanup());
    EXPECT_FALSE(std::filesystem::exists(socket_path_));
}

TEST_F(SecApplicationTest, InitializeStoreFailureReturnsFalse) {
    // store_root 指向不可创建目录的路径（/dev/null 是文件，其下无法建目录）
    makeConfig(test_dir_, "/dev/null/cannot_create_store", socket_path_);
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    EXPECT_FALSE(app.doInitialize());
    // store 失败时不得启动 IPC，无 socket 残留
    EXPECT_FALSE(std::filesystem::exists(socket_path_));
}

TEST_F(SecApplicationTest, InitializeIpcBindFailureRollsBack) {
    // socket 路径位于 /dev/null（文件）之下，bind 必然失败（ENOTDIR）；
    // 验证 IPC start 失败后 initialize 返回 false 且无半初始化资源、cleanup 幂等。
    makeConfig(test_dir_, store_dir_, "/dev/null/cannot_bind.sock");
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    EXPECT_FALSE(app.doInitialize());
    // 失败后 cleanup 必须安全（幂等）
    EXPECT_NO_THROW(app.doCleanup());
}

// ============================================================
// execute 在收到停机请求后及时返回
// ============================================================

TEST_F(SecApplicationTest, ExecuteReturnsAfterShutdownRequest) {
    makeConfig(test_dir_, store_dir_, socket_path_);
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    ASSERT_TRUE(app.doInitialize());

    // 异步触发停机；execute 不依赖 EINTR，应在 poll 周期内返回
    std::thread([&app]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        app.doRequestShutdown();
    }).detach();

    auto start = std::chrono::steady_clock::now();
    int rc = app.doExecute();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    EXPECT_EQ(rc, 0);
    // 默认 poll 100ms + 触发延迟 150ms，应在 1s 内返回（不依赖 EINTR）
    EXPECT_LT(elapsed, 1000);

    app.doCleanup();
}

// ============================================================
// CR-024 修订：dev/test fake 只读快照源装配与生产隔离
// ============================================================

// 唯一判定入口：仅「显式 provider=fake 且非生产」允许，无 accept_unverified/bypass
TEST_F(SecApplicationTest, FakeTimeProfilePredicate) {
    EXPECT_TRUE(TestableSecApplication::fakeAllowed("fake", false));
    EXPECT_FALSE(TestableSecApplication::fakeAllowed("fake", true));
    EXPECT_FALSE(TestableSecApplication::fakeAllowed("composite", false));
    EXPECT_FALSE(TestableSecApplication::fakeAllowed("", false));
}

// dev/test fake profile：IPC 方法 24 的读入口不再是 NOT_IMPLEMENTED(SEC-8004)
TEST_F(SecApplicationTest, DevTestFakeProfileExposesReadOnlyIpcSource) {
    makeConfig(test_dir_, store_dir_, socket_path_,
               "  trusted_time:\n    provider: \"fake\"\n",
               "environment:\n  is_production: false\n");
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    ASSERT_TRUE(app.doInitialize());

    TrustedTimeSnapshotSource* src = app.timeSource();
    ASSERT_NE(src, nullptr);
    EXPECT_NE(dynamic_cast<FakeTrustedTimeSnapshotSource*>(src), nullptr);

    const auto env = src->get(0).to_envelope();
    EXPECT_EQ(env.valid, true);
    EXPECT_EQ(env.contract_complete, true);
    EXPECT_EQ(env.trust_state, "trusted");
    EXPECT_EQ(env.source, "fake_test");
    EXPECT_GT(env.remaining_validity_ms, 0);

    app.doCleanup();
    EXPECT_FALSE(std::filesystem::exists(socket_path_));
}

// 缺省 composite profile：不得装配 fake 源（生产/通用路径保持 monitor）
TEST_F(SecApplicationTest, CompositeProfileDoesNotUseFakeSource) {
    makeConfig(test_dir_, store_dir_, socket_path_);
    TestableSecApplication app;
    ASSERT_TRUE(app.doLoadConfig(test_dir_));
    ASSERT_TRUE(app.doInitialize());

    TrustedTimeSnapshotSource* src = app.timeSource();
    ASSERT_NE(src, nullptr);
    EXPECT_EQ(dynamic_cast<FakeTrustedTimeSnapshotSource*>(src), nullptr);
    EXPECT_NE(dynamic_cast<TrustedTimeMonitor*>(src), nullptr);

    app.doCleanup();
}

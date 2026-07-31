//
// TBOX-SEC-DSN-CR-011 §9.1: 回滚验证用的旧式手写生命周期入口。
// 当 SEC_USE_FRAMEWORK_APPLICATION=OFF 时编译。不使用 hwyz::Application，
// 自行安装信号、初始化日志、装配 IPC 并维护运行循环。
// 验收后删除本文件与开关（CR-011 阶段 3）。
//
// 注意：SecService 已按本 CR 瘦身（移除 start_ipc_server/stop_ipc_server），
// 故本入口手动装配 dispatcher + ipc::Server，等价于 SecApplication 的 IPC 部分。
//

#include "sec_service.h"
#include "sec_ipc_dispatcher.h"
#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "ipc_prov_service.h"
#include "ipc.h"
#include "ipc_protocol.h"
#include "sec_log_adapter.h"
#include "log.h"
#include "config.h"
#include "store.h"
#include "error_codes.h"

#include <iostream>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <memory>
#include <string>

using namespace tbox::sec;

static std::atomic<bool> shutdown_requested(false);
static volatile sig_atomic_t received_signal = 0;

extern "C" void signal_handler(int signum) {
    received_signal = signum;
    shutdown_requested.store(true, std::memory_order_relaxed);
    static const char msg[] = "\n[signal] shutdown requested\n";
    ssize_t ignored = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ignored;
}

static bool install_signal_handlers() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sa.sa_flags = SA_RESTART;

    const int shutdown_signals[] = {SIGINT, SIGTERM};
    for (int sig : shutdown_signals) {
        if (sigaction(sig, &sa, nullptr) != 0) {
            std::cerr << "FATAL: sigaction failed for signal " << sig << std::endl;
            return false;
        }
    }

    struct sigaction sa_ign;
    std::memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    if (sigaction(SIGPIPE, &sa_ign, nullptr) != 0) {
        std::cerr << "FATAL: sigaction failed for SIGPIPE" << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (!install_signal_handlers()) {
        return 1;
    }

    // 配置根目录：命令行参数优先，否则使用默认 roots
    std::string config_root;
    if (argc > 1) {
        config_root = argv[1];
    }
    auto& cm = hwyz::config::ConfigManager::instance();
    auto err = config_root.empty()
        ? cm.load("sec")
        : cm.load("sec", config_root);
    if (err != hwyz::config::ConfigError::kOk) {
        auto info = cm.getLastError();
        std::cerr << "FATAL: Config load failed: " << info.message << std::endl;
        return 1;
    }

    auto cfg = cm.getSnapshot();

    // framework-log 初始化（strict 失败 fail-closed）
    tbox::fw::log::LogConfig log_config;
    log_config.level = tbox::fw::log::LogLevel::kInfo;
    log_config.strict = false;
    std::string log_level_str = cfg->getString("common.log.level", "info");
    if (log_level_str == "trace") log_config.level = tbox::fw::log::LogLevel::kTrace;
    else if (log_level_str == "debug") log_config.level = tbox::fw::log::LogLevel::kDebug;
    else if (log_level_str == "info") log_config.level = tbox::fw::log::LogLevel::kInfo;
    else if (log_level_str == "warn") log_config.level = tbox::fw::log::LogLevel::kWarn;
    else if (log_level_str == "error") log_config.level = tbox::fw::log::LogLevel::kError;

    auto log_result = SecLogAdapter::init("sec", log_config);
    if (log_result.error != tbox::fw::log::LogError::kOk) {
        std::cerr << "FATAL: Logger init failed: " << log_result.error_message << std::endl;
        return 1;
    }

    SecLogAdapter::service().info("sec.service.starting",
        "TBOX SEC Service Starting (legacy lifecycle)");

    std::string store_root = cfg->getString("common.store.root", "/var/lib/tbox");
    std::string ipc_socket_path = cfg->getString("sec.ipc.socket_path", "/tmp/tbox-sec.sock");
    std::string prov_socket_path = cfg->getString("prov.socket_path", "/tmp/tbox-prov.sock");

    tbox::fw::ipc::IpcConfig ipc_config;
    ipc_config.max_frame_bytes = static_cast<uint32_t>(
        cfg->getInt("common.ipc.max_frame_bytes", 10485760));
    ipc_config.receive_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.receive_timeout_ms", 60000));
    ipc_config.connect_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.connect_timeout_ms", 3000));
    ipc_config.listen_backlog = cfg->getInt("common.ipc.listen_backlog", 5);
    ipc_config.reconnect.initial_backoff_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.reconnect.initial_backoff_ms", 100));
    ipc_config.reconnect.max_backoff_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.reconnect.max_backoff_ms", 5000));
    ipc_config.reconnect.multiplier =
        cfg->getDouble("common.ipc.reconnect.multiplier", 2.0);

    SecServiceConfig svc_config;
    svc_config.config_snapshot = cfg;
    svc_config.ipc_config = ipc_config;
    svc_config.ipc_socket_path = ipc_socket_path;

    // PROV client
    auto prov_service = std::make_shared<IpcProvService>(prov_socket_path);
    if (prov_service->initialize() != ErrorCode::SUCCESS) {
        SecLogAdapter::service().error("sec.service.prov_init_failed",
            "Failed to connect to PROV service");
        return 1;
    }

    // Store + SecService
    auto store = hwyz::store::Store::open("sec", store_root);
    auto service = std::make_shared<SecService>(svc_config, nullptr, prov_service, std::move(store));
    if (service->initialize() != ErrorCode::SUCCESS) {
        SecLogAdapter::service().error("sec.service.initialization_failed",
            "Failed to initialize SEC service");
        return 1;
    }

    // 手动装配 PeerCredentialResolver + SecIpcDispatcher + framework-ipc Server
    // （等价 SecApplication 的 IPC 部分）
    std::shared_ptr<PeerCredentialResolver> peer_resolver;
    std::string dev_peer = svc_config.get_tls_dev_peer_service();
    if (!dev_peer.empty() && !svc_config.get_is_production()) {
        peer_resolver = std::make_shared<DevPeerCredentialResolver>(dev_peer);
    } else {
        peer_resolver = std::make_shared<SystemdPeerCredentialResolver>();
    }

    auto dispatcher = std::make_unique<SecIpcDispatcher>(service.get());
    if (auto* tls_provider = service->tls_credential_provider()) {
        dispatcher->setTlsCredentialProvider(tls_provider);
    }
    dispatcher->setPeerCredentialResolver(peer_resolver);

    auto ipc_server = std::make_unique<tbox::fw::ipc::Server>(ipc_socket_path, ipc_config);
    auto* server_ptr = ipc_server.get();
    dispatcher->setAddSubscriptionCallback(
        [server_ptr](int client_fd, uint32_t event_type) -> bool {
            return server_ptr->add_subscription(client_fd, event_type);
        });
    service->setEventPublisher(
        [server_ptr](uint32_t event_type, const std::string& payload_json) {
            server_ptr->push_event(event_type, payload_json);
        });

    auto* dispatcher_ptr = dispatcher.get();
    auto request_handler = [dispatcher_ptr](uint32_t method_id,
                                            std::string_view params_json,
                                            int client_fd) -> std::string {
        return dispatcher_ptr->dispatch(method_id, params_json, client_fd);
    };
    if (!ipc_server->start(std::move(request_handler), {})) {
        SecLogAdapter::service().error("sec.service.ipc_start_failed",
            "Failed to start IPC server");
        return 1;
    }

    SecLogAdapter::service().info("sec.service.ready",
        "SEC service is ready to accept IPC connections");

    while (!shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    SecLogAdapter::service().info("sec.service.shutting_down",
        "Shutting down SEC service...",
        {tbox::fw::log::Field("signal",
            tbox::fw::log::FieldValue::makeInt(static_cast<int>(received_signal)))});

    service->beginShutdown();
    ipc_server->stop();
    dispatcher.reset();

    SecLogAdapter::service().info("sec.service.stopped",
        "SEC service stopped");
    return 0;
}

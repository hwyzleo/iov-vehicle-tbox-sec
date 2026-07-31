//
// TBOX-SEC-DSN-CR-011: SecApplication 实现。
// 组合根装配顺序：Store -> ProvClient -> SecService -> PeerResolver/Dispatcher -> ipc::Server
// 清理顺序（§7）：beginShutdown -> ipc::Server::stop -> dispatcher_.reset
//                   -> peer_resolver_.reset -> security_service_.reset -> prov_client_.reset
//

#include "sec_application.h"
#include "sec_ipc_dispatcher.h"
#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "ipc_prov_service.h"
#include "sec_log_adapter.h"
#include "log.h"
#include "config.h"
#include "store.h"
#include "ipc_protocol.h"

#include <csignal>
#include <chrono>

namespace tbox {
namespace sec {

SecApplication::SecApplication() = default;

// 析构定义于 .cpp：此时 SecIpcDispatcher/PeerCredentialResolver 已完整可见，
// unique_ptr 析构方可实例化（避免 incomplete type）。
SecApplication::~SecApplication() = default;

// ============================================================
// 服务标识
// ============================================================

std::string SecApplication::getServiceName() const {
    return "sec";
}

// ============================================================
// 初始化
// ============================================================

bool SecApplication::initialize() {
    // Application::run 已完成 Config::load + Logger::init + 信号安装。
    // 此处只获取配置快照并装配业务组件。
    auto cfg = getConfigSnapshot();
    if (!cfg) {
        SecLogAdapter::service().error(
            "sec.application.config_unavailable",
            "Config snapshot unavailable after Application::load_config");
        return false;
    }

    // ---- 读取 IPC 配置（common.ipc.* + sec.ipc.*）----
    ipc_socket_path_ = cfg->getString("sec.ipc.socket_path",
                                       "/tmp/tbox-sec.sock");
    ipc_config_.max_frame_bytes = static_cast<uint32_t>(
        cfg->getInt("common.ipc.max_frame_bytes", 10485760));
    ipc_config_.receive_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.receive_timeout_ms", 60000));
    ipc_config_.connect_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.connect_timeout_ms", 3000));
    ipc_config_.listen_backlog =
        cfg->getInt("common.ipc.listen_backlog", 5);
    ipc_config_.reconnect.initial_backoff_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.reconnect.initial_backoff_ms", 100));
    ipc_config_.reconnect.max_backoff_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.reconnect.max_backoff_ms", 5000));
    ipc_config_.reconnect.multiplier =
        cfg->getDouble("common.ipc.reconnect.multiplier", 2.0);

    // ---- 构建 SecServiceConfig（framework-config 类型化访问）----
    SecServiceConfig svc_config;
    svc_config.config_snapshot = cfg;
    svc_config.ipc_config = ipc_config_;
    svc_config.ipc_socket_path = ipc_socket_path_;

    std::string store_root = cfg->getString("common.store.root", "/var/lib/tbox");
    std::string prov_socket_path = cfg->getString("prov.socket_path",
                                                   "/tmp/tbox-prov.sock");

    // ---- a. Store（仅非秘密状态；framework-store 原子写）----
    std::optional<hwyz::store::Store> store_opt;
    try {
        store_opt = hwyz::store::Store::open("sec", store_root);
    } catch (const std::exception& e) {
        SecLogAdapter::service().error(
            "sec.application.store_open_failed",
            "Store open failed",
            {tbox::fw::log::Field("store_root",
                tbox::fw::log::FieldValue::makeString(store_root)),
             tbox::fw::log::Field("reason",
                tbox::fw::log::FieldValue::makeString(e.what()))});
        return false;
    }
    init_stage_ = InitStage::StoreOpened;

    // ---- b. PROV client（经 framework-ipc 调 readVIN()/readBinding()）----
    prov_client_ = createProvClient(prov_socket_path);
    if (prov_client_->initialize() != ErrorCode::SUCCESS) {
        SecLogAdapter::service().error(
            "sec.application.prov_init_failed",
            "PROV client initialize failed",
            {tbox::fw::log::Field("prov_socket_path",
                tbox::fw::log::FieldValue::makeString(prov_socket_path))});
        rollbackInitialization();
        return false;
    }
    init_stage_ = InitStage::ProvClientReady;

    // ---- c. SecService（安全业务内核：HSM/KeyEngine/CsrBuilder/CertValidator/
    //                    CloudClient/SeedKey/TlsCredentialProvider）----
    security_service_ = std::make_shared<SecService>(
        svc_config, nullptr, prov_client_, std::move(*store_opt));
    if (security_service_->initialize() != ErrorCode::SUCCESS) {
        SecLogAdapter::service().error(
            "sec.application.service_init_failed",
            "SecService initialize failed");
        rollbackInitialization();
        return false;
    }
    init_stage_ = InitStage::ServiceReady;

    // ---- d. PeerCredentialResolver（= CR mqtt_acl）+ SecIpcDispatcher ----
    // 开发/测试：配置了 sec.tls.dev_peer_service 且非生产环境时，
    // 使用 DevPeerCredentialResolver 绕过 SO_PEERCRED（如 macOS 本地联调）。
    std::string dev_peer = svc_config.get_tls_dev_peer_service();
    if (!dev_peer.empty() && !svc_config.get_is_production()) {
        SecLogAdapter::ipc().warn(
            "sec.ipc.dev_peer_resolver_enabled",
            "已启用开发用 peer 身份解析器，TLS ACL 将固定放行（仅限非生产环境）",
            {tbox::fw::log::Field("service_name",
                tbox::fw::log::FieldValue::makeString(dev_peer))});
        peer_resolver_ = std::make_shared<DevPeerCredentialResolver>(dev_peer);
    } else {
        peer_resolver_ = std::make_shared<SystemdPeerCredentialResolver>();
    }

    dispatcher_ = std::make_unique<SecIpcDispatcher>(security_service_.get());
    // 注入 TLS Credential Provider（保留在 SecService 内，经 getter 暴露）
    if (auto* tls_provider = security_service_->tls_credential_provider()) {
        dispatcher_->setTlsCredentialProvider(tls_provider);
    }
    dispatcher_->setPeerCredentialResolver(peer_resolver_);
    init_stage_ = InitStage::DispatcherReady;

    // ---- e. ipc::Server（传输与适配由组合根持有）----
    ipc_server_ = std::make_unique<tbox::fw::ipc::Server>(
        ipc_socket_path_, ipc_config_);

    // 接线 add_subscription 回调到 Server
    auto* server_ptr = ipc_server_.get();
    dispatcher_->setAddSubscriptionCallback(
        [server_ptr](int client_fd, uint32_t event_type) -> bool {
            return server_ptr->add_subscription(client_fd, event_type);
        });

    // 接线 TLS 凭据变更事件发布（解耦：SecService 经 event_publisher_ 推送，
    // 不再直接持有 ipc::Server）
    security_service_->setEventPublisher(
        [server_ptr](uint32_t event_type, const std::string& payload_json) {
            server_ptr->push_event(event_type, payload_json);
        });

    // framework RequestHandler -> dispatcher
    auto* dispatcher_ptr = dispatcher_.get();
    auto request_handler = [dispatcher_ptr](uint32_t method_id,
                                            std::string_view params_json,
                                            int client_fd) -> std::string {
        return dispatcher_ptr->dispatch(method_id, params_json, client_fd);
    };
    // disconnect handler: 仅清理 SEC 业务引用；fd/订阅由 framework 清理
    auto disconnect_handler = [](int client_fd) {
        SecLogAdapter::ipc().debug(
            "sec.ipc.client_disconnected",
            "Client disconnected (framework)",
            {tbox::fw::log::Field("client_fd",
                tbox::fw::log::FieldValue::makeInt(client_fd))});
    };

    if (!ipc_server_->start(std::move(request_handler), std::move(disconnect_handler))) {
        SecLogAdapter::service().error(
            "sec.application.ipc_start_failed",
            "IPC server start failed",
            {tbox::fw::log::Field("socket_path",
                tbox::fw::log::FieldValue::makeString(ipc_socket_path_))});
        // bind/listen 失败后不得遗留 socket 路径
        ipc_server_.reset();
        dispatcher_.reset();
        peer_resolver_.reset();
        rollbackInitialization();
        return false;
    }
    init_stage_ = InitStage::IpcStarted;

    SecLogAdapter::ipc().info(
        "sec.ipc.server_started",
        "IPC server started (framework-ipc)",
        {tbox::fw::log::Field("socket_path",
            tbox::fw::log::FieldValue::makeString(ipc_socket_path_))});
    return true;
}

void SecApplication::rollbackInitialization() {
    // 逆序释放已完成的阶段（CR-011 §4.3）
    if (init_stage_ == InitStage::IpcStarted) {
        if (ipc_server_) ipc_server_->stop();
        ipc_server_.reset();
        dispatcher_.reset();
        peer_resolver_.reset();
        init_stage_ = InitStage::DispatcherReady;
    }
    if (init_stage_ == InitStage::DispatcherReady) {
        dispatcher_.reset();
        peer_resolver_.reset();
        init_stage_ = InitStage::ServiceReady;
    }
    if (init_stage_ == InitStage::ServiceReady) {
        if (security_service_) security_service_->beginShutdown();
        security_service_.reset();
        init_stage_ = InitStage::ProvClientReady;
    }
    if (init_stage_ == InitStage::ProvClientReady) {
        prov_client_.reset();
        init_stage_ = InitStage::StoreOpened;
    }
    if (init_stage_ == InitStage::StoreOpened) {
        // Store 已移入 SecService 并随其销毁；此处无独立资源需释放。
        init_stage_ = InitStage::None;
    }
}

// ============================================================
// 可测试性钩子
// ============================================================

std::shared_ptr<ProvServiceInterface> SecApplication::createProvClient(
    const std::string& socket_path) {
    return std::make_shared<IpcProvService>(socket_path);
}

// ============================================================
// 长驻执行
// ============================================================

int SecApplication::execute() {
    SecLogAdapter::service().info(
        "sec.service.ready", "SEC service is ready");
    // 不维护私有 running 标志，不依赖 EINTR；统一等待 Application 退出状态。
    waitForShutdown(std::chrono::milliseconds{100});
    return 0;
}

// ============================================================
// 清理（幂等有序停机）
// ============================================================

void SecApplication::cleanup() {
    // 1. Quiesce：拒绝新安全操作（getSeed/verifyKey/密钥生成/证书注入/TLS sign）
    if (security_service_) {
        security_service_->beginShutdown();
    }
    // 2. Stop IPC：中断 accept/read，关闭连接与订阅，join 连接线程
    if (ipc_server_) {
        ipc_server_->stop();
    }
    // 3. 销毁 dispatcher（线程退出后才销毁，防 use-after-free）
    dispatcher_.reset();
    // 4. 释放 ACL（peer credential resolver）
    peer_resolver_.reset();
    // 5. 销毁 security service（业务内核、HSM、TLS provider、store 随之释放；
    //    framework-store 原子写已逐次落盘，无需额外 flush）
    security_service_.reset();
    // 6. 释放 PROV client
    prov_client_.reset();
    ipc_server_.reset();
    init_stage_ = InitStage::None;
    // 最终日志 flush 由 Application::run 在 cleanup 后统一完成。
}

} // namespace sec
} // namespace tbox

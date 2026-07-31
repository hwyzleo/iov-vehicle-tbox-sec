#pragma once

//
// TBOX-SEC-DSN-CR-011: SecApplication 作为组合根（Composition Root）。
// 继承 hwyz::Application，统一编排配置加载、framework-log 初始化、信号安装、
// 长驻执行与最终 flush；装配并释放 IpcProvService / SecService /
// PeerCredentialResolver / SecIpcDispatcher / framework-ipc Server。
//
// 生命周期不变量（CR-011 §7）：
//   cleanup 顺序 = SecService::beginShutdown -> ipc::Server::stop -> dispatcher_.reset
//                  -> peer_resolver_.reset -> security_service_.reset
//                  -> prov_client_.reset
//   dispatcher_ 必须先于 security_service_ 销毁（dispatcher 持 service 裸指针）；
//   dispatcher_ 必须在 ipc::Server::stop join 线程后才销毁（防 use-after-free）。
//
// 设计说明：Store 经 Store::open 打开后按值移入 SecService（与既有构造契约一致，
// SecService 拥有 store）。framework-store 原子写已逐次落盘，cleanup 无需额外 flush
// （与 PROV CR-008 同构）。
//

#include "application.h"
#include "sec_service.h"
#include "ipc.h"
#include "ipc_types.h"

#include <optional>
#include <memory>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

class SecIpcDispatcher;
class PeerCredentialResolver;
class ProvServiceInterface;

// 注：未标记 final，以便白盒单元测试通过派生访问 protected 生命周期钩子；
// 生产语义上 SecApplication 仍为组合根叶子类，不作为扩展基类。
class SecApplication : public hwyz::Application {
public:
    SecApplication();
    ~SecApplication() override;

protected:
    // ============ 服务标识与信号 ============
    std::string getServiceName() const override;
    // CR-011 §6: 沿用 Application 默认信号集合：
    //   graceful = {SIGINT, SIGTERM}（SA_RESTART）
    //   ignored  = {SIGPIPE}
    //   fatal    = {SIGSEGV, SIGABRT}（SA_RESETHAND）
    // 不覆盖 gracefulSignals/ignoredSignals/fatalSignals。

    // ============ 生命周期 ============
    bool initialize() override;
    int execute() override;
    void cleanup() override;

    // ============ 可测试性钩子 ============
    // 创建 PROV client。默认返回 IpcProvService（连框架 PROV daemon）；
    // 单测可 override 返回 MockProvService 以脱离真实 PROV 依赖。
    virtual std::shared_ptr<ProvServiceInterface> createProvClient(
        const std::string& socket_path);

private:
    enum class InitStage {
        None,
        StoreOpened,
        ProvClientReady,
        ServiceReady,
        DispatcherReady,
        IpcStarted
    };

    // 逆序释放已完成的初始化阶段（initialize 失败时调用）
    void rollbackInitialization();

    InitStage init_stage_{InitStage::None};

    // 组合根持有的全部组件（RAII）
    std::shared_ptr<ProvServiceInterface> prov_client_;
    std::shared_ptr<SecService> security_service_;
    std::shared_ptr<PeerCredentialResolver> peer_resolver_;  // = CR mqtt_acl
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
    std::unique_ptr<tbox::fw::ipc::Server> ipc_server_;

    // initialize 读取、execute/cleanup 复用的配置
    std::string ipc_socket_path_;
    tbox::fw::ipc::IpcConfig ipc_config_{};
};

} // namespace sec
} // namespace tbox

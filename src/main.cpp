#include <atomic>
#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include "sec_service.h"
#include "ipc_prov_service.h"
#include "config.h"
#include "store.h"

using namespace tbox::sec;

std::shared_ptr<SecService> g_sec_service;
std::atomic<bool> g_running{true};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cerr << "\n[signal] received signal " << signal << ", requesting shutdown" << std::endl;
        g_running = false;
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    std::cout << "TBOX Security Service Starting..." << std::endl;

    std::string config_root = "/etc/tbox";
    
    // 多层配置查找：当前目录 -> config目录 -> 上级config目录 -> 系统目录
    if (argc > 1) {
        // 命令行参数优先
        config_root = argv[1];
    } else {
        // 检查当前目录是否有 common.yaml
        if (access("common.yaml", F_OK) == 0) {
            config_root = ".";
        }
        // 检查 config 目录
        else if (access("config/common.yaml", F_OK) == 0) {
            config_root = "config";
        }
        // 检查上级 config 目录（用于在 build 目录中运行）
        else if (access("../config/common.yaml", F_OK) == 0) {
            config_root = "../config";
        }
        // 否则使用默认系统目录 /etc/tbox
        else {
            config_root = "/etc/tbox";
        }
    }
    
    std::cout << "Using config root: " << config_root << std::endl;

    auto& config_manager = hwyz::config::ConfigManager::instance();
    auto config_result = config_manager.load("sec", config_root);
    if (config_result != hwyz::config::ConfigError::kOk) {
        std::cerr << "Failed to load configuration from: " << config_root << std::endl;
        std::cerr << "Error code: " << static_cast<uint32_t>(config_result) << std::endl;
        return 1;
    }

    auto config_snapshot = config_manager.getSnapshot();

    SecServiceConfig sec_config;
    sec_config.config_snapshot = config_snapshot;

    std::string prov_socket_path = config_snapshot->getString("prov.socket_path", "/tmp/tbox-prov.sock");
    auto prov_service = std::make_shared<IpcProvService>(prov_socket_path);

    ErrorCode prov_result = prov_service->initialize();
    if (prov_result != ErrorCode::SUCCESS) {
        std::cerr << "Failed to connect to PROV service: "
                  << error_code_to_string(prov_result) << std::endl;
        std::cerr << "Please ensure PROV service is running at " << prov_socket_path << std::endl;
        return 1;
    }

    try {
        auto store = hwyz::store::Store::open("sec");
        g_sec_service = std::make_shared<SecService>(sec_config, nullptr, prov_service, std::move(store));
        ErrorCode result = g_sec_service->initialize();

        if (result != ErrorCode::SUCCESS) {
            std::cerr << "Failed to initialize SEC service: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }

        std::cout << "TBOX Security Service initialized successfully" << std::endl;
        std::cout << g_sec_service->get_device_info() << std::endl;

        if (!g_sec_service->start_ipc_server()) {
            std::cerr << "Failed to start IPC server" << std::endl;
            return 1;
        }

        std::cout << "SEC service is ready to accept IPC connections" << std::endl;

        while (g_running) {
            sleep(1);
        }

        std::cout << "TBOX Security Service shutting down" << std::endl;
        g_sec_service->stop_ipc_server();

    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize SEC service: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

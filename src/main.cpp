#include <atomic>
#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include "sec_service.h"
#include "config.h"
#include "store.h"

using namespace tbox::sec;

class DefaultProvService : public ProvServiceInterface {
public:
    DefaultProvService(const std::string& vin, const std::string& ecu_uid)
        : vin_(vin), ecu_uid_(ecu_uid) {}

    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }

    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = vin_;
        info.device_sn = ecu_uid_;
        return ErrorCode::SUCCESS;
    }

    bool is_connected() const override {
        return true;
    }

    std::string get_service_status() const override {
        return "Default PROV Service";
    }

private:
    std::string vin_;
    std::string ecu_uid_;
};

std::shared_ptr<SecService> g_sec_service;
std::atomic<bool> g_running{true};

void signal_handler(int signal) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 确定配置根目录
    std::string config_root = "/etc/tbox";
    if (argc > 1) {
        config_root = argv[1];
    }

    // 初始化framework-config
    auto& config_manager = hwyz::config::ConfigManager::instance();
    auto config_result = config_manager.load("sec", config_root);
    if (config_result != hwyz::config::ConfigError::kOk) {
        std::cerr << "Failed to load configuration: "
                  << static_cast<uint32_t>(config_result) << std::endl;
        return 1;
    }

    // 获取配置快照
    auto config_snapshot = config_manager.getSnapshot();

    // 创建SecServiceConfig
    SecServiceConfig sec_config;
    sec_config.config_snapshot = config_snapshot;

    // 初始化framework-store
    auto store = hwyz::store::Store::open("sec");

    // 读取VIN和ECU UID配置（用于默认PROV服务）
    std::string vin = config_snapshot->getString("vin", "DEFAULT_VIN");
    std::string ecu_uid = config_snapshot->getString("ecu_uid", "DEFAULT_ECU_UID");

    // 创建默认PROV服务实例
    auto prov_service = std::make_shared<DefaultProvService>(vin, ecu_uid);

    // 创建SEC服务
    try {
        g_sec_service = std::make_shared<SecService>(sec_config, nullptr, prov_service, std::move(store));
        ErrorCode result = g_sec_service->initialize();

        if (result != ErrorCode::SUCCESS) {
            std::cerr << "Failed to initialize SEC service: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }

        std::cout << "TBOX Security Service started successfully" << std::endl;
        std::cout << g_sec_service->get_device_info() << std::endl;

        while (g_running) {
            sleep(1);
        }

        std::cout << "TBOX Security Service shutting down" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize SEC service: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

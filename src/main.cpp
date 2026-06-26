#include <atomic>
#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include "sec_service.h"
#include "yaml-cpp/yaml.h"

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
        info.ecu_uid = ecu_uid_;
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

namespace {

template<typename T>
T get_config_value(const YAML::Node& node, const std::string& key, const std::string& context) {
    if (!node) {
        throw std::runtime_error("Missing config section: " + context);
    }
    if (!node[key]) {
        throw std::runtime_error("Missing config key: " + context + "." + key);
    }
    return node[key].as<T>();
}

}  // namespace

SecServiceConfig load_config(const std::string& config_file) {
    YAML::Node config;
    try {
        config = YAML::LoadFile(config_file);
    } catch (const YAML::BadFile& e) {
        throw std::runtime_error("Cannot open config file: " + config_file);
    } catch (const YAML::ParserException& e) {
        throw std::runtime_error("Invalid YAML in config file: " + std::string(e.what()));
    }

    YAML::Node tbox = config["tbox"];
    if (!tbox) {
        throw std::runtime_error("Missing top-level 'tbox' section in config");
    }

    SecServiceConfig sec_config;
    sec_config.state_file_path = get_config_value<std::string>(
        tbox["storage"], "state_file", "tbox.storage");

    // CA certificate path (optional)
    YAML::Node storage = tbox["storage"];
    if (storage && storage["ca_cert"]) {
        sec_config.ca_cert_path = storage["ca_cert"].as<std::string>();
    }

    // Certificate store path
    if (storage && storage["cert_store"]) {
        sec_config.cert_store_path = storage["cert_store"].as<std::string>();
    }

    YAML::Node hsm = tbox["hsm"];
    sec_config.hsm_type = get_config_value<std::string>(hsm, "type", "tbox.hsm");
    sec_config.hsm_config_path = get_config_value<std::string>(hsm, "library_path", "tbox.hsm");

    YAML::Node cloud = tbox["cloud"];
    sec_config.cloud_config.oapi_endpoint = get_config_value<std::string>(
        cloud, "oapi_endpoint", "tbox.cloud");
    sec_config.cloud_config.timeout_ms = get_config_value<int>(
        cloud, "timeout_ms", "tbox.cloud");
    sec_config.cloud_config.retry_count = get_config_value<int>(
        cloud, "retry_count", "tbox.cloud");
    sec_config.cloud_config.retry_delay_ms = get_config_value<int>(
        cloud, "retry_delay_ms", "tbox.cloud");

    if (sec_config.cloud_config.timeout_ms <= 0) {
        throw std::runtime_error("tbox.cloud.timeout_ms must be positive");
    }
    if (sec_config.cloud_config.retry_count < 0) {
        throw std::runtime_error("tbox.cloud.retry_count must be non-negative");
    }
    if (sec_config.cloud_config.retry_delay_ms < 0) {
        throw std::runtime_error("tbox.cloud.retry_delay_ms must be non-negative");
    }

    // 解析密钥生成模式
    if (tbox["key_provisioning"] && tbox["key_provisioning"]["mode"]) {
        sec_config.key_provisioning_mode = tbox["key_provisioning"]["mode"].as<std::string>("hsm");
    }

    // 解析软件落盘配置
    if (tbox["soft_key"]) {
        auto soft_key_node = tbox["soft_key"];
        if (soft_key_node["path"]) {
            sec_config.soft_key_config.key_path = soft_key_node["path"].as<std::string>("/var/lib/tbox/sec/soft_keys");
        }
        if (soft_key_node["encryption_algo"]) {
            sec_config.soft_key_config.encryption_algo = soft_key_node["encryption_algo"].as<std::string>("aes-256-gcm");
        }
        if (soft_key_node["encryption_key_path"]) {
            sec_config.soft_key_config.encryption_key_path = soft_key_node["encryption_key_path"].as<std::string>("");
        }
    }

    // 解析环境配置
    if (tbox["environment"]) {
        if (tbox["environment"]["is_production"]) {
            sec_config.is_production = tbox["environment"]["is_production"].as<bool>(false);
        }
    }

    return sec_config;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::string config_file = "config/config.yaml";
    if (argc > 1) {
        config_file = argv[1];
    }

    try {
        SecServiceConfig config = load_config(config_file);

        // 读取VIN和ECU UID配置（用于默认PROV服务）
        YAML::Node yaml_config = YAML::LoadFile(config_file);
        YAML::Node tbox = yaml_config["tbox"];
        std::string vin = "DEFAULT_VIN";
        std::string ecu_uid = "DEFAULT_ECU_UID";
        if (tbox && tbox["vin"]) {
            vin = tbox["vin"].as<std::string>();
        }
        if (tbox && tbox["ecu_uid"]) {
            ecu_uid = tbox["ecu_uid"].as<std::string>();
        }

        // 创建默认PROV服务实例
        auto prov_service = std::make_shared<DefaultProvService>(vin, ecu_uid);

        g_sec_service = std::make_shared<SecService>(config, nullptr, prov_service);
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
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

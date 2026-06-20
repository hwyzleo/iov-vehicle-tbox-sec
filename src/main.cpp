#include <atomic>
#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include "sec_service.h"
#include "uds_handler.h"
#include "yaml-cpp/yaml.h"

using namespace tbox::sec;

std::shared_ptr<SecService> g_sec_service;
std::unique_ptr<UdsHandler> g_uds_handler;
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
    sec_config.vin = get_config_value<std::string>(tbox, "vin", "tbox");
    sec_config.ecu_uid = get_config_value<std::string>(tbox, "ecu_uid", "tbox");
    sec_config.state_file_path = get_config_value<std::string>(
        tbox["storage"], "state_file", "tbox.storage");

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

        g_sec_service = std::make_shared<SecService>(config);
        ErrorCode result = g_sec_service->initialize();

        if (result != ErrorCode::SUCCESS) {
            std::cerr << "Failed to initialize SEC service: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }

        g_uds_handler = std::make_unique<UdsHandler>(g_sec_service);
        result = g_uds_handler->initialize();

        if (result != ErrorCode::SUCCESS) {
            std::cerr << "Failed to initialize UDS handler: "
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

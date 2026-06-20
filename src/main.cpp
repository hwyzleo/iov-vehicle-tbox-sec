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
bool g_running = true;

void signal_handler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
}

SecServiceConfig load_config(const std::string& config_file) {
    YAML::Node config = YAML::LoadFile(config_file);

    SecServiceConfig sec_config;
    sec_config.vin = config["tbox"]["vin"].as<std::string>();
    sec_config.ecu_uid = config["tbox"]["ecu_uid"].as<std::string>();
    sec_config.hsm_type = config["tbox"]["hsm"]["type"].as<std::string>();
    sec_config.hsm_config_path = config["tbox"]["hsm"]["library_path"].as<std::string>();
    sec_config.state_file_path = config["tbox"]["storage"]["state_file"].as<std::string>();

    sec_config.cloud_config.oapi_endpoint = config["tbox"]["cloud"]["oapi_endpoint"].as<std::string>();
    sec_config.cloud_config.timeout_ms = config["tbox"]["cloud"]["timeout_ms"].as<int>();
    sec_config.cloud_config.retry_count = config["tbox"]["cloud"]["retry_count"].as<int>();
    sec_config.cloud_config.retry_delay_ms = config["tbox"]["cloud"]["retry_delay_ms"].as<int>();

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

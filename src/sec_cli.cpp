#include "sec_service.h"
#include "config.h"
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

using namespace tbox::sec;

void print_usage() {
    std::cout << "SEC CLI Tool" << std::endl;
    std::cout << "Usage: sec_cli <command> [args...]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  init                         - Initialize SEC service" << std::endl;
    std::cout << "  generate_key                 - Generate device key pair" << std::endl;
    std::cout << "  get_csr                      - Get CSR (PEM format)" << std::endl;
    std::cout << "  save_csr <file>              - Save CSR to file" << std::endl;
    std::cout << "  submit_csr                   - Submit CSR to cloud" << std::endl;
    std::cout << "  inject_cert <file>           - Inject certificate from file" << std::endl;
    std::cout << "  apply_cert                   - Apply certificate (full flow)" << std::endl;
    std::cout << "  set_ca_cert <file>           - Set CA certificate" << std::endl;
    std::cout << "  get_seed <level>             - Get security seed" << std::endl;
    std::cout << "  verify_key <level> <hex_key> - Verify key" << std::endl;
    std::cout << "  get_status                   - Get provision status" << std::endl;
    std::cout << "  get_device_info              - Get device information" << std::endl;
    std::cout << "  reset_status                 - Reset provision status" << std::endl;
    std::cout << "  show_config                  - Show current configuration" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string command = argv[1];

    // Load framework configuration
    auto err = CONFIG_MANAGER.load("sec");
    if (err != hwyz::config::ConfigError::kOk) {
        auto info = CONFIG_MANAGER.getLastError();
        std::cerr << "Config load failed: " << info.message << std::endl;
        return 1;
    }

    // Read service parameters from configuration
    auto cfg = CONFIG_SNAPSHOT;
    SecServiceConfig config;
    config.config_snapshot = cfg;

    // Create and initialize SEC service
    SecService service(config);
    auto result = service.initialize();

    if (result != ErrorCode::SUCCESS) {
        std::cerr << "Failed to initialize SEC service: " 
                  << error_code_to_string(result) << std::endl;
        return 1;
    }

    // TODO: Handle commands
    
    return 0;
}

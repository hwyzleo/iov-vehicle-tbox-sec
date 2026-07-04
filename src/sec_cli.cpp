#include "sec_service.h"
#include "config.h"
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <iomanip>

using namespace tbox::sec;

std::string der_to_pem(const std::vector<uint8_t>& der, const std::string& type) {
    std::string pem;
    pem += "-----BEGIN " + type + "-----\n";
    
    const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    int in_len = der.size();
    int pos = 0;
    
    while (in_len--) {
        char_array_3[i++] = der[pos++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; (i < 4); i++)
                pem += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (j = 0; (j < i + 1); j++)
            pem += base64_chars[char_array_4[j]];
        
        while ((i++ < 3))
            pem += '=';
    }
    
    pem += "\n-----END " + type + "-----\n";
    return pem;
}

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

    if (command == "init") {
        std::cout << "SEC service initialized successfully" << std::endl;
    }
    else if (command == "generate_key") {
        result = service.generate_key_pair();
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Key pair generated successfully" << std::endl;
        } else {
            std::cerr << "Failed to generate key pair: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "get_csr") {
        std::vector<uint8_t> csr_der;
        result = service.get_csr(csr_der);
        if (result == ErrorCode::SUCCESS) {
            std::cout << der_to_pem(csr_der, "CERTIFICATE REQUEST");
        } else {
            std::cerr << "Failed to get CSR: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "save_csr") {
        if (argc < 3) {
            std::cerr << "Usage: sec_cli save_csr <file>" << std::endl;
            return 1;
        }
        std::string file_path = argv[2];
        std::vector<uint8_t> csr_der;
        result = service.get_csr(csr_der);
        if (result == ErrorCode::SUCCESS) {
            std::ofstream file(file_path, std::ios::binary);
            if (file.is_open()) {
                file.write(reinterpret_cast<const char*>(csr_der.data()), csr_der.size());
                file.close();
                std::cout << "CSR saved to " << file_path << std::endl;
            } else {
                std::cerr << "Failed to open file: " << file_path << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Failed to get CSR: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "submit_csr") {
        result = service.submit_csr();
        if (result == ErrorCode::SUCCESS) {
            std::cout << "CSR submitted successfully" << std::endl;
        } else {
            std::cerr << "Failed to submit CSR: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "inject_cert") {
        if (argc < 3) {
            std::cerr << "Usage: sec_cli inject_cert <file>" << std::endl;
            return 1;
        }
        std::string file_path = argv[2];
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << file_path << std::endl;
            return 1;
        }
        std::vector<uint8_t> cert_der(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();
        
        result = service.inject_certificate(cert_der);
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Certificate injected successfully" << std::endl;
        } else {
            std::cerr << "Failed to inject certificate: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "apply_cert") {
        result = service.apply_certificate();
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Certificate application completed" << std::endl;
        } else {
            std::cerr << "Failed to apply certificate: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "set_ca_cert") {
        if (argc < 3) {
            std::cerr << "Usage: sec_cli set_ca_cert <file>" << std::endl;
            return 1;
        }
        std::string file_path = argv[2];
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << file_path << std::endl;
            return 1;
        }
        std::vector<uint8_t> ca_cert_der(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();
        
        result = service.set_ca_certificate(ca_cert_der);
        if (result == ErrorCode::SUCCESS) {
            std::cout << "CA certificate set successfully" << std::endl;
        } else {
            std::cerr << "Failed to set CA certificate: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "get_seed") {
        if (argc < 3) {
            std::cerr << "Usage: sec_cli get_seed <level>" << std::endl;
            return 1;
        }
        uint8_t level = static_cast<uint8_t>(std::stoul(argv[2], nullptr, 0));
        std::vector<uint8_t> seed;
        result = service.get_seed(level, seed);
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Seed: ";
            for (auto b : seed) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<int>(b);
            }
            std::cout << std::endl;
        } else {
            std::cerr << "Failed to get seed: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "verify_key") {
        if (argc < 4) {
            std::cerr << "Usage: sec_cli verify_key <level> <hex_key>" << std::endl;
            return 1;
        }
        uint8_t level = static_cast<uint8_t>(std::stoul(argv[2], nullptr, 0));
        std::string hex_key = argv[3];
        
        // Convert hex string to bytes
        std::vector<uint8_t> key;
        for (size_t i = 0; i < hex_key.length(); i += 2) {
            std::string byte_string = hex_key.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_string, nullptr, 16));
            key.push_back(byte);
        }
        
        result = service.verify_key(level, key);
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Key verification successful" << std::endl;
        } else {
            std::cerr << "Key verification failed: " 
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        print_usage();
        return 1;
    }

    return 0;
}

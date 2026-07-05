#include "sec_client.h"
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <iomanip>
#include <nlohmann/json.hpp>

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
    std::cout << "SEC CLI Tool (IPC Client)" << std::endl;
    std::cout << "Usage: sec_cli [-s <socket_path>] <command> [args...]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s, --socket <socket_path>  - Specify IPC socket path (default: /tmp/tbox-sec.sock)" << std::endl;
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
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string command = argv[1];
    std::string socket_path = "/tmp/tbox-sec.sock";

    if (command == "-s" || command == "--socket") {
        if (argc < 4) {
            std::cerr << "Usage: sec_cli -s <socket_path> <command> [args...]" << std::endl;
            return 1;
        }
        socket_path = argv[2];
        command = argv[3];
        argc -= 2;
        argv += 2;
    }

    SecClient client(socket_path);
    if (!client.connect()) {
        std::cerr << "Failed to connect to SEC service at " << socket_path << std::endl;
        std::cerr << "Please ensure TboxSecService is running" << std::endl;
        return 1;
    }

    std::cout << "Connected to SEC service" << std::endl;

    if (command == "init") {
        auto result = client.initialize();
        if (result == ErrorCode::SUCCESS) {
            std::cout << "SEC service initialized successfully" << std::endl;
        } else {
            std::cerr << "Failed to initialize SEC service: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "generate_key") {
        auto result = client.generate_key_pair();
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
        auto result = client.get_csr(csr_der);
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
        auto result = client.get_csr(csr_der);
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
        auto result = client.submit_csr();
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

        auto result = client.inject_certificate(cert_der);
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Certificate injected successfully" << std::endl;
        } else {
            std::cerr << "Failed to inject certificate: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "apply_cert") {
        auto result = client.apply_certificate();
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

        auto result = client.set_ca_certificate(ca_cert_der);
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
        auto result = client.get_seed(level, seed);
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

        std::vector<uint8_t> key;
        for (size_t i = 0; i < hex_key.length(); i += 2) {
            std::string byte_string = hex_key.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_string, nullptr, 16));
            key.push_back(byte);
        }

        auto result = client.verify_key(level, key);
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Key verification successful" << std::endl;
        } else {
            std::cerr << "Key verification failed: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else if (command == "get_status") {
        auto status = client.get_provision_status();
        std::cout << "Provision State: " << status.state << std::endl;
        std::cout << "VIN: " << (status.vin.empty() ? "(not available)" : status.vin) << std::endl;
        std::cout << "Device SN: " << (status.ecu_uid.empty() ? "(not available)" : status.ecu_uid) << std::endl;
        std::cout << "Retry Count: " << status.retry_count << std::endl;
        std::cout << "Last Error: " << (status.last_error.empty() ? "(none)" : status.last_error) << std::endl;
    }
    else if (command == "get_device_info") {
        std::string device_info = client.get_device_info();
        std::cout << device_info;
    }
    else if (command == "reset_status") {
        auto result = client.reset_provision_status();
        if (result == ErrorCode::SUCCESS) {
            std::cout << "Provision status reset successfully" << std::endl;
        } else {
            std::cerr << "Failed to reset provision status: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        print_usage();
        return 1;
    }

    client.disconnect();
    return 0;
}

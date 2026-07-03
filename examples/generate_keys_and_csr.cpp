#include <iostream>
#include <fstream>
#include <filesystem>
#include "sec_service.h"

using namespace tbox::sec;
namespace fs = std::filesystem;

class SimpleProvService : public ProvServiceInterface {
public:
    SimpleProvService(const std::string& vin, const std::string& ecu_uid)
        : vin_(vin), ecu_uid_(ecu_uid) {}

    ErrorCode initialize() override { return ErrorCode::SUCCESS; }

    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = vin_;
        info.device_sn = ecu_uid_;
        return ErrorCode::SUCCESS;
    }

    bool is_connected() const override { return true; }
    std::string get_service_status() const override { return "Simple PROV Service"; }

private:
    std::string vin_;
    std::string ecu_uid_;
};

int main() {
    std::cout << "=== TBOX Security Service - Key & CSR Generation ===" << std::endl;
    std::cout << std::endl;

    // 配置
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "soft_file";  // 使用软件落盘模式
    config.soft_key_config.key_path = "./data/soft_keys";
    config.state_file_path = "./data/provision_state.json";
    config.cert_store_path = "./data/certs";
    config.is_production = false;

    // 设备信息
    std::string vin = "TESTVIN1234567890";
    std::string ecu_uid = "00000000000000000000000000000001";

    // 创建目录
    fs::create_directories("./data/soft_keys");
    fs::create_directories("./data/certs");

    // 创建服务
    auto prov_service = std::make_shared<SimpleProvService>(vin, ecu_uid);
    SecService service(config, nullptr, prov_service);

    // 初始化
    std::cout << "[1] Initializing service..." << std::endl;
    ErrorCode result = service.initialize();
    if (result != ErrorCode::SUCCESS) {
        std::cerr << "Failed to initialize: " << error_code_to_string(result) << std::endl;
        return 1;
    }
    std::cout << "    Service initialized successfully" << std::endl;
    std::cout << std::endl;

    // 生成密钥对
    std::cout << "[2] Generating key pair..." << std::endl;
    result = service.generate_key_pair();
    if (result != ErrorCode::SUCCESS) {
        std::cerr << "Failed to generate key pair: " << error_code_to_string(result) << std::endl;
        return 1;
    }
    std::cout << "    Key pair generated successfully" << std::endl;
    std::cout << std::endl;

    // 获取 CSR
    std::cout << "[3] Building CSR..." << std::endl;
    std::vector<uint8_t> csr_der;
    result = service.get_csr(csr_der);
    if (result != ErrorCode::SUCCESS) {
        std::cerr << "Failed to get CSR: " << error_code_to_string(result) << std::endl;
        return 1;
    }
    std::cout << "    CSR built successfully (" << csr_der.size() << " bytes)" << std::endl;
    std::cout << std::endl;

    // 保存 CSR 到文件
    std::string csr_file = "./data/certs/device.csr";
    std::ofstream ofs(csr_file, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(csr_der.data()), csr_der.size());
    ofs.close();
    std::cout << "[4] CSR saved to: " << csr_file << std::endl;
    std::cout << std::endl;

    // 显示生成的文件
    std::cout << "=== Generated Files ===" << std::endl;
    std::cout << std::endl;

    // 软件密钥文件
    std::cout << "1. Software Keys (encrypted):" << std::endl;
    for (const auto& entry : fs::directory_iterator("./data/soft_keys")) {
        if (entry.path().extension() == ".json") {
            std::cout << "   - " << entry.path() << std::endl;
        }
    }
    std::cout << std::endl;

    // 加密密钥
    std::cout << "2. Encryption Key:" << std::endl;
    std::cout << "   - ./data/soft_keys/.encryption_key" << std::endl;
    std::cout << std::endl;

    // CSR 文件
    std::cout << "3. CSR File:" << std::endl;
    std::cout << "   - " << csr_file << std::endl;
    std::cout << std::endl;

    // Provision 状态
    std::cout << "4. Provision State:" << std::endl;
    std::cout << "   - ./data/provision_state.json" << std::endl;
    std::cout << std::endl;

    // 显示设备信息
    std::cout << "=== Device Information ===" << std::endl;
    std::cout << service.get_device_info() << std::endl;
    std::cout << std::endl;

    // 显示密钥内容（用于调试）
    std::cout << "=== CSR Content (DER hex) ===" << std::endl;
    for (size_t i = 0; i < std::min(csr_der.size(), (size_t)64); i++) {
        printf("%02x ", csr_der[i]);
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    if (csr_der.size() > 64) {
        std::cout << "... (" << csr_der.size() - 64 << " more bytes)" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "=== Done ===" << std::endl;

    return 0;
}

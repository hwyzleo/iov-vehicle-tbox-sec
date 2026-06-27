#include <gtest/gtest.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "csr_builder.h"
#include "key_engine.h"
#include "hsm_interface.h"
#include "constants.h"

using namespace tbox::sec;

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0 && i % 16 == 0) ss << "\n";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i < data.size() - 1) ss << " ";
    }
    return ss.str();
}

std::string get_subject_from_csr(const std::vector<uint8_t>& csr_der) {
    // 简单解析 CSR DER 格式获取 Subject
    // 这里只是演示，实际应该使用 OpenSSL API
    return "CN=TBOX-ECU-001, OU=TBOX-TSP, O=OpenIOV, C=CN";
}

TEST(ShowCsr, GenerateAndDisplay) {
    // 创建 HSM
    auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, "/tmp/test_keys");
    ASSERT_NE(hsm, nullptr);
    
    // 创建密钥引擎
    KeyEngine key_engine(std::move(hsm));
    ASSERT_EQ(key_engine.initialize(), ErrorCode::SUCCESS);
    
    // 生成密钥对
    std::string vin = "TESTVIN1234567890";
    std::string device_sn = "TBOX-ECU-001";
    KeyPair key_pair;
    ASSERT_EQ(key_engine.generate_device_key(vin, device_sn, key_pair), ErrorCode::SUCCESS);
    
    std::cout << "\n=== 生成的密钥信息 ===" << std::endl;
    std::cout << "Key ID: " << key_pair.key_id << std::endl;
    std::cout << "Algorithm: " << key_pair.algorithm << std::endl;
    std::cout << "Public Key Size: " << key_pair.public_key.size() << " bytes" << std::endl;
    
    // 创建 CSR 构建器
    CsrBuilder csr_builder(&key_engine);
    
    // 配置 CSR
    CsrConfig config;
    config.device_sn = device_sn;
    config.key_id = device_sn;
    config.algorithm = "ecdsa-p256";
    
    // 构建 CSR
    std::vector<uint8_t> csr_der;
    ASSERT_EQ(csr_builder.build_csr(vin, config, csr_der), ErrorCode::SUCCESS);
    
    std::cout << "\n=== 生成的 CSR 信息 ===" << std::endl;
    std::cout << "CSR Size: " << csr_der.size() << " bytes" << std::endl;
    std::cout << "\nCSR DER (Hex):" << std::endl;
    std::cout << bytes_to_hex(csr_der) << std::endl;
    
    // 显示 Subject DN 格式
    std::cout << "\n=== Subject DN 格式 ===" << std::endl;
    std::cout << "CN = " << device_sn << " (ECU UID)" << std::endl;
    std::cout << "OU = " << CSR_SUBJECT_OU << std::endl;
    std::cout << "O = " << CSR_SUBJECT_O << std::endl;
    std::cout << "C = " << CSR_SUBJECT_C << std::endl;
    
    // 显示 SAN 扩展
    std::cout << "\n=== SAN 扩展 ===" << std::endl;
    std::cout << "URI: urn:ecu-uid:" << device_sn << std::endl;
    std::cout << "(注意: 不包含 VIN)" << std::endl;
    
    // 显示幂等键格式
    std::cout << "\n=== 幂等键格式 ===" << std::endl;
    std::cout << "Key ID: " << key_pair.key_id << std::endl;
    std::cout << "格式: {device_sn}+{key_id}" << std::endl;
}
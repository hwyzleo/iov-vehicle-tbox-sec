#include <gtest/gtest.h>
#include "csr_builder.h"
#include "key_engine.h"
#include "hsm_interface.h"

using namespace tbox::sec;

class CsrBuilderTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, "/tmp/test_csr");
        auto key_engine = std::make_shared<KeyEngine>(std::move(hsm));
        key_engine->initialize();
        
        // Generate test key
        KeyPair key_pair;
        key_engine->generate_device_key("TESTVIN1234567890", "TBOX-ECU-001", key_pair);
        
        builder = std::make_unique<CsrBuilder>(key_engine);
    }
    
    std::unique_ptr<CsrBuilder> builder;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "TBOX-ECU-001";
};

TEST_F(CsrBuilderTest, BuildCsr) {
    CsrConfig config;
    config.common_name = "ECU:TBOX-ECU-001";
    config.vin = test_vin;
    config.ecu_uid = test_ecu_uid;
    config.key_usage = "digitalSignature";
    config.extended_key_usage = "clientAuth";
    
    std::vector<uint8_t> csr_der;
    EXPECT_EQ(builder->build_csr(config, csr_der), ErrorCode::SUCCESS);
    EXPECT_FALSE(csr_der.empty());
}

TEST_F(CsrBuilderTest, BuildCsrWithKey) {
    CsrConfig config;
    config.common_name = "ECU:TBOX-ECU-001";
    config.vin = test_vin;
    config.ecu_uid = test_ecu_uid;
    
    KeyPair key_pair;
    key_pair.key_id = test_vin + ":" + test_ecu_uid;
    key_pair.algorithm = "ecdsa-p256";
    key_pair.public_key = {0x04, 0x01, 0x02, 0x03};
    key_pair.private_key_exists = true;
    
    std::vector<uint8_t> csr_der;
    EXPECT_EQ(builder->build_csr_with_key(config, key_pair, csr_der), ErrorCode::SUCCESS);
    EXPECT_FALSE(csr_der.empty());
}

TEST_F(CsrBuilderTest, BuildCsrWithNullEngine) {
    auto null_builder = std::make_unique<CsrBuilder>(nullptr);
    
    CsrConfig config;
    config.common_name = "ECU:TBOX-ECU-001";
    config.vin = test_vin;
    config.ecu_uid = test_ecu_uid;
    
    std::vector<uint8_t> csr_der;
    EXPECT_EQ(null_builder->build_csr(config, csr_der), ErrorCode::INVALID_PARAMETER);
}

TEST_F(CsrBuilderTest, BuildCsrWithMissingKey) {
    CsrConfig config;
    config.common_name = "ECU:TBOX-ECU-001";
    config.vin = "NONEXISTENTVIN";
    config.ecu_uid = "NONEXISTENTECU";
    
    std::vector<uint8_t> csr_der;
    EXPECT_EQ(builder->build_csr(config, csr_der), ErrorCode::KEY_NOT_FOUND);
}
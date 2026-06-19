#include <gtest/gtest.h>
#include "key_engine.h"
#include "hsm_interface.h"

using namespace tbox::sec;

class KeyEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, "/tmp/test_keys");
        engine = std::make_unique<KeyEngine>(std::move(hsm));
        engine->initialize();
    }
    
    std::unique_ptr<KeyEngine> engine;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "TBOX-ECU-001";
};

TEST_F(KeyEngineTest, GenerateDeviceKey) {
    KeyPair key_pair;
    EXPECT_EQ(engine->generate_device_key(test_vin, test_ecu_uid, key_pair), ErrorCode::SUCCESS);
    EXPECT_FALSE(key_pair.public_key.empty());
    EXPECT_TRUE(key_pair.private_key_exists);
}

TEST_F(KeyEngineTest, GenerateDuplicateKey) {
    KeyPair key_pair;
    EXPECT_EQ(engine->generate_device_key(test_vin, test_ecu_uid, key_pair), ErrorCode::SUCCESS);
    
    // Try to generate again - should fail
    EXPECT_EQ(engine->generate_device_key(test_vin, test_ecu_uid, key_pair), ErrorCode::KEY_ALREADY_EXISTS);
}

TEST_F(KeyEngineTest, GetDeviceKey) {
    KeyPair key_pair;
    engine->generate_device_key(test_vin, test_ecu_uid, key_pair);
    
    KeyPair retrieved_key;
    EXPECT_EQ(engine->get_device_key(test_vin, test_ecu_uid, retrieved_key), ErrorCode::SUCCESS);
    EXPECT_EQ(retrieved_key.key_id, key_pair.key_id);
}

TEST_F(KeyEngineTest, SignData) {
    KeyPair key_pair;
    engine->generate_device_key(test_vin, test_ecu_uid, key_pair);
    
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> signature;
    
    EXPECT_EQ(engine->sign(test_vin, test_ecu_uid, data, signature), ErrorCode::SUCCESS);
    EXPECT_FALSE(signature.empty());
}

TEST_F(KeyEngineTest, KeyExists) {
    EXPECT_FALSE(engine->device_key_exists(test_vin, test_ecu_uid));
    
    KeyPair key_pair;
    engine->generate_device_key(test_vin, test_ecu_uid, key_pair);
    
    EXPECT_TRUE(engine->device_key_exists(test_vin, test_ecu_uid));
}

TEST_F(KeyEngineTest, DeleteDeviceKey) {
    KeyPair key_pair;
    engine->generate_device_key(test_vin, test_ecu_uid, key_pair);
    EXPECT_TRUE(engine->device_key_exists(test_vin, test_ecu_uid));
    
    EXPECT_EQ(engine->delete_device_key(test_vin, test_ecu_uid), ErrorCode::SUCCESS);
    EXPECT_FALSE(engine->device_key_exists(test_vin, test_ecu_uid));
}

TEST_F(KeyEngineTest, GetNonExistentKey) {
    KeyPair key_pair;
    EXPECT_EQ(engine->get_device_key(test_vin, test_ecu_uid, key_pair), ErrorCode::KEY_NOT_FOUND);
}

TEST_F(KeyEngineTest, SignWithoutKey) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> signature;
    
    EXPECT_EQ(engine->sign(test_vin, test_ecu_uid, data, signature), ErrorCode::KEY_NOT_FOUND);
}

TEST_F(KeyEngineTest, DifferentVinEcuPairs) {
    KeyPair key_pair1;
    KeyPair key_pair2;
    
    EXPECT_EQ(engine->generate_device_key("VIN001", "ECU001", key_pair1), ErrorCode::SUCCESS);
    EXPECT_EQ(engine->generate_device_key("VIN001", "ECU002", key_pair2), ErrorCode::SUCCESS);
    
    EXPECT_TRUE(engine->device_key_exists("VIN001", "ECU001"));
    EXPECT_TRUE(engine->device_key_exists("VIN001", "ECU002"));
    EXPECT_FALSE(engine->device_key_exists("VIN002", "ECU001"));
}

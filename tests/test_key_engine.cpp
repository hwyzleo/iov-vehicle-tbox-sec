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
    std::string test_device_sn = "TBOX-DEVICE-001";
    std::string test_key_id = "key-001";
};

TEST_F(KeyEngineTest, GenerateDeviceKey) {
    KeyPair key_pair;
    EXPECT_EQ(engine->generate_device_key(test_device_sn, test_key_id, key_pair), ErrorCode::SUCCESS);
    EXPECT_FALSE(key_pair.public_key.empty());
    EXPECT_TRUE(key_pair.private_key_exists);
    EXPECT_EQ(key_pair.key_id, test_device_sn + "+" + test_key_id);
}

TEST_F(KeyEngineTest, GenerateDuplicateKey) {
    KeyPair key_pair;
    EXPECT_EQ(engine->generate_device_key(test_device_sn, test_key_id, key_pair), ErrorCode::SUCCESS);
    
    KeyPair key_pair2;
    EXPECT_EQ(engine->generate_device_key(test_device_sn, test_key_id, key_pair2), ErrorCode::SUCCESS);
    EXPECT_EQ(key_pair2.key_id, key_pair.key_id);
    EXPECT_EQ(key_pair2.public_key, key_pair.public_key);
}

TEST_F(KeyEngineTest, GetDeviceKey) {
    KeyPair key_pair;
    engine->generate_device_key(test_device_sn, test_key_id, key_pair);
    
    KeyPair retrieved_key;
    EXPECT_EQ(engine->get_device_key(test_device_sn, test_key_id, retrieved_key), ErrorCode::SUCCESS);
    EXPECT_EQ(retrieved_key.key_id, key_pair.key_id);
}

TEST_F(KeyEngineTest, SignData) {
    KeyPair key_pair;
    engine->generate_device_key(test_device_sn, test_key_id, key_pair);
    
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> signature;
    
    EXPECT_EQ(engine->sign(test_device_sn, test_key_id, data, signature), ErrorCode::SUCCESS);
    EXPECT_FALSE(signature.empty());
}

TEST_F(KeyEngineTest, KeyExists) {
    EXPECT_FALSE(engine->device_key_exists(test_device_sn, test_key_id));
    
    KeyPair key_pair;
    engine->generate_device_key(test_device_sn, test_key_id, key_pair);
    
    EXPECT_TRUE(engine->device_key_exists(test_device_sn, test_key_id));
}

TEST_F(KeyEngineTest, DeleteDeviceKey) {
    KeyPair key_pair;
    engine->generate_device_key(test_device_sn, test_key_id, key_pair);
    EXPECT_TRUE(engine->device_key_exists(test_device_sn, test_key_id));
    
    EXPECT_EQ(engine->delete_device_key(test_device_sn, test_key_id), ErrorCode::SUCCESS);
    EXPECT_FALSE(engine->device_key_exists(test_device_sn, test_key_id));
}

TEST_F(KeyEngineTest, GetNonExistentKey) {
    KeyPair key_pair;
    EXPECT_EQ(engine->get_device_key(test_device_sn, test_key_id, key_pair), ErrorCode::KEY_NOT_FOUND);
}

TEST_F(KeyEngineTest, SignWithoutKey) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> signature;
    
    EXPECT_EQ(engine->sign(test_device_sn, test_key_id, data, signature), ErrorCode::KEY_NOT_FOUND);
}

TEST_F(KeyEngineTest, DifferentDeviceKeyPairs) {
    KeyPair key_pair1;
    KeyPair key_pair2;
    
    EXPECT_EQ(engine->generate_device_key("DEVICE-001", "key-a", key_pair1), ErrorCode::SUCCESS);
    EXPECT_EQ(engine->generate_device_key("DEVICE-001", "key-b", key_pair2), ErrorCode::SUCCESS);
    
    EXPECT_TRUE(engine->device_key_exists("DEVICE-001", "key-a"));
    EXPECT_TRUE(engine->device_key_exists("DEVICE-001", "key-b"));
    EXPECT_FALSE(engine->device_key_exists("DEVICE-002", "key-a"));
}

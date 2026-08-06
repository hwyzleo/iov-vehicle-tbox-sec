#include <gtest/gtest.h>
#include "hsm_interface.h"
#include <filesystem>

using namespace tbox::sec;

class HsmInterfaceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 每个测试前清理持久化目录，保证测试隔离（SoftFileHsm 落盘持久化）
        std::filesystem::remove_all("/tmp/test_hsm");
        hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, "/tmp/test_hsm");
        // SoftFileHsm 需先初始化以加载/生成主加密密钥(KEK)，否则密钥落盘加密失败
        ASSERT_EQ(hsm->initialize(), ErrorCode::SUCCESS);
    }

    void TearDown() override {
        hsm.reset();
        std::filesystem::remove_all("/tmp/test_hsm");
    }

    std::unique_ptr<HsmInterface> hsm;
};

TEST_F(HsmInterfaceTest, Initialize) {
    EXPECT_EQ(hsm->initialize(), ErrorCode::SUCCESS);
}

TEST_F(HsmInterfaceTest, GenerateKeyPair) {
    KeyPair key_pair;
    EXPECT_EQ(hsm->generate_key_pair("test-key", "ecdsa-p256", key_pair), ErrorCode::SUCCESS);
    EXPECT_EQ(key_pair.key_id, "test-key");
    EXPECT_EQ(key_pair.algorithm, "ecdsa-p256");
    EXPECT_TRUE(key_pair.private_key_exists);
}

TEST_F(HsmInterfaceTest, SignAndVerify) {
    KeyPair key_pair;
    ASSERT_EQ(hsm->generate_key_pair("test-key", "ecdsa-p256", key_pair), ErrorCode::SUCCESS);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> signature;

    EXPECT_EQ(hsm->sign("test-key", data, signature), ErrorCode::SUCCESS);
    EXPECT_FALSE(signature.empty());

    bool valid = false;
    EXPECT_EQ(hsm->verify("test-key", data, signature, valid), ErrorCode::SUCCESS);
    EXPECT_TRUE(valid);
}

TEST_F(HsmInterfaceTest, ExportPublicKey) {
    KeyPair key_pair;
    ASSERT_EQ(hsm->generate_key_pair("test-key", "ecdsa-p256", key_pair), ErrorCode::SUCCESS);

    std::vector<uint8_t> public_key;
    EXPECT_EQ(hsm->export_public_key("test-key", public_key), ErrorCode::SUCCESS);
    EXPECT_FALSE(public_key.empty());
}

TEST_F(HsmInterfaceTest, KeyExistsBeforeGeneration) {
    EXPECT_FALSE(hsm->key_exists("non-existent-key"));
}

TEST_F(HsmInterfaceTest, KeyExistsAfterGeneration) {
    KeyPair key_pair;
    hsm->generate_key_pair("test-key", "ecdsa-p256", key_pair);
    EXPECT_TRUE(hsm->key_exists("test-key"));
}

TEST_F(HsmInterfaceTest, KeyDeleted) {
    KeyPair key_pair;
    hsm->generate_key_pair("test-key", "ecdsa-p256", key_pair);
    EXPECT_EQ(hsm->delete_key("test-key"), ErrorCode::SUCCESS);
    EXPECT_FALSE(hsm->key_exists("test-key"));
}

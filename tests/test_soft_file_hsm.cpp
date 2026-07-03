#include <gtest/gtest.h>
#include "soft_file_hsm.h"
#include "store.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

class SoftFileHsmTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/tbox_sec_test_" + std::to_string(
            std::chrono::system_clock::now().time_since_epoch().count());
        fs::create_directories(test_dir_);
        auto store = hwyz::store::Store::open("sec_test", test_dir_);
        hsm_ = std::make_unique<tbox::sec::SoftFileHsm>(
            std::move(store), "aes-256-gcm", test_dir_ + "/.encryption_key");
        hsm_->initialize();
    }
    
    void TearDown() override {
        hsm_.reset();
        fs::remove_all(test_dir_);
    }
    
    std::string test_dir_;
    std::unique_ptr<tbox::sec::SoftFileHsm> hsm_;
};

TEST_F(SoftFileHsmTest, InitializeSuccess) {
    EXPECT_TRUE(fs::exists(test_dir_));
    EXPECT_FALSE(fs::exists(test_dir_ + "/.encryption_key"));
}

TEST_F(SoftFileHsmTest, GenerateKeyPairSuccess) {
    tbox::sec::KeyPair key_pair;
    auto err = hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    EXPECT_EQ(err, tbox::sec::ErrorCode::SUCCESS);
    EXPECT_FALSE(key_pair.public_key.empty());
    EXPECT_TRUE(key_pair.private_key_exists);
    EXPECT_EQ(key_pair.storage_mode, tbox::sec::KeyStorageMode::SOFT_FILE);
    EXPECT_TRUE(key_pair.exportable);
}

TEST_F(SoftFileHsmTest, KeyExistsAfterGenerate) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    EXPECT_TRUE(hsm_->key_exists("test:vin:ecu"));
}

TEST_F(SoftFileHsmTest, SignAndVerify) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::vector<uint8_t> signature;
    
    auto sign_err = hsm_->sign("test:vin:ecu", data, signature);
    EXPECT_EQ(sign_err, tbox::sec::ErrorCode::SUCCESS);
    EXPECT_FALSE(signature.empty());
    
    bool valid = false;
    auto verify_err = hsm_->verify("test:vin:ecu", data, signature, valid);
    EXPECT_EQ(verify_err, tbox::sec::ErrorCode::SUCCESS);
    EXPECT_TRUE(valid);
}

TEST_F(SoftFileHsmTest, VerifyWithWrongDataFails) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::vector<uint8_t> signature;
    hsm_->sign("test:vin:ecu", data, signature);
    
    std::vector<uint8_t> wrong_data = {6, 7, 8, 9, 10};
    bool valid = true;
    auto err = hsm_->verify("test:vin:ecu", wrong_data, signature, valid);
    EXPECT_EQ(err, tbox::sec::ErrorCode::SUCCESS);
    EXPECT_FALSE(valid);
}

TEST_F(SoftFileHsmTest, ExportPublicKey) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    std::vector<uint8_t> exported_key;
    auto err = hsm_->export_public_key("test:vin:ecu", exported_key);
    EXPECT_EQ(err, tbox::sec::ErrorCode::SUCCESS);
    EXPECT_EQ(exported_key, key_pair.public_key);
}

TEST_F(SoftFileHsmTest, ExportPrivateKey) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    std::vector<uint8_t> private_key;
    auto err = hsm_->export_private_key("test:vin:ecu", private_key);
    EXPECT_EQ(err, tbox::sec::ErrorCode::SUCCESS);
    EXPECT_FALSE(private_key.empty());
}

TEST_F(SoftFileHsmTest, DeleteKey) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    EXPECT_TRUE(hsm_->key_exists("test:vin:ecu"));
    
    auto err = hsm_->delete_key("test:vin:ecu");
    EXPECT_EQ(err, tbox::sec::ErrorCode::SUCCESS);
    
    EXPECT_FALSE(hsm_->key_exists("test:vin:ecu"));
}

TEST_F(SoftFileHsmTest, KeyPersistedToStore) {
    tbox::sec::KeyPair key_pair;
    hsm_->generate_key_pair("test:vin:ecu", "ecdsa-p256", key_pair);
    
    // 重新初始化 HSM，应该能加载已有密钥
    auto store = hwyz::store::Store::open("sec_test", test_dir_);
    auto hsm2 = std::make_unique<tbox::sec::SoftFileHsm>(
        std::move(store), "aes-256-gcm", test_dir_ + "/.encryption_key");
    hsm2->initialize();
    
    EXPECT_TRUE(hsm2->key_exists("test:vin:ecu"));
    
    // 验证签名仍然有效
    std::vector<uint8_t> data = {1, 2, 3};
    std::vector<uint8_t> signature;
    hsm2->sign("test:vin:ecu", data, signature);
    
    bool valid = false;
    hsm2->verify("test:vin:ecu", data, signature, valid);
    EXPECT_TRUE(valid);
}

TEST_F(SoftFileHsmTest, SignNonExistentKeyFails) {
    std::vector<uint8_t> data = {1, 2, 3};
    std::vector<uint8_t> signature;
    
    auto err = hsm_->sign("nonexistent:key", data, signature);
    EXPECT_EQ(err, tbox::sec::ErrorCode::KEY_NOT_FOUND);
}

TEST_F(SoftFileHsmTest, MultipleKeysIsolation) {
    tbox::sec::KeyPair key_pair1, key_pair2;
    hsm_->generate_key_pair("vin1:ecu1", "ecdsa-p256", key_pair1);
    hsm_->generate_key_pair("vin2:ecu2", "ecdsa-p256", key_pair2);
    
    // 签名应该使用正确的密钥
    std::vector<uint8_t> data = {1, 2, 3};
    std::vector<uint8_t> sig1, sig2;
    hsm_->sign("vin1:ecu1", data, sig1);
    hsm_->sign("vin2:ecu2", data, sig2);
    
    // 交叉验证应该失败
    bool valid = false;
    hsm_->verify("vin1:ecu1", data, sig2, valid);
    EXPECT_FALSE(valid);
    
    hsm_->verify("vin2:ecu2", data, sig1, valid);
    EXPECT_FALSE(valid);
}

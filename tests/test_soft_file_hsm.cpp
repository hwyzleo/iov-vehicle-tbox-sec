#include "gtest/gtest.h"
#include "soft_file_hsm.h"
#include "store.h"

#include <filesystem>
#include <fstream>
#include <optional>

using namespace tbox::sec;

class SoftFileHsmTest : public ::testing::Test {
protected:
    void SetUp() override {
        store_dir_ = "/tmp/test_soft_hsm_" + std::to_string(getpid());
        std::filesystem::create_directories(store_dir_);
        
        store_.emplace(hwyz::store::Store::open("sec", store_dir_));
        
        // Create encryption key file
        std::string enc_key_path = "/tmp/test_encryption_key";
        std::ofstream ofs(enc_key_path, std::ios::binary);
        std::vector<uint8_t> key(32, 0x42); // 32 bytes key
        ofs.write(reinterpret_cast<const char*>(key.data()), key.size());
        ofs.close();
    }

    void TearDown() override {
        store_.reset();
        std::filesystem::remove_all(store_dir_);
        std::filesystem::remove("/tmp/test_encryption_key");
    }

    std::string store_dir_;
    std::optional<hwyz::store::Store> store_;
};

TEST_F(SoftFileHsmTest, GenerateKeyPair) {
    SoftFileHsm hsm(std::move(*store_), "aes-256-gcm", "/tmp/test_encryption_key");
    
    // Initialize the HSM first
    auto init_result = hsm.initialize();
    ASSERT_EQ(init_result, ErrorCode::SUCCESS);

    KeyPair key_pair;
    auto result = hsm.generate_key_pair("test_key", "ecdsa-p256", key_pair);

    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(key_pair.key_id, "test_key");
    EXPECT_TRUE(key_pair.private_key_exists);
}

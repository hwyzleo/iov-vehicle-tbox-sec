#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include "service_dispatcher.h"
#include "sec_service.h"
#include "diag_service_interface.h"
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace tbox::diag;
using namespace tbox::sec;

class MockDiagService : public DiagServiceInterface {
public:
    ErrorCode initialize() override {
        initialized_ = true;
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode send_request(DiagRequestType request_type,
                          const std::vector<uint8_t>& request_data,
                          DiagResponseCallback callback) override {
        DiagResponse response;
        response.error_code = ErrorCode::SUCCESS;
        response.data = {0x01};
        if (callback) callback(response);
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode send_request_sync(DiagRequestType request_type,
                               const std::vector<uint8_t>& request_data,
                               DiagResponse& response) override {
        response.error_code = ErrorCode::SUCCESS;
        response.data = {0x01};
        return ErrorCode::SUCCESS;
    }
    
    bool is_connected() const override {
        return initialized_;
    }
    
    std::string get_service_status() const override {
        return "Mock DIAG Service";
    }

private:
    bool initialized_ = false;
};

class MockProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }

    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.ecu_uid = "00000000000000000000000000000001";
        return ErrorCode::SUCCESS;
    }

    bool is_connected() const override {
        return true;
    }

    std::string get_service_status() const override {
        return "Mock PROV Service";
    }
};

class ServiceDispatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 每个测试前清理持久化目录，保证测试隔离
        std::filesystem::remove_all("/tmp/test_dispatcher");
        std::filesystem::remove_all("/tmp/test_dispatcher_state.json");

        // Create empty state file so load_state() succeeds
        std::ofstream state_file("/tmp/test_dispatcher_state.json");
        state_file << "{}";
        state_file.close();

        // Create config
        SecServiceConfig config;
        config.hsm_type = "software";
        // SoftFileHsm 的存储根与 KEK 路径须显式指向可写临时目录，
        // 否则会回退到 /var/lib/tbox（无写权限导致 STORAGE_WRITE_FAILED）
        config.store_root = "/tmp/test_dispatcher";
        config.soft_key_config.key_path = "/tmp/test_dispatcher";
        config.state_file_path = "/tmp/test_dispatcher_state.json";
        // Seed-Key 共享密钥（AES-128，32 hex 字符），测试固定值
        config.seed_key_shared_secret = "0102030405060708090a0b0c0d0e0f10";

        // Create mock services
        auto mock_diag = std::make_shared<MockDiagService>();
        auto mock_prov = std::make_shared<MockProvService>();

        // Create SEC service
        sec_service_ = std::make_shared<SecService>(config, mock_diag, mock_prov);
        ASSERT_EQ(sec_service_->initialize(), ErrorCode::SUCCESS);

        // Create dispatcher
        dispatcher_ = std::make_unique<ServiceDispatcher>(sec_service_);
    }

    void TearDown() override {
        dispatcher_.reset();
        sec_service_.reset();
        std::filesystem::remove_all("/tmp/test_dispatcher");
        std::filesystem::remove_all("/tmp/test_dispatcher_state.json");
    }

    std::shared_ptr<SecService> sec_service_;
    std::unique_ptr<ServiceDispatcher> dispatcher_;
};

TEST_F(ServiceDispatcherTest, RequestSeedSuccess) {
    SecurityAccessResponse response;
    // requestSeed with level 0x27 (odd)
    ErrorCode result = dispatcher_->handle_security_access(0x27, {}, response);
    
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00); // positive response
    EXPECT_EQ(response.data.size(), 16); // 16-byte seed
}

TEST_F(ServiceDispatcherTest, SendKeySuccess) {
    // First get a seed
    SecurityAccessResponse response;
    ASSERT_EQ(dispatcher_->handle_security_access(0x27, {}, response), ErrorCode::SUCCESS);
    std::vector<uint8_t> seed = response.data;
    
    // Compute valid key using AES-128-ECB (same as SecService::compute_expected_key, DSN §5)
    const uint8_t key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                             0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    AES_KEY aes;
    AES_set_encrypt_key(key, 128, &aes);
    std::vector<uint8_t> expected_key(16);
    AES_encrypt(seed.data(), expected_key.data(), &aes);
    
    // sendKey with level 0x28 (even, = 0x27 + 1)
    ErrorCode result = dispatcher_->handle_security_access(0x28, expected_key, response);
    
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00); // positive response
}

TEST_F(ServiceDispatcherTest, SendKeyInvalidKey) {
    // First get a seed
    SecurityAccessResponse response;
    ASSERT_EQ(dispatcher_->handle_security_access(0x27, {}, response), ErrorCode::SUCCESS);
    
    // sendKey with invalid key
    std::vector<uint8_t> invalid_key(16, 0xFF);
    ErrorCode result = dispatcher_->handle_security_access(0x28, invalid_key, response);
    
    EXPECT_EQ(result, ErrorCode::KEY_VERIFICATION_FAILED);
    EXPECT_EQ(response.nrc, 0x35); // invalidKey
}

TEST_F(ServiceDispatcherTest, SendKeyLockoutAfter3Failures) {
    // Get a seed and fail 3 times
    SecurityAccessResponse response;
    for (int i = 0; i < 3; ++i) {
        ASSERT_EQ(dispatcher_->handle_security_access(0x27, {}, response), ErrorCode::SUCCESS);
        
        std::vector<uint8_t> invalid_key(16, 0xFF);
        dispatcher_->handle_security_access(0x28, invalid_key, response);
    }
    
    // After 3 failures, should get exceededNumberOfAttempts
    EXPECT_EQ(response.nrc, 0x36);
}

TEST_F(ServiceDispatcherTest, RequestSeedUsesRawLevel) {
    // Test with different security levels
    SecurityAccessResponse response;
    
    // Level 0x01
    EXPECT_EQ(dispatcher_->handle_security_access(0x01, {}, response), ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00);
    
    // Level 0x03
    EXPECT_EQ(dispatcher_->handle_security_access(0x03, {}, response), ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00);
    
    // Level 0x27
    EXPECT_EQ(dispatcher_->handle_security_access(0x27, {}, response), ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00);
}

TEST_F(ServiceDispatcherTest, SendKeyUsesRawLevelNotDecremented) {
    // This is the critical test: sendKey should pass raw level (0x28) to SEC,
    // NOT (0x28 - 1) = 0x27
    
    // First get a seed with level 0x27
    SecurityAccessResponse response;
    ASSERT_EQ(dispatcher_->handle_security_access(0x27, {}, response), ErrorCode::SUCCESS);
    std::vector<uint8_t> seed = response.data;
    
    // Compute valid key using AES-128-ECB (same as SecService::compute_expected_key, DSN §5)
    const uint8_t key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                             0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    AES_KEY aes;
    AES_set_encrypt_key(key, 128, &aes);
    std::vector<uint8_t> expected_key(16);
    AES_encrypt(seed.data(), expected_key.data(), &aes);
    
    // sendKey with level 0x28 - should work because SEC expects 0x28
    ErrorCode result = dispatcher_->handle_security_access(0x28, expected_key, response);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00);
}

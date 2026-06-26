#include <gtest/gtest.h>
#include <fstream>
#include "sec_service.h"
#include "diag_service_interface.h"
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace tbox::sec;

class MockProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }

    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.ecu_uid = "TBOX-ECU-001";
        return ErrorCode::SUCCESS;
    }

    bool is_connected() const override {
        return true;
    }

    std::string get_service_status() const override {
        return "Mock PROV Service";
    }
};

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

class SeedKeyTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create empty state file so load_state() succeeds
        std::ofstream state_file("/tmp/test_seed_key_state.json");
        state_file << "{}";
        state_file.close();

        // Create config
        SecServiceConfig config;
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_seed_key";
        config.state_file_path = "/tmp/test_seed_key_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        // Create mock services
        mock_diag_ = std::make_shared<MockDiagService>();
        mock_prov_ = std::make_shared<MockProvService>();

        // Create SEC service
        service_ = std::make_unique<SecService>(config, mock_diag_, mock_prov_);
        
        // Initialize service
        ASSERT_EQ(service_->initialize(), ErrorCode::SUCCESS);
    }

    void TearDown() override {
        service_.reset();
        mock_diag_.reset();
        mock_prov_.reset();
    }

    std::shared_ptr<MockDiagService> mock_diag_;
    std::shared_ptr<MockProvService> mock_prov_;
    std::unique_ptr<SecService> service_;
};

TEST_F(SeedKeyTest, GetSeedSuccess) {
    std::vector<uint8_t> seed;
    // Use UDS security level 0x27 (requestSeed)
    ErrorCode result = service_->get_seed(0x27, seed);
    
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(seed.size(), 16); // 128-bit seed
    
    // Verify seed is not all zeros
    bool all_zeros = true;
    for (auto byte : seed) {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros);
}

TEST_F(SeedKeyTest, GetSeedInvalidLevel) {
    std::vector<uint8_t> seed;
    // Even level is invalid for requestSeed (should be odd)
    ErrorCode result = service_->get_seed(0x28, seed);
    
    EXPECT_EQ(result, ErrorCode::INVALID_PARAMETER);
}

TEST_F(SeedKeyTest, GetSeedZeroLevel) {
    std::vector<uint8_t> seed;
    ErrorCode result = service_->get_seed(0x00, seed);
    
    EXPECT_EQ(result, ErrorCode::INVALID_PARAMETER);
}

TEST_F(SeedKeyTest, VerifyKeySuccess) {
    // First get a seed with UDS security level 0x27
    std::vector<uint8_t> seed;
    ASSERT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
    
    // Compute expected key using XOR algorithm (same as in SecService)
    std::vector<uint8_t> shared_secret(16, 0x01); // Same as in SecService
    std::vector<uint8_t> expected_key(16);
    
    // XOR-based computation: key = seed XOR shared_secret
    for (size_t i = 0; i < 16; i++) {
        expected_key[i] = seed[i] ^ shared_secret[i];
    }
    
    // Verify key with UDS security level 0x28 (sendKey = requestSeed + 1)
    ErrorCode result = service_->verify_key(0x28, expected_key);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SeedKeyTest, VerifyKeyInvalidLevelOdd) {
    std::vector<uint8_t> key(16, 0x01);
    // Odd level is invalid for sendKey (should be even)
    ErrorCode result = service_->verify_key(0x27, key);
    
    EXPECT_EQ(result, ErrorCode::INVALID_PARAMETER);
}

TEST_F(SeedKeyTest, VerifyKeyLevelMismatch) {
    // Get seed with level 0x27
    std::vector<uint8_t> seed;
    ASSERT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
    
    // Try to verify with wrong level (0x04 instead of 0x28)
    std::vector<uint8_t> key(16, 0x01);
    ErrorCode result = service_->verify_key(0x04, key);
    
    EXPECT_EQ(result, ErrorCode::INVALID_PARAMETER);
}

TEST_F(SeedKeyTest, VerifyKeyInvalidKey) {
    // First get a seed
    std::vector<uint8_t> seed;
    ASSERT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
    
    // Use invalid key
    std::vector<uint8_t> invalid_key(16, 0xFF);
    ErrorCode result = service_->verify_key(0x28, invalid_key);
    
    EXPECT_EQ(result, ErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyTest, VerifyKeyWithoutGetSeed) {
    // Try to verify key without getting seed first
    std::vector<uint8_t> key(16, 0x01);
    ErrorCode result = service_->verify_key(0x28, key);
    
    EXPECT_EQ(result, ErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyTest, VerifyKeyLockout) {
    // Get a seed
    std::vector<uint8_t> seed;
    ASSERT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
    
    // Fail verification 3 times
    std::vector<uint8_t> invalid_key(16, 0xFF);
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(service_->verify_key(0x28, invalid_key), 
                  ErrorCode::KEY_VERIFICATION_FAILED);
        
        // Get new seed for next attempt
        if (i < 2) {
            EXPECT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
        }
    }
    
    // Should be in lockout now
    EXPECT_EQ(service_->get_seed(0x27, seed), ErrorCode::UDS_SECURITY_DENIED);
}

TEST_F(SeedKeyTest, SeedInvalidatedAfterUse) {
    // Get a seed
    std::vector<uint8_t> seed;
    ASSERT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
    
    // Compute valid key using XOR algorithm
    std::vector<uint8_t> shared_secret(16, 0x01);
    std::vector<uint8_t> expected_key(16);
    
    // XOR-based computation: key = seed XOR shared_secret
    for (size_t i = 0; i < 16; i++) {
        expected_key[i] = seed[i] ^ shared_secret[i];
    }
    
    // Verify key (should succeed and invalidate seed)
    EXPECT_EQ(service_->verify_key(0x28, expected_key), ErrorCode::SUCCESS);
    
    // Try to verify again with same key (should fail - seed invalidated)
    EXPECT_EQ(service_->verify_key(0x28, expected_key), 
              ErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyTest, SeedExpired) {
    // Get a seed
    std::vector<uint8_t> seed;
    ASSERT_EQ(service_->get_seed(0x27, seed), ErrorCode::SUCCESS);
    
    // Wait for seed to expire (30 seconds + buffer)
    std::this_thread::sleep_for(std::chrono::seconds(31));
    
    // Try to verify key (should fail - seed expired)
    std::vector<uint8_t> key(16, 0x01);
    EXPECT_EQ(service_->verify_key(0x28, key), ErrorCode::KEY_VERIFICATION_FAILED);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

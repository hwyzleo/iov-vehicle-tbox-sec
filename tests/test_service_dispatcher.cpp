#include <gtest/gtest.h>
#include <fstream>
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
        // Create empty state file so load_state() succeeds
        std::ofstream state_file("/tmp/test_dispatcher_state.json");
        state_file << "{}";
        state_file.close();

        // Create config
        SecServiceConfig config;
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_dispatcher";
        config.state_file_path = "/tmp/test_dispatcher_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

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
    
    // Compute valid key using XOR algorithm
    std::vector<uint8_t> shared_secret(16, 0x01);
    std::vector<uint8_t> expected_key(16);
    
    // XOR-based computation: key = seed XOR shared_secret
    for (size_t i = 0; i < 16; i++) {
        expected_key[i] = seed[i] ^ shared_secret[i];
    }
    
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
    
    // Compute valid key using XOR algorithm
    std::vector<uint8_t> shared_secret(16, 0x01);
    std::vector<uint8_t> expected_key(16);
    
    // XOR-based computation: key = seed XOR shared_secret
    for (size_t i = 0; i < 16; i++) {
        expected_key[i] = seed[i] ^ shared_secret[i];
    }
    
    // sendKey with level 0x28 - should work because SEC expects 0x28
    ErrorCode result = dispatcher_->handle_security_access(0x28, expected_key, response);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(response.nrc, 0x00);
}

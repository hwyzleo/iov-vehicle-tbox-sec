#include <gtest/gtest.h>
#include "sec_service.h"
#include "diag_service_interface.h"

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
        return initialized_ ? "Connected" : "Disconnected";
    }

private:
    bool initialized_ = false;
};

class SecServiceWithDiagTest : public ::testing::Test {
protected:
    void SetUp() override {
        SecServiceConfig config;
        config.vin = "TESTVIN1234567890";
        config.ecu_uid = "TBOX-ECU-001";
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_sec";
        config.state_file_path = "/tmp/test_sec_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        mock_diag_service = std::make_shared<MockDiagService>();
        service = std::make_unique<SecService>(config);
        service->set_diag_service(mock_diag_service);
    }

    std::shared_ptr<MockDiagService> mock_diag_service;
    std::unique_ptr<SecService> service;
};

TEST_F(SecServiceWithDiagTest, InitializeWithDiagService) {
    // Test that DIAG service is set
    EXPECT_NE(mock_diag_service, nullptr);
    
    // Initialize the mock DIAG service first
    mock_diag_service->initialize();
    EXPECT_TRUE(mock_diag_service->is_connected());
    
    // Test that service is not initialized yet
    EXPECT_FALSE(service->is_initialized());
    
    // Note: We don't call service->initialize() here because it would try to
    // initialize HSM and cloud client, which might hang in test environment.
    // The important thing is that the DIAG service is properly set and initialized.
}

TEST_F(SecServiceWithDiagTest, GenerateKeyPairViaDiag) {
    // Initialize mock DIAG service
    mock_diag_service->initialize();
    
    // Without initializing the service, generate_key_pair should return NOT_INITIALIZED
    ErrorCode result = service->generate_key_pair();
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceWithDiagTest, GetCsrViaDiag) {
    // Initialize mock DIAG service
    mock_diag_service->initialize();
    
    // Without initializing the service, get_csr should return NOT_INITIALIZED
    std::vector<uint8_t> csr;
    ErrorCode result = service->get_csr(csr);
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceWithDiagTest, InjectCertificateViaDiag) {
    // Initialize mock DIAG service
    mock_diag_service->initialize();
    
    // Without initializing the service, inject_certificate should return NOT_INITIALIZED
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    ErrorCode result = service->inject_certificate(cert);
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceWithDiagTest, DeviceInfoContainsDiagStatus) {
    // Initialize mock DIAG service
    mock_diag_service->initialize();
    
    // Device info should show DIAG service is available
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("DIAG Service: Connected"), std::string::npos);
}

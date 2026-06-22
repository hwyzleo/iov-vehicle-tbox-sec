#include <gtest/gtest.h>
#include <fstream>
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
        last_request_type_ = request_type;
        DiagResponse response;
        response.error_code = ErrorCode::SUCCESS;
        response.data = {0x01};
        if (callback) callback(response);
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode send_request_sync(DiagRequestType request_type,
                               const std::vector<uint8_t>& request_data,
                               DiagResponse& response) override {
        last_request_type_ = request_type;
        request_count_++;
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

    DiagRequestType get_last_request_type() const { return last_request_type_; }
    int get_request_count() const { return request_count_; }

private:
    bool initialized_ = false;
    DiagRequestType last_request_type_;
    int request_count_ = 0;
};

class SecServiceWithDiagTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create empty state file so load_state() succeeds
        std::ofstream state_file("/tmp/test_sec_diag_state.json");
        state_file << "{}";
        state_file.close();

        SecServiceConfig config;
        config.vin = "TESTVIN1234567890";
        config.ecu_uid = "TBOX-ECU-001";
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_sec_diag";
        config.state_file_path = "/tmp/test_sec_diag_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        mock_diag_service = std::make_shared<MockDiagService>();
        service = std::make_unique<SecService>(config, mock_diag_service);
    }

    void TearDown() override {
        service.reset();
        mock_diag_service.reset();
    }

    std::shared_ptr<MockDiagService> mock_diag_service;
    std::unique_ptr<SecService> service;
};

TEST_F(SecServiceWithDiagTest, InitializeWithDiagService) {
    EXPECT_FALSE(service->is_initialized());
    EXPECT_NE(mock_diag_service, nullptr);
    
    ErrorCode result = service->initialize();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_TRUE(service->is_initialized());
    EXPECT_TRUE(mock_diag_service->is_connected());
}

TEST_F(SecServiceWithDiagTest, GenerateKeyPairViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(mock_diag_service->get_last_request_type(), DiagRequestType::GENERATE_KEY_PAIR);
    EXPECT_GT(mock_diag_service->get_request_count(), 0);
}

TEST_F(SecServiceWithDiagTest, GetCsrViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(mock_diag_service->get_last_request_type(), DiagRequestType::READ_CSR);
}

TEST_F(SecServiceWithDiagTest, SubmitCsrViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->submit_csr();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(mock_diag_service->get_last_request_type(), DiagRequestType::SUBMIT_CSR);
}

TEST_F(SecServiceWithDiagTest, InjectCertificateViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->submit_csr();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    result = service->inject_certificate(cert);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(mock_diag_service->get_last_request_type(), DiagRequestType::INJECT_CERTIFICATE);
}

TEST_F(SecServiceWithDiagTest, DeviceInfoContainsDiagStatus) {
    mock_diag_service->initialize();
    
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("DIAG Service: Connected"), std::string::npos);
}

TEST_F(SecServiceWithDiagTest, FullProvisioningFlowViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->submit_csr();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    result = service->inject_certificate(cert);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    EXPECT_GE(mock_diag_service->get_request_count(), 4);
}

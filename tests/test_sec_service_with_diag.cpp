#include <gtest/gtest.h>
#include <fstream>
#include <optional>
#include "sec_service.h"
#include "diag_service_interface.h"

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
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_sec_diag";
        config.state_file_path = "/tmp/test_sec_diag_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        mock_diag_service = std::make_shared<MockDiagService>();
        auto prov_service = std::make_shared<MockProvService>();
        service = std::make_unique<SecService>(config, mock_diag_service, prov_service);
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
    
    // Generate key pair via diag service
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Actually generate the key in HSM (diag service only updates state)
    result = service->generate_and_store_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceWithDiagTest, SubmitCsrViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Generate key pair via diag service
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Actually generate the key in HSM
    result = service->generate_and_store_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->submit_csr();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceWithDiagTest, InjectCertificateViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Generate key pair via diag service
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Actually generate the key in HSM
    result = service->generate_and_store_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->submit_csr();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    result = service->inject_certificate(cert);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceWithDiagTest, DeviceInfoShowsConnectedWhenInitialized) {
    mock_diag_service->initialize();
    
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("DIAG Service: Connected"), std::string::npos);
}

TEST_F(SecServiceWithDiagTest, DeviceInfoShowsDisconnectedWhenNotInitialized) {
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("DIAG Service: Disconnected"), std::string::npos);
}

TEST_F(SecServiceWithDiagTest, FullProvisioningFlowViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Generate key pair via diag service
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Actually generate the key in HSM
    result = service->generate_and_store_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->submit_csr();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    result = service->inject_certificate(cert);
    ASSERT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceWithDiagTest, ApplyCertificateViaDiag) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->apply_certificate();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(mock_diag_service->get_last_request_type(), DiagRequestType::APPLY_CERTIFICATE);
}

class FailingDiagService : public DiagServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode send_request(DiagRequestType request_type,
                          const std::vector<uint8_t>& request_data,
                          DiagResponseCallback callback) override {
        DiagResponse response;
        response.error_code = ErrorCode::CONNECTION_FAILED;
        if (callback) callback(response);
        return ErrorCode::CONNECTION_FAILED;
    }
    
    ErrorCode send_request_sync(DiagRequestType request_type,
                               const std::vector<uint8_t>& request_data,
                               DiagResponse& response) override {
        response.error_code = ErrorCode::CONNECTION_FAILED;
        return ErrorCode::CONNECTION_FAILED;
    }
    
    bool is_connected() const override {
        return false;
    }
    
    std::string get_service_status() const override {
        return "Disconnected";
    }
};

class SelectiveFailureDiagService : public DiagServiceInterface {
public:
    ErrorCode initialize() override {
        initialized_ = true;
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode send_request(DiagRequestType request_type,
                          const std::vector<uint8_t>& request_data,
                          DiagResponseCallback callback) override {
        DiagResponse response;
        response.error_code = should_fail(request_type) ? ErrorCode::CONNECTION_FAILED : ErrorCode::SUCCESS;
        if (callback) callback(response);
        return response.error_code;
    }
    
    ErrorCode send_request_sync(DiagRequestType request_type,
                               const std::vector<uint8_t>& request_data,
                               DiagResponse& response) override {
        if (should_fail(request_type)) {
            response.error_code = ErrorCode::CONNECTION_FAILED;
            return ErrorCode::CONNECTION_FAILED;
        }
        response.error_code = ErrorCode::SUCCESS;
        response.data = {0x01};
        return ErrorCode::SUCCESS;
    }
    
    bool is_connected() const override {
        return connected_;
    }
    
    std::string get_service_status() const override {
        return connected_ ? "Connected" : "Disconnected";
    }

    void set_fail_on(DiagRequestType type) { fail_on_type_ = type; }
    void set_connected(bool connected) { connected_ = connected; }

private:
    bool should_fail(DiagRequestType type) const {
        return !connected_ || (fail_on_type_ && *fail_on_type_ == type);
    }

    bool initialized_ = false;
    bool connected_ = true;
    std::optional<DiagRequestType> fail_on_type_;
};

class SecServiceDiagFailureTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::ofstream state_file("/tmp/test_sec_diag_fail_state.json");
        state_file << "{}";
        state_file.close();

        SecServiceConfig config;
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_sec_diag_fail";
        config.state_file_path = "/tmp/test_sec_diag_fail_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        selective_diag_service = std::make_shared<SelectiveFailureDiagService>();
        auto prov_service = std::make_shared<MockProvService>();
        service = std::make_unique<SecService>(config, selective_diag_service, prov_service);
    }

    void TearDown() override {
        service.reset();
        selective_diag_service.reset();
    }

    std::shared_ptr<SelectiveFailureDiagService> selective_diag_service;
    std::unique_ptr<SecService> service;
};

TEST_F(SecServiceDiagFailureTest, GenerateKeyPairFailsWhenDisconnected) {
    selective_diag_service->set_connected(false);
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    EXPECT_EQ(result, ErrorCode::CONNECTION_FAILED);
}

TEST_F(SecServiceDiagFailureTest, GenerateKeyPairFailsOnRequestError) {
    selective_diag_service->set_fail_on(DiagRequestType::GENERATE_KEY_PAIR);
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    EXPECT_EQ(result, ErrorCode::CONNECTION_FAILED);
}

TEST_F(SecServiceDiagFailureTest, GetCsrBuiltLocallyWhenDiagFails) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // First succeed at key generation to advance state
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Actually generate the key in HSM
    result = service->generate_and_store_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    // Now make READ_CSR fail - but get_csr builds CSR locally, not via diag
    selective_diag_service->set_fail_on(DiagRequestType::READ_CSR);
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    // get_csr builds CSR locally using CsrBuilder, not via diag service
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_FALSE(csr.empty());
}

TEST_F(SecServiceDiagFailureTest, DeviceInfoShowsDisconnected) {
    selective_diag_service->set_connected(false);
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("DIAG Service: Disconnected"), std::string::npos);
}

TEST_F(SecServiceDiagFailureTest, ApplyCertificateFailsWhenDisconnected) {
    selective_diag_service->set_connected(false);
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->apply_certificate();
    EXPECT_EQ(result, ErrorCode::CONNECTION_FAILED);
}

TEST_F(SecServiceDiagFailureTest, ApplyCertificateFailsOnRequestError) {
    selective_diag_service->set_fail_on(DiagRequestType::APPLY_CERTIFICATE);
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->apply_certificate();
    EXPECT_EQ(result, ErrorCode::CONNECTION_FAILED);
}

class SecServiceFallbackTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::ofstream state_file("/tmp/test_sec_fallback_state.json");
        state_file << "{}";
        state_file.close();

        SecServiceConfig config;
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_sec_fallback";
        config.state_file_path = "/tmp/test_sec_fallback_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        auto prov_service = std::make_shared<MockProvService>();
        service = std::make_unique<SecService>(config, nullptr, prov_service);
    }

    void TearDown() override {
        service.reset();
    }

    std::unique_ptr<SecService> service;
};

TEST_F(SecServiceFallbackTest, GenerateKeyPairWithoutDiagService) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceFallbackTest, GetCsrWithoutDiagService) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->generate_key_pair();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    std::vector<uint8_t> csr;
    result = service->get_csr(csr);
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceFallbackTest, DeviceInfoShowsNoDiagService) {
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("DIAG Service: Not available"), std::string::npos);
}

TEST_F(SecServiceFallbackTest, ApplyCertificateWithoutDiagService) {
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->apply_certificate();
    // 在没有DIAG服务的情况下，会尝试提交CSR到云端，但云端连接会失败
    EXPECT_EQ(result, ErrorCode::PKI_CONNECTION_FAILED);
}

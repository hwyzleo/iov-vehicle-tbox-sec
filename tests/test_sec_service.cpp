#include <gtest/gtest.h>
#include <fstream>
#include "sec_service.h"

using namespace tbox::sec;

class MockProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }

    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.device_sn = "TBOX-ECU-001";
        return ErrorCode::SUCCESS;
    }

    bool is_connected() const override {
        return true;
    }

    std::string get_service_status() const override {
        return "Mock PROV Service";
    }
};

class SecServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        SecServiceConfig config;
        config.hsm_type = "software";
        config.hsm_config_path = "/tmp/test_sec";
        config.state_file_path = "/tmp/test_sec_state.json";
        config.cloud_config.oapi_endpoint = "https://test.example.com:10805";
        config.cloud_config.timeout_ms = 5000;
        config.cloud_config.retry_count = 1;
        config.cloud_config.retry_delay_ms = 1000;

        auto prov_service = std::make_shared<MockProvService>();
        service = std::make_unique<SecService>(config, nullptr, prov_service);
    }

    std::unique_ptr<SecService> service;
};

TEST_F(SecServiceTest, Initialize) {
    service->initialize();
}

TEST_F(SecServiceTest, GenerateKeyPair) {
    service->initialize();

    ErrorCode result = service->generate_key_pair();
}

TEST_F(SecServiceTest, GetProvisionStatus) {
    service->initialize();
    ProvisionStatus status = service->get_provision_status();
    EXPECT_EQ(status.vin, "TESTVIN1234567890");
    EXPECT_EQ(status.ecu_uid, "TBOX-ECU-001");
}

TEST_F(SecServiceTest, GetDeviceInfo) {
    service->initialize();
    std::string info = service->get_device_info();
    EXPECT_FALSE(info.empty());
    EXPECT_NE(info.find("VIN: TESTVIN1234567890"), std::string::npos);
}

TEST_F(SecServiceTest, IsInitializedBeforeInit) {
    EXPECT_FALSE(service->is_initialized());
}

TEST_F(SecServiceTest, GenerateKeyPairNotInitialized) {
    ErrorCode result = service->generate_key_pair();
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceTest, GetCsrNotInitialized) {
    std::vector<uint8_t> csr;
    ErrorCode result = service->get_csr(csr);
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceTest, SubmitCsrNotInitialized) {
    ErrorCode result = service->submit_csr();
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceTest, InjectCertificateNotInitialized) {
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    ErrorCode result = service->inject_certificate(cert);
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceTest, ResetProvisionStatusNotInitialized) {
    ErrorCode result = service->reset_provision_status();
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceTest, DefaultConstructor) {
    SecService default_service;
    EXPECT_FALSE(default_service.is_initialized());

    ProvisionStatus status = default_service.get_provision_status();
    EXPECT_EQ(status.state, ProvisionState::NONE);
}

TEST_F(SecServiceTest, GetDeviceInfoContainsHsmType) {
    service->initialize();
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("HSM Type: software"), std::string::npos);
}

TEST_F(SecServiceTest, GetDeviceInfoContainsEcuUid) {
    service->initialize();
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("ECU UID: TBOX-ECU-001"), std::string::npos);
}

TEST_F(SecServiceTest, GetDeviceInfoContainsProvService) {
    service->initialize();
    std::string info = service->get_device_info();
    EXPECT_NE(info.find("PROV Service: Connected"), std::string::npos);
}

TEST_F(SecServiceTest, ApplyCertificateNotInitialized) {
    ErrorCode result = service->apply_certificate();
    EXPECT_EQ(result, ErrorCode::NOT_INITIALIZED);
}

TEST_F(SecServiceTest, ApplyCertificate) {
    // 创建空的状态文件，以便load_state()成功
    std::ofstream state_file("/tmp/test_sec_state.json");
    state_file << "{}";
    state_file.close();
    
    ErrorCode result = service->initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);
    
    result = service->apply_certificate();
    // 在没有DIAG服务的情况下，会尝试提交CSR到云端，但云端连接会失败
    EXPECT_EQ(result, ErrorCode::PKI_CONNECTION_FAILED);
}

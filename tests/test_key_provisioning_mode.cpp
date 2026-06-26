#include <gtest/gtest.h>
#include "sec_service.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace tbox::sec;

class MockProvServiceForModeTest : public ProvServiceInterface {
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

class KeyProvisioningModeTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/tbox_sec_mode_test_" + std::to_string(
            std::chrono::system_clock::now().time_since_epoch().count());
        fs::create_directories(test_dir_);

        state_file_ = test_dir_ + "/state.json";
        std::ofstream state_file(state_file_);
        state_file << "{}";
        state_file.close();
    }

    void TearDown() override {
        fs::remove_all(test_dir_);
    }

    std::string test_dir_;
    std::string state_file_;
};

TEST_F(KeyProvisioningModeTest, HsmModeDefault) {
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "hsm";
    config.state_file_path = state_file_;
    config.is_production = false;

    auto prov_service = std::make_shared<MockProvServiceForModeTest>();
    auto service = std::make_unique<SecService>(config, nullptr, prov_service);
    auto err = service->initialize();
    EXPECT_EQ(err, ErrorCode::SUCCESS);
}

TEST_F(KeyProvisioningModeTest, SoftFileModeInTestEnv) {
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "soft_file";
    config.soft_key_config.key_path = test_dir_;
    config.state_file_path = state_file_;
    config.is_production = false;

    auto prov_service = std::make_shared<MockProvServiceForModeTest>();
    auto service = std::make_unique<SecService>(config, nullptr, prov_service);
    auto err = service->initialize();
    EXPECT_EQ(err, ErrorCode::SUCCESS);
}

TEST_F(KeyProvisioningModeTest, SoftFileModeInProductionFails) {
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "soft_file";
    config.soft_key_config.key_path = test_dir_;
    config.state_file_path = state_file_;
    config.is_production = true;

    auto prov_service = std::make_shared<MockProvServiceForModeTest>();
    auto service = std::make_unique<SecService>(config, nullptr, prov_service);
    auto err = service->initialize();
    EXPECT_EQ(err, ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED);
}

TEST_F(KeyProvisioningModeTest, GenerateKeyInHsmMode) {
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "hsm";
    config.state_file_path = state_file_;
    config.is_production = false;

    auto prov_service = std::make_shared<MockProvServiceForModeTest>();
    auto service = std::make_unique<SecService>(config, nullptr, prov_service);
    auto err = service->initialize();
    ASSERT_EQ(err, ErrorCode::SUCCESS);

    err = service->generate_key_pair();
    EXPECT_EQ(err, ErrorCode::SUCCESS);
}

TEST_F(KeyProvisioningModeTest, GenerateKeyInSoftFileMode) {
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "soft_file";
    config.soft_key_config.key_path = test_dir_;
    config.state_file_path = state_file_;
    config.is_production = false;

    auto prov_service = std::make_shared<MockProvServiceForModeTest>();
    auto service = std::make_unique<SecService>(config, nullptr, prov_service);
    auto err = service->initialize();
    ASSERT_EQ(err, ErrorCode::SUCCESS);

    err = service->generate_key_pair();
    EXPECT_EQ(err, ErrorCode::SUCCESS);
}

TEST_F(KeyProvisioningModeTest, InvalidModeDefaultsToHsm) {
    SecServiceConfig config;
    config.hsm_type = "software";
    config.key_provisioning_mode = "invalid_mode";
    config.state_file_path = state_file_;
    config.is_production = false;

    auto prov_service = std::make_shared<MockProvServiceForModeTest>();
    auto service = std::make_unique<SecService>(config, nullptr, prov_service);
    auto err = service->initialize();
    EXPECT_EQ(err, ErrorCode::SUCCESS);
}

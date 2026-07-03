#include "gtest/gtest.h"
#include "sec_service.h"
#include "prov_service_interface.h"
#include "config.h"
#include "store.h"

#include <filesystem>
#include <fstream>

using namespace tbox::sec;
using namespace hwyz::config;
using namespace hwyz::store;

class MockProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }

    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.device_sn = "TESTDEVICE001";
        return ErrorCode::SUCCESS;
    }

    bool is_connected() const override {
        return true;
    }

    std::string get_service_status() const override {
        return "Connected";
    }
};

class FrameworkIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_framework_integration_" + std::to_string(getpid());
        config_dir_ = test_dir_ + "/config";
        store_dir_ = test_dir_ + "/store";

        std::filesystem::create_directories(config_dir_);
        std::filesystem::create_directories(store_dir_);

        create_test_config();
    }

    void TearDown() override {
        std::filesystem::remove_all(test_dir_);
    }

    void create_test_config() {
        std::ofstream common(config_dir_ + "/common.yaml");
        common << "log:\n  level: \"info\"\n";
        common << "cloud:\n  endpoint: \"https://test.example.com\"\n  timeout_ms: 1000\n";
        common.close();

        std::filesystem::create_directories(config_dir_ + "/conf.d");
        std::ofstream sec(config_dir_ + "/conf.d/sec.yaml");
        sec << "hsm:\n  type: \"soft_file\"\n  library_path: \"/usr/lib/libhsm.so\"\n";
        sec << "key_provisioning:\n  mode: \"soft_file\"\n";
        sec.close();
    }

    std::string test_dir_;
    std::string config_dir_;
    std::string store_dir_;
};

TEST_F(FrameworkIntegrationTest, ConfigLoading) {
    auto& config_manager = ConfigManager::instance();
    auto result = config_manager.load("sec", config_dir_);

    EXPECT_EQ(result, ConfigError::kOk);

    auto snapshot = config_manager.getSnapshot();
    EXPECT_EQ(snapshot->getString("hsm.type"), "soft_file");
    EXPECT_EQ(snapshot->getString("cloud.endpoint"), "https://test.example.com");
}

TEST_F(FrameworkIntegrationTest, StoreOperations) {
    auto store = Store::open("sec", store_dir_);

    store.save("test_key", std::string("test_value"));
    auto value = store.load<std::string>("test_key");
    EXPECT_EQ(value, "test_value");

    store.remove("test_key");
    EXPECT_FALSE(store.has("test_key"));
}

TEST_F(FrameworkIntegrationTest, EndToEndWorkflow) {
    auto& config_manager = ConfigManager::instance();
    config_manager.load("sec", config_dir_);
    auto config_snapshot = config_manager.getSnapshot();

    auto store = Store::open("sec", store_dir_);

    SecServiceConfig config;
    config.config_snapshot = config_snapshot;

    auto prov_service = std::make_shared<MockProvService>();
    SecService service(config, nullptr, prov_service, std::move(store));
    auto result = service.initialize();

    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

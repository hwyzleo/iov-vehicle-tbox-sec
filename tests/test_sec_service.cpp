#include "gtest/gtest.h"
#include "sec_service.h"
#include "config.h"
#include "store.h"
#include "prov_service_interface.h"

#include <filesystem>
#include <fstream>
#include <optional>

using namespace tbox::sec;

// Simple mock ProvService for testing
class SimpleProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.device_sn = "TBOX-DEV-001";
        return ErrorCode::SUCCESS;
    }
    
    bool is_connected() const override {
        return true;
    }
    
    std::string get_service_status() const override {
        return "OK";
    }
};

class SecServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_sec_service_" + std::to_string(getpid());
        config_dir_ = test_dir_ + "/config";
        store_dir_ = test_dir_ + "/store";

        std::filesystem::create_directories(config_dir_);
        std::filesystem::create_directories(store_dir_);

        create_test_config();

        auto& config_manager = hwyz::config::ConfigManager::instance();
        config_manager.load("sec", config_dir_);
        config_snapshot_ = config_manager.getSnapshot();

        store_.emplace(hwyz::store::Store::open("sec", store_dir_));
    }

    void TearDown() override {
        store_.reset();
        std::filesystem::remove_all(test_dir_);
    }

    void create_test_config() {
        std::ofstream common(config_dir_ + "/common.yaml");
        common << "cloud:\n  endpoint: \"https://test.example.com\"\n  timeout_ms: 1000\n";
        common << "\nlog:\n  level: \"info\"\n";
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
    std::shared_ptr<const hwyz::config::ImmutableConfigView> config_snapshot_;
    std::optional<hwyz::store::Store> store_;
};

TEST_F(SecServiceTest, InitializeSuccess) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    
    // Create simple prov service
    auto prov_service = std::make_shared<SimpleProvService>();
    
    SecService service(config, nullptr, prov_service, std::move(*store_));
    auto result = service.initialize();

    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

#include "gtest/gtest.h"
#include "sec_service.h"
#include "diag_service_interface.h"
#include "config.h"
#include "store.h"

#include <filesystem>
#include <fstream>
#include <optional>

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

// Simple mock ProvService for testing
class SimpleProvService : public ProvServiceInterface {
public:
    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }
    
    ErrorCode get_vehicle_info(VehicleInfo& info) override {
        info.vin = "TESTVIN1234567890";
        info.ecu_uid = "TBOX-DEV-001";
        return ErrorCode::SUCCESS;
    }
    
    bool is_connected() const override {
        return true;
    }
    
    std::string get_service_status() const override {
        return "OK";
    }
};

class SecServiceWithDiagTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_sec_service_diag_" + std::to_string(getpid());
        config_dir_ = test_dir_ + "/config";
        store_dir_ = test_dir_ + "/store";

        std::filesystem::create_directories(config_dir_);
        std::filesystem::create_directories(store_dir_);

        create_test_config();

        auto& config_manager = hwyz::config::ConfigManager::instance();
        config_manager.load("sec", config_dir_);
        config_snapshot_ = config_manager.getSnapshot();

        store_.emplace(hwyz::store::Store::open("sec", store_dir_));

        mock_diag_service = std::make_shared<MockDiagService>();
    }

    void TearDown() override {
        mock_diag_service.reset();
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
    std::shared_ptr<MockDiagService> mock_diag_service;
};

TEST_F(SecServiceWithDiagTest, InitializeWithDiagService) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;
    
    auto prov_service = std::make_shared<SimpleProvService>();

    SecService service(config, mock_diag_service, prov_service, std::move(*store_));
    EXPECT_FALSE(service.is_initialized());

    ErrorCode result = service.initialize();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_TRUE(service.is_initialized());
    EXPECT_TRUE(mock_diag_service->is_connected());
}

TEST_F(SecServiceWithDiagTest, GenerateKeyPairViaDiag) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;

    auto prov_service = std::make_shared<SimpleProvService>();
    SecService service(config, mock_diag_service, prov_service, std::move(*store_));
    ErrorCode result = service.initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);

    result = service.generate_key_pair();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
    EXPECT_EQ(mock_diag_service->get_last_request_type(), DiagRequestType::GENERATE_KEY_PAIR);
    EXPECT_GT(mock_diag_service->get_request_count(), 0);
}

TEST_F(SecServiceWithDiagTest, ApplyCertificateViaDiag) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;

    auto prov_service = std::make_shared<SimpleProvService>();
    SecService service(config, mock_diag_service, prov_service, std::move(*store_));
    ErrorCode result = service.initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);

    result = service.apply_certificate();
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

class SecServiceDiagFailureTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_sec_diag_fail_" + std::to_string(getpid());
        config_dir_ = test_dir_ + "/config";
        store_dir_ = test_dir_ + "/store";

        std::filesystem::create_directories(config_dir_);
        std::filesystem::create_directories(store_dir_);

        create_test_config();

        auto& config_manager = hwyz::config::ConfigManager::instance();
        config_manager.load("sec", config_dir_);
        config_snapshot_ = config_manager.getSnapshot();

        store_.emplace(hwyz::store::Store::open("sec", store_dir_));

        failing_diag_service = std::make_shared<FailingDiagService>();
    }

    void TearDown() override {
        failing_diag_service.reset();
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
    std::shared_ptr<FailingDiagService> failing_diag_service;
};

TEST_F(SecServiceDiagFailureTest, GenerateKeyPairFailsWhenDisconnected) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;

    auto prov_service = std::make_shared<SimpleProvService>();
    SecService service(config, failing_diag_service, prov_service, std::move(*store_));
    ErrorCode result = service.initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);

    result = service.generate_key_pair();
    EXPECT_EQ(result, ErrorCode::CONNECTION_FAILED);
}

TEST_F(SecServiceDiagFailureTest, ApplyCertificateFailsWhenDisconnected) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;

    auto prov_service = std::make_shared<SimpleProvService>();
    SecService service(config, failing_diag_service, prov_service, std::move(*store_));
    ErrorCode result = service.initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);

    result = service.apply_certificate();
    EXPECT_EQ(result, ErrorCode::CONNECTION_FAILED);
}

class SecServiceFallbackTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "/tmp/test_sec_fallback_" + std::to_string(getpid());
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

TEST_F(SecServiceFallbackTest, GenerateKeyPairWithoutDiagService) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;

    auto prov_service = std::make_shared<SimpleProvService>();
    SecService service(config, nullptr, prov_service, std::move(*store_));
    ErrorCode result = service.initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);

    result = service.generate_key_pair();
    EXPECT_EQ(result, ErrorCode::SUCCESS);
}

TEST_F(SecServiceFallbackTest, ApplyCertificateWithoutDiagService) {
    SecServiceConfig config;
    config.config_snapshot = config_snapshot_;
    config.store_root = store_dir_;
    config.soft_key_config.key_path = store_dir_;

    auto prov_service = std::make_shared<SimpleProvService>();
    SecService service(config, nullptr, prov_service, std::move(*store_));
    ErrorCode result = service.initialize();
    ASSERT_EQ(result, ErrorCode::SUCCESS);

    result = service.apply_certificate();
    EXPECT_EQ(result, ErrorCode::PKI_CONNECTION_FAILED);
}

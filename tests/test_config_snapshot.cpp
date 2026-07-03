#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "sec_service.h"
#include "config.h"

using namespace tbox::sec;
using namespace hwyz::config;
using ::testing::Return;
using ::testing::_;

class MockImmutableConfigView : public ImmutableConfigView {
public:
    MOCK_METHOD(bool, has, (const std::string& key), (const, override));
    MOCK_METHOD(std::string, getString, (const std::string& key, const std::string& defaultValue), (const, override));
    MOCK_METHOD(int, getInt, (const std::string& key, int defaultValue), (const, override));
    MOCK_METHOD(double, getDouble, (const std::string& key, double defaultValue), (const, override));
    MOCK_METHOD(bool, getBool, (const std::string& key, bool defaultValue), (const, override));
    MOCK_METHOD(std::vector<std::string>, getStringList, (const std::string& key), (const, override));
    MOCK_METHOD(std::shared_ptr<const ImmutableConfigView>, getSection, (const std::string& key), (const, override));
    MOCK_METHOD(std::vector<std::string>, getKeys, (), (const, override));
};

TEST(ConfigSnapshotTest, PrecedenceOverLegacyFields) {
    SecServiceConfig config;
    config.hsm_type = "legacy_hsm";
    config.key_provisioning_mode = "legacy_mode";

    auto snapshot = std::make_shared<MockImmutableConfigView>();
    EXPECT_CALL(*snapshot, getString("hsm.type", ""))
        .WillOnce(Return("snapshot_hsm"));
    EXPECT_CALL(*snapshot, getString("key_provisioning.mode", "hsm"))
        .WillOnce(Return("snapshot_mode"));

    config.config_snapshot = snapshot;

    EXPECT_EQ(config.get_hsm_type(), "snapshot_hsm");
    EXPECT_EQ(config.get_key_provisioning_mode(), "snapshot_mode");
}

TEST(ConfigSnapshotTest, FallbackToLegacyWhenNoSnapshot) {
    SecServiceConfig config;
    config.hsm_type = "legacy_hsm";
    config.key_provisioning_mode = "legacy_mode";

    EXPECT_EQ(config.get_hsm_type(), "legacy_hsm");
    EXPECT_EQ(config.get_key_provisioning_mode(), "legacy_mode");
}

TEST(ConfigSnapshotTest, CloudConfigPrecedence) {
    SecServiceConfig config;
    config.cloud_config.oapi_endpoint = "https://legacy.example.com";
    config.cloud_config.timeout_ms = 3000;
    config.cloud_config.retry_count = 5;
    config.cloud_config.retry_delay_ms = 2000;

    auto snapshot = std::make_shared<MockImmutableConfigView>();
    EXPECT_CALL(*snapshot, getString("cloud.endpoint", ""))
        .WillOnce(Return("https://snapshot.example.com"));
    EXPECT_CALL(*snapshot, getInt("cloud.timeout_ms", 5000))
        .WillOnce(Return(8000));
    EXPECT_CALL(*snapshot, getInt("cloud.retry_count", 3))
        .WillOnce(Return(2));
    EXPECT_CALL(*snapshot, getInt("cloud.retry_delay_ms", 1000))
        .WillOnce(Return(500));

    config.config_snapshot = snapshot;

    EXPECT_EQ(config.get_cloud_endpoint(), "https://snapshot.example.com");
    EXPECT_EQ(config.get_cloud_timeout_ms(), 8000);
    EXPECT_EQ(config.get_cloud_retry_count(), 2);
    EXPECT_EQ(config.get_cloud_retry_delay_ms(), 500);
}

TEST(ConfigSnapshotTest, StoragePathPrecedence) {
    SecServiceConfig config;
    config.state_file_path = "/legacy/state.json";
    config.ca_cert_path = "/legacy/ca.pem";
    config.cert_store_path = "/legacy/certs";

    auto snapshot = std::make_shared<MockImmutableConfigView>();
    EXPECT_CALL(*snapshot, getString("storage.state_file", "/var/lib/tbox/sec/provision_state.json"))
        .WillOnce(Return("/snapshot/state.json"));
    EXPECT_CALL(*snapshot, getString("storage.ca_cert", ""))
        .WillOnce(Return("/snapshot/ca.pem"));
    EXPECT_CALL(*snapshot, getString("storage.cert_store", ""))
        .WillOnce(Return("/snapshot/certs"));

    config.config_snapshot = snapshot;

    EXPECT_EQ(config.get_state_file_path(), "/snapshot/state.json");
    EXPECT_EQ(config.get_ca_cert_path(), "/snapshot/ca.pem");
    EXPECT_EQ(config.get_cert_store_path(), "/snapshot/certs");
}

TEST(ConfigSnapshotTest, SoftKeyConfigPrecedence) {
    SecServiceConfig config;
    config.soft_key_config.key_path = "/legacy/keys";
    config.soft_key_config.encryption_algo = "legacy-algo";
    config.soft_key_config.encryption_key_path = "/legacy/key.pem";

    auto snapshot = std::make_shared<MockImmutableConfigView>();
    EXPECT_CALL(*snapshot, getString("soft_key.path", "/var/lib/tbox/sec/soft_keys"))
        .WillOnce(Return("/snapshot/keys"));
    EXPECT_CALL(*snapshot, getString("soft_key.encryption_algo", "aes-256-gcm"))
        .WillOnce(Return("snapshot-algo"));
    EXPECT_CALL(*snapshot, getString("soft_key.encryption_key_path", ""))
        .WillOnce(Return("/snapshot/key.pem"));

    config.config_snapshot = snapshot;

    EXPECT_EQ(config.get_soft_key_path(), "/snapshot/keys");
    EXPECT_EQ(config.get_soft_key_encryption_algo(), "snapshot-algo");
    EXPECT_EQ(config.get_soft_key_encryption_key_path(), "/snapshot/key.pem");
}

TEST(ConfigSnapshotTest, EnvironmentPrecedence) {
    SecServiceConfig config;
    config.is_production = false;

    auto snapshot = std::make_shared<MockImmutableConfigView>();
    EXPECT_CALL(*snapshot, getBool("environment.is_production", false))
        .WillOnce(Return(true));

    config.config_snapshot = snapshot;

    EXPECT_TRUE(config.get_is_production());
}

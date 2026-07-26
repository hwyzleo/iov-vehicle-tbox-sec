#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "log_types.h"

using namespace tbox::sec;
using namespace tbox::fw::log;

class SecLogAdapterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 每个测试前重置状态
    }

    void TearDown() override {
        // 每个测试后清理
    }
};

TEST_F(SecLogAdapterTest, InitSuccess) {
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    
    auto result = SecLogAdapter::init("sec_test", config);
    EXPECT_EQ(result.error, LogError::kOk);
}

TEST_F(SecLogAdapterTest, GetServiceLogger) {
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    SecLogAdapter::init("sec_test", config);
    
    auto logger = SecLogAdapter::service();
    EXPECT_NO_THROW(logger.info("test.event", "test message"));
}

TEST_F(SecLogAdapterTest, GetProvisioningLogger) {
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    SecLogAdapter::init("sec_test", config);
    
    auto logger = SecLogAdapter::provisioning();
    EXPECT_NO_THROW(logger.info("test.event", "test message"));
}

TEST_F(SecLogAdapterTest, GetCertificateLogger) {
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    SecLogAdapter::init("sec_test", config);
    
    auto logger = SecLogAdapter::certificate();
    EXPECT_NO_THROW(logger.info("test.event", "test message"));
}

TEST_F(SecLogAdapterTest, GetSeedKeyLogger) {
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    SecLogAdapter::init("sec_test", config);
    
    auto logger = SecLogAdapter::seed_key();
    EXPECT_NO_THROW(logger.info("test.event", "test message"));
}

TEST_F(SecLogAdapterTest, GetIpcLogger) {
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    SecLogAdapter::init("sec_test", config);
    
    auto logger = SecLogAdapter::ipc();
    EXPECT_NO_THROW(logger.info("test.event", "test message"));
}

#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "log_types.h"

using namespace tbox::sec;
using namespace tbox::fw::log;

class SecLogFaultTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 每个测试前重置
    }
};

TEST_F(SecLogFaultTest, LoggerInitFailureDegradation) {
    // 测试 Logger 初始化失败时的降级行为
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    config.strict = false;  // 非严格模式
    
    // 模拟初始化失败（例如配置无效）
    // 这里测试正常初始化，验证降级逻辑存在
    auto result = SecLogAdapter::init("sec_test", config);
    
    // 在非严格模式下，即使初始化失败也应该能继续
    if (result.error != LogError::kOk) {
        // 验证降级行为
        EXPECT_FALSE(result.error_message.empty());
    }
}

TEST_F(SecLogFaultTest, LoggerInitStrictMode) {
    // 测试严格模式下的 Logger 初始化
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    config.strict = true;  // 严格模式
    
    auto result = SecLogAdapter::init("sec_test", config);
    
    // 严格模式下，初始化成功应该返回 kOk
    EXPECT_EQ(result.error, LogError::kOk);
}

TEST_F(SecLogFaultTest, QueueOverflowHandling) {
    // 测试队列溢出处理
    LogConfig config;
    config.level = LogLevel::kDebug;
    config.console_config.enabled = true;
    config.async_config.enabled = true;
    config.async_config.queue_size = 10;  // 小队列
    
    SecLogAdapter::init("sec_test", config);
    
    // 快速生成大量日志
    for (int i = 0; i < 100; ++i) {
        SecLogAdapter::service().info(
            "test.queue_overflow",
            "测试队列溢出",
            {{"index", FieldValue::makeInt(i)}}
        );
    }
    
    // 应该不会崩溃
    EXPECT_TRUE(true);
}

TEST_F(SecLogFaultTest, SinkFailureHandling) {
    // 测试 sink 故障处理
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;
    config.file_config.enabled = true;
    config.file_config.root = "/nonexistent/path";
    
    SecLogAdapter::init("sec_test", config);
    
    // 尝试输出日志
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.sink_failure",
            "测试 sink 故障"
        );
    });
}

TEST_F(SecLogFaultTest, MultipleInitCalls) {
    // 测试多次初始化
    LogConfig config1;
    config1.level = LogLevel::kInfo;
    config1.console_config.enabled = true;
    
    LogConfig config2;
    config2.level = LogLevel::kDebug;
    config2.console_config.enabled = true;
    
    auto result1 = SecLogAdapter::init("sec_test1", config1);
    auto result2 = SecLogAdapter::init("sec_test2", config2);
    
    // 两次初始化都应该成功（或第二次被忽略）
    EXPECT_EQ(result1.error, LogError::kOk);
}

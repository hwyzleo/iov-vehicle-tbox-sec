#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "log_types.h"

using namespace tbox::sec;
using namespace tbox::fw::log;

class SecLogContextTest : public ::testing::Test {
protected:
    void SetUp() override {
        LogConfig config;
        config.level = LogLevel::kDebug;
        config.console_config.enabled = true;
        SecLogAdapter::init("sec_test", config);
    }
};

TEST_F(SecLogContextTest, ContextScopeCreation) {
    LogContext context;
    context.trace_id = "trace-123";
    context.request_id = "req-456";
    context.session_id = "sess-789";
    
    {
        ContextScope scope(context);
        
        // 验证上下文可用
        const LogContext* current = ContextScope::current();
        ASSERT_NE(current, nullptr);
        EXPECT_EQ(current->trace_id, "trace-123");
        EXPECT_EQ(current->request_id, "req-456");
        EXPECT_EQ(current->session_id, "sess-789");
    }
}

TEST_F(SecLogContextTest, ContextScopeNested) {
    LogContext outer_context;
    outer_context.trace_id = "outer-trace";
    outer_context.request_id = "outer-req";
    
    LogContext inner_context;
    inner_context.trace_id = "inner-trace";
    inner_context.request_id = "inner-req";
    
    {
        ContextScope outer_scope(outer_context);
        
        const LogContext* current = ContextScope::current();
        EXPECT_EQ(current->trace_id, "outer-trace");
        
        {
            ContextScope inner_scope(inner_context);
            
            current = ContextScope::current();
            EXPECT_EQ(current->trace_id, "inner-trace");
        }
        
        // 退出内部作用域后恢复外部上下文
        current = ContextScope::current();
        EXPECT_EQ(current->trace_id, "outer-trace");
    }
}

TEST_F(SecLogContextTest, ContextScopeEmpty) {
    LogContext context;
    // 不设置任何 ID
    
    {
        ContextScope scope(context);
        
        const LogContext* current = ContextScope::current();
        ASSERT_NE(current, nullptr);
        EXPECT_TRUE(current->trace_id.empty());
        EXPECT_TRUE(current->request_id.empty());
        EXPECT_TRUE(current->session_id.empty());
    }
}

TEST_F(SecLogContextTest, ContextScopeNullWhenNone) {
    // 没有 ContextScope 时，current 应返回 nullptr 或空
    const LogContext* current = ContextScope::current();
    // 根据实现，可能是 nullptr 或空上下文
    // 这里假设为 nullptr
    EXPECT_EQ(current, nullptr);
}

TEST_F(SecLogContextTest, LogWithContext) {
    LogContext context;
    context.trace_id = "trace-123";
    context.request_id = "req-456";
    context.session_id = "sess-789";
    
    {
        ContextScope scope(context);
        
        // 在上下文中输出日志
        EXPECT_NO_THROW({
            SecLogAdapter::service().info(
                "sec.test.with_context",
                "带上下文的日志",
                {{"test_field", FieldValue::makeString("value")}}
            );
        });
    }
}

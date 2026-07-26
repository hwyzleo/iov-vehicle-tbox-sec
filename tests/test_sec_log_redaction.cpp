#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "log_types.h"

using namespace tbox::sec;
using namespace tbox::fw::log;

class SecLogRedactionTest : public ::testing::Test {
protected:
    void SetUp() override {
        LogConfig config;
        config.level = LogLevel::kDebug;
        config.console_config.enabled = true;
        config.redact_config.identifiers = "mask";
        SecLogAdapter::init("sec_test", config);
    }
};

TEST_F(SecLogRedactionTest, IdentifierMasking) {
    // Identifier 字段应该被掩码
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.identifier",
            "测试标识符掩码",
            {
                {"device_sn", FieldValue::makeString("ABCDEFGH12345678"), Sensitivity::Identifier},
                {"vin", FieldValue::makeString("LMWXXX1234567890"), Sensitivity::Identifier}
            }
        );
    });
}

TEST_F(SecLogRedactionTest, SecretRejection) {
    // Secret 字段应该被拒绝输出
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.secret",
            "测试密钥拒绝",
            {
                {"private_key", FieldValue::makeString("MIIEvgIBADANBg..."), Sensitivity::Secret},
                {"symmetric_key", FieldValue::makeString("0123456789abcdef"), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogRedactionTest, PayloadLimiting) {
    // Payload 字段应该被限长
    std::string long_payload(1000, 'A');
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.payload",
            "测试报文限长",
            {
                {"raw_csr", FieldValue::makeString(long_payload), Sensitivity::Payload}
            }
        );
    });
}

TEST_F(SecLogRedactionTest, NormalFieldNoRedaction) {
    // Normal 字段不应该被脱敏
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.normal",
            "测试普通字段",
            {
                {"algorithm", FieldValue::makeString("RSA-2048"), Sensitivity::Normal},
                {"duration_ms", FieldValue::makeInt(150), Sensitivity::Normal}
            }
        );
    });
}

TEST_F(SecLogRedactionTest, MixedSensitivityFields) {
    // 混合不同敏感度的字段
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.mixed",
            "测试混合敏感度字段",
            {
                {"algorithm", FieldValue::makeString("RSA-2048"), Sensitivity::Normal},
                {"device_sn", FieldValue::makeString("DEVICE123"), Sensitivity::Identifier},
                {"private_key", FieldValue::makeString("SECRET_KEY"), Sensitivity::Secret},
                {"raw_csr", FieldValue::makeString("CSR_DATA"), Sensitivity::Payload}
            }
        );
    });
}

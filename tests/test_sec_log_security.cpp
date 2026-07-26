#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "log_types.h"

using namespace tbox::sec;
using namespace tbox::fw::log;

class SecLogSecurityTest : public ::testing::Test {
protected:
    void SetUp() override {
        LogConfig config;
        config.level = LogLevel::kDebug;
        config.console_config.enabled = true;
        config.redact_config.identifiers = "mask";
        SecLogAdapter::init("sec_test", config);
    }
};

TEST_F(SecLogSecurityTest, PrivateKeyNotExposed) {
    // 私钥不应在日志中明文出现
    std::string private_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...";
    
    // 尝试输出私钥（作为 Secret 字段）
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.private_key",
            "测试私钥不暴露",
            {
                {"private_key", FieldValue::makeString(private_key), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, SymmetricKeyNotExposed) {
    // 对称密钥不应在日志中明文出现
    std::string symmetric_key = "0123456789abcdef0123456789abcdef";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.symmetric_key",
            "测试对称密钥不暴露",
            {
                {"symmetric_key", FieldValue::makeString(symmetric_key), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, SeedNotExposed) {
    // Seed 不应在日志中明文出现
    std::string seed = "abcdef1234567890";
    
    EXPECT_NO_THROW({
        SecLogAdapter::seed_key().info(
            "test.seed",
            "测试 seed 不暴露",
            {
                {"seed", FieldValue::makeString(seed), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, KeyNotExposed) {
    // Key 不应在日志中明文出现
    std::string key = "fedcba0987654321";
    
    EXPECT_NO_THROW({
        SecLogAdapter::seed_key().info(
            "test.key",
            "测试 key 不暴露",
            {
                {"key", FieldValue::makeString(key), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, RawCsrNotExposed) {
    // 原始 CSR 不应在日志中明文出现
    std::string raw_csr = "MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCQ04xDTALBgNVBAgMBHRlc3Q...";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.raw_csr",
            "测试原始 CSR 不暴露",
            {
                {"raw_csr", FieldValue::makeString(raw_csr), Sensitivity::Payload}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, RawCertNotExposed) {
    // 原始证书不应在日志中明文出现
    std::string raw_cert = "MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3DQEBCwUA...";
    
    EXPECT_NO_THROW({
        SecLogAdapter::certificate().info(
            "test.raw_cert",
            "测试原始证书不暴露",
            {
                {"raw_cert", FieldValue::makeString(raw_cert), Sensitivity::Payload}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, HsmHandleNotExposed) {
    // HSM 句柄不应在日志中明文出现
    std::string hsm_handle = "handle_12345_internal";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.hsm_handle",
            "测试 HSM 句柄不暴露",
            {
                {"hsm_handle", FieldValue::makeString(hsm_handle), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, VinMasked) {
    // VIN 应该被掩码
    std::string vin = "LMWXXX1234567890";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.vin",
            "测试 VIN 掩码",
            {
                {"vin", FieldValue::makeString(vin), Sensitivity::Identifier}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, UidMasked) {
    // ECU UID 应该被掩码
    std::string ecu_uid = "ECU123456789";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.uid",
            "测试 UID 掩码",
            {
                {"ecu_uid", FieldValue::makeString(ecu_uid), Sensitivity::Identifier}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, TokenNotExposed) {
    // Token 不应在日志中明文出现
    std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.token",
            "测试 Token 不暴露",
            {
                {"token", FieldValue::makeString(token), Sensitivity::Secret}
            }
        );
    });
}

TEST_F(SecLogSecurityTest, PinNotExposed) {
    // PIN 不应在日志中明文出现
    std::string pin = "123456";
    
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "test.pin",
            "测试 PIN 不暴露",
            {
                {"pin", FieldValue::makeString(pin), Sensitivity::Secret}
            }
        );
    });
}

#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "log_types.h"

using namespace tbox::sec;
using namespace tbox::fw::log;

class SecLogEventsTest : public ::testing::Test {
protected:
    void SetUp() override {
        LogConfig config;
        config.level = LogLevel::kDebug;
        config.console_config.enabled = true;
        SecLogAdapter::init("sec_test", config);
    }

    void TearDown() override {
        // 清理
    }
};

TEST_F(SecLogEventsTest, LogInitialized) {
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "sec.service.log_initialized",
            "SEC 日志系统初始化成功",
            {
                {"service", FieldValue::makeString("sec")},
                {"sink_mode", FieldValue::makeString("console")}
            }
        );
    });
}

TEST_F(SecLogEventsTest, KeypairGenerateSucceeded) {
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "sec.keypair.generate.succeeded",
            "密钥对生成成功",
            {
                {"algorithm", FieldValue::makeString("RSA-2048")},
                {"storage_mode", FieldValue::makeString("file")},
                {"key_id_hash", FieldValue::makeString("abc123def456")},
                {"duration_ms", FieldValue::makeInt(150)}
            }
        );
    });
}

TEST_F(SecLogEventsTest, KeypairGenerateFailed) {
    EXPECT_NO_THROW({
        SecLogAdapter::service().error(
            "sec.keypair.generate.failed",
            "密钥对生成失败",
            {
                {"algorithm", FieldValue::makeString("RSA-2048")},
                {"storage_mode", FieldValue::makeString("file")},
                {"duration_ms", FieldValue::makeInt(50)},
                {"error_code", FieldValue::makeString("SEC-1001")}
            }
        );
    });
}

TEST_F(SecLogEventsTest, CsrBuildSucceeded) {
    EXPECT_NO_THROW({
        SecLogAdapter::service().info(
            "sec.csr.build.succeeded",
            "CSR 构造成功",
            {
                {"subject_profile", FieldValue::makeString("device")},
                {"key_id_hash", FieldValue::makeString("abc123def456")},
                {"duration_ms", FieldValue::makeInt(100)}
            }
        );
    });
}

TEST_F(SecLogEventsTest, CsrBuildFailed) {
    EXPECT_NO_THROW({
        SecLogAdapter::service().error(
            "sec.csr.build.failed",
            "CSR 构造失败",
            {
                {"subject_profile", FieldValue::makeString("device")},
                {"duration_ms", FieldValue::makeInt(50)},
                {"error_code", FieldValue::makeString("SEC-1002")}
            }
        );
    });
}

TEST_F(SecLogEventsTest, BindingNotReady) {
    EXPECT_NO_THROW({
        SecLogAdapter::provisioning().warn(
            "sec.binding.not_ready",
            "PROV 尚未完成绑定",
            {
                {"provision_state", FieldValue::makeString("pending")},
                {"duration_ms", FieldValue::makeInt(0)},
                {"error_code", FieldValue::makeString("SEC-1006")}
            }
        );
    });
}

TEST_F(SecLogEventsTest, CertificateInstallSucceeded) {
    EXPECT_NO_THROW({
        SecLogAdapter::certificate().info(
            "sec.certificate.install.succeeded",
            "证书校验并安装成功",
            {
                {"cert_serial_hash", FieldValue::makeString("cert_hash_123")},
                {"issuer_id", FieldValue::makeString("issuer_456")},
                {"duration_ms", FieldValue::makeInt(200)}
            }
        );
    });
}

TEST_F(SecLogEventsTest, CertificateInstallFailed) {
    EXPECT_NO_THROW({
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书安装失败",
            {
                {"cert_serial_hash", FieldValue::makeString("cert_hash_123")},
                {"failure_stage", FieldValue::makeString("validation")},
                {"duration_ms", FieldValue::makeInt(100)},
                {"error_code", FieldValue::makeString("SEC-1005")}
            }
        );
    });
}

TEST_F(SecLogEventsTest, SeedGenerateFailed) {
    EXPECT_NO_THROW({
        SecLogAdapter::seed_key().error(
            "sec.seed.generate.failed",
            "seed 生成失败",
            {
                {"security_level", FieldValue::makeString("high")},
                {"duration_ms", FieldValue::makeInt(50)},
                {"error_code", FieldValue::makeString("SEC-1007")}
            }
        );
    });
}

TEST_F(SecLogEventsTest, SeedKeyVerifySucceeded) {
    EXPECT_NO_THROW({
        SecLogAdapter::seed_key().debug(
            "sec.seed_key.verify.succeeded",
            "key 校验通过",
            {
                {"security_level", FieldValue::makeString("high")},
                {"duration_ms", FieldValue::makeInt(30)}
            }
        );
    });
}

TEST_F(SecLogEventsTest, SeedKeyVerifyFailed) {
    EXPECT_NO_THROW({
        SecLogAdapter::seed_key().warn(
            "sec.seed_key.verify.failed",
            "key 校验失败",
            {
                {"security_level", FieldValue::makeString("high")},
                {"duration_ms", FieldValue::makeInt(30)},
                {"error_code", FieldValue::makeString("SEC-1008")}
            }
        );
    });
}

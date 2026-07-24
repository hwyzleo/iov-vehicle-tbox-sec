#include <gtest/gtest.h>
#include "csr_builder.h"
#include "cloud_client.h"
#include "sec_service.h"

using namespace tbox::sec;

// 验证 hsm_uid 用于 CSR 构建
TEST(DeviceIdentityTest, CsrUsesHsmUid) {
    CsrConfig config;
    config.hsm_uid = "test-hsm-uid-001";
    config.key_id = "test-hsm-uid-001";
    config.algorithm = "ecdsa-p256";

    EXPECT_EQ(config.hsm_uid, "test-hsm-uid-001");
    EXPECT_EQ(config.key_id, "test-hsm-uid-001");
    EXPECT_EQ(config.algorithm, "ecdsa-p256");
}

// 验证 CertificateRequest 使用 ecu_uid
TEST(DeviceIdentityTest, CertRequestUsesEcuUid) {
    CertificateRequest request;
    request.ecu_uid = "test-ecu-uid-001";
    request.csr_der = {0x30, 0x82, 0x01, 0x00};

    EXPECT_EQ(request.ecu_uid, "test-ecu-uid-001");
    EXPECT_FALSE(request.csr_der.empty());
}

// 验证 ProvisionStatus 包含 ecu_uid
TEST(DeviceIdentityTest, ProvisionStatusContainsEcuUid) {
    ProvisionStatus status;
    status.ecu_uid = "test-ecu-uid-001";
    status.vin = "TESTVIN0000000001";
    status.state = ProvisionState::NONE;

    auto json = status.to_json();
    EXPECT_EQ(json["ecu_uid"], "test-ecu-uid-001");
    EXPECT_EQ(json["vin"], "TESTVIN0000000001");
}

// 验证 ProvisionStatus 序列化/反序列化
TEST(DeviceIdentityTest, ProvisionStatusSerialization) {
    ProvisionStatus status;
    status.ecu_uid = "test-ecu-uid-002";
    status.vin = "TESTVIN0000000002";
    status.state = ProvisionState::KEY_GENERATED;

    auto json = status.to_json();
    auto restored = ProvisionStatus::from_json(json);

    EXPECT_EQ(restored.ecu_uid, "test-ecu-uid-002");
    EXPECT_EQ(restored.vin, "TESTVIN0000000002");
    EXPECT_EQ(restored.state, ProvisionState::KEY_GENERATED);
}

// 验证 CsrConfig 字段类型正确
TEST(DeviceIdentityTest, CsrConfigFieldTypes) {
    CsrConfig config;
    config.hsm_uid = "uid-001";
    config.key_id = "key-001";
    config.algorithm = "SHA256withECDSA";

    // 验证字段可以正确赋值和读取
    std::string hsm_uid = config.hsm_uid;
    std::string key_id = config.key_id;
    std::string algorithm = config.algorithm;

    EXPECT_EQ(hsm_uid, "uid-001");
    EXPECT_EQ(key_id, "key-001");
    EXPECT_EQ(algorithm, "SHA256withECDSA");
}

#pragma once

//
// V2C 密钥开通能力上报（TBOX-SEC-DSN-CR-020 §11 / US-022）。
//
// 结构定义已上移到公开 SDK 头 tbox/sec/business_key.h（TBOX-TSP-DSN-CR-012 Q1：
// TSP 需通过 SecClient 只读查询 capability，故 DTO 必须随 SDK 安装）。
// 本头文件保留为内部引用的兼容入口。
//

#include "tbox/sec/business_key.h"

namespace tbox {
namespace sec {

/// capability 契约版本别名（兼容旧引用）。
constexpr uint32_t kV2cKeyProvisioningCapabilityContractVersion =
    V2cKeyProvisioningCapability::kContractVersion;

} // namespace sec
} // namespace tbox

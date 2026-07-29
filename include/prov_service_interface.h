#pragma once

#include <string>
#include "error_codes.h"

namespace tbox {
namespace sec {

struct VehicleInfo {
    std::string vin;           // 保留但不再用于证书
    std::string ecu_uid;       // ECU硬件序列号，出厂锁定绑定芯片UID
};

// 车辆个性化/绑定状态，PROV 为权威来源（对应 PROV 的 tbox::prov::ProvisionState）。
// 注意：这与 SEC 自身的证书下发状态（ProvisionState: KEY_GENERATED/CSR_*/CERT_INSTALLED）
// 是两个不同的状态机，前者描述“车辆身份是否已绑定”，后者描述“安全证书下发进度”。
enum class DeviceProvisionState {
    UNKNOWN,      // 无法获取（PROV 不可用/未实现）
    NONE,         // 未开始
    VIN_WRITTEN,  // VIN 已写待绑
    BOUND,        // 已绑定
    FAILED        // 失败
};

inline const char* device_provision_state_to_string(DeviceProvisionState s) {
    switch (s) {
        case DeviceProvisionState::NONE:        return "NONE";
        case DeviceProvisionState::VIN_WRITTEN: return "VIN_WRITTEN";
        case DeviceProvisionState::BOUND:       return "BOUND";
        case DeviceProvisionState::FAILED:      return "FAILED";
        case DeviceProvisionState::UNKNOWN:     return "UNKNOWN";
    }
    return "UNKNOWN";
}

class ProvServiceInterface {
public:
    virtual ~ProvServiceInterface() = default;

    virtual ErrorCode initialize() = 0;

    // 获取设备信息，VIN 保留但不再用于证书 Subject，证书使用 HSM UID (ecu_uid)
    virtual ErrorCode get_vehicle_info(VehicleInfo& info) = 0;

    // 从 PROV（权威来源）查询车辆个性化/绑定状态。
    // 默认实现返回 NOT_IMPLEMENTED，便于既有 mock 无需改动；真实实现见 IpcProvService。
    virtual ErrorCode get_provision_state(DeviceProvisionState& state) {
        state = DeviceProvisionState::UNKNOWN;
        return ErrorCode::NOT_IMPLEMENTED;
    }

    virtual bool is_connected() const = 0;

    virtual std::string get_service_status() const = 0;
};

} // namespace sec
} // namespace tbox
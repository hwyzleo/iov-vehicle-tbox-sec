#pragma once

#include <string>
#include "error_codes.h"

namespace tbox {
namespace sec {

struct VehicleInfo {
    std::string vin;           // 保留但不再用于证书
    std::string ecu_uid;       // ECU硬件序列号，出厂锁定绑定芯片UID
};

class ProvServiceInterface {
public:
    virtual ~ProvServiceInterface() = default;

    virtual ErrorCode initialize() = 0;

    // 获取设备信息，VIN 保留但不再用于证书 Subject，证书使用 HSM UID (ecu_uid)
    virtual ErrorCode get_vehicle_info(VehicleInfo& info) = 0;

    virtual bool is_connected() const = 0;

    virtual std::string get_service_status() const = 0;
};

} // namespace sec
} // namespace tbox
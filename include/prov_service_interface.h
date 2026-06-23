#pragma once

#include <string>
#include "error_codes.h"

namespace tbox {
namespace sec {

struct VehicleInfo {
    std::string vin;
    std::string ecu_uid;
};

class ProvServiceInterface {
public:
    virtual ~ProvServiceInterface() = default;

    virtual ErrorCode initialize() = 0;

    virtual ErrorCode get_vehicle_info(VehicleInfo& info) = 0;

    virtual bool is_connected() const = 0;

    virtual std::string get_service_status() const = 0;
};

} // namespace sec
} // namespace tbox
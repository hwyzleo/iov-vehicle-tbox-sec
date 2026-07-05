#include "ipc_prov_service.h"
#include <iostream>

namespace tbox {
namespace sec {

IpcProvService::IpcProvService(const std::string& socket_path)
    : client_(socket_path) {}

ErrorCode IpcProvService::initialize() {
    if (!client_.connect()) {
        std::cerr << "[SEC] Failed to connect to PROV service" << std::endl;
        return ErrorCode::CONNECTION_FAILED;
    }
    std::cout << "[SEC] Connected to PROV service" << std::endl;
    return ErrorCode::SUCCESS;
}

ErrorCode IpcProvService::get_vehicle_info(VehicleInfo& info) {
    auto binding = client_.read_binding();
    info.vin = binding.vin;
    info.ecu_uid = binding.ecu_uid;

    if (info.vin.empty() || info.ecu_uid.empty()) {
        std::cerr << "[SEC] Empty VIN or ECU UID from PROV service" << std::endl;
        return ErrorCode::INVALID_PARAMETER;
    }

    std::cout << "[SEC] Vehicle info from PROV: vin=" << info.vin
              << " ecu_uid=" << info.ecu_uid << std::endl;
    return ErrorCode::SUCCESS;
}

bool IpcProvService::is_connected() const {
    return client_.is_connected();
}

std::string IpcProvService::get_service_status() const {
    return "IPC PROV Service";
}

} // namespace sec
} // namespace tbox

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
        std::cerr << "[SEC] PROV service connected but VIN/ECU UID not configured yet"
                  << std::endl;
        return ErrorCode::SUCCESS;
    }

    std::cout << "[SEC] Vehicle info from PROV: vin=" << info.vin
              << " ecu_uid=" << info.ecu_uid << std::endl;
    return ErrorCode::SUCCESS;
}

ErrorCode IpcProvService::get_provision_state(DeviceProvisionState& state) {
    // PROV 为车辆绑定/个性化状态的权威来源。
    if (!client_.is_connected()) {
        state = DeviceProvisionState::UNKNOWN;
        return ErrorCode::CONNECTION_FAILED;
    }
    // ProvClient::get_provision_state() 在 IPC 失败时返回 NONE（不抛异常）。
    tbox::prov::ProvisionState ps = client_.get_provision_state();
    switch (ps) {
        case tbox::prov::ProvisionState::NONE:
            state = DeviceProvisionState::NONE;
            break;
        case tbox::prov::ProvisionState::VIN_WRITTEN:
            state = DeviceProvisionState::VIN_WRITTEN;
            break;
        case tbox::prov::ProvisionState::BOUND:
            state = DeviceProvisionState::BOUND;
            break;
        case tbox::prov::ProvisionState::FAILED:
            state = DeviceProvisionState::FAILED;
            break;
        default:
            state = DeviceProvisionState::UNKNOWN;
            break;
    }
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

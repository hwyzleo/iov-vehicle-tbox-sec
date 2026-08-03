#pragma once

#include "prov_service_interface.h"
// TBOX-SEC-DSN-CR-012: 只消费已安装的 TboxProvClient package 公共头
// （tbox/prov/client.h）；不得引用 PROV 源码/私有头（include/prov_client.h 仅内部兼容包装）。
#include "tbox/prov/client.h"

namespace tbox {
namespace sec {

class IpcProvService : public ProvServiceInterface {
public:
    IpcProvService(const std::string& socket_path = "/tmp/tbox-prov.sock");
    ~IpcProvService() override = default;

    ErrorCode initialize() override;
    ErrorCode get_vehicle_info(VehicleInfo& info) override;
    ErrorCode get_provision_state(DeviceProvisionState& state) override;
    bool is_connected() const override;
    std::string get_service_status() const override;

private:
    tbox::prov::ProvClient client_;
};

} // namespace sec
} // namespace tbox

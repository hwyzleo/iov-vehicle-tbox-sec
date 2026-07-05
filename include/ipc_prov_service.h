#pragma once

#include "prov_service_interface.h"
#include "prov_client.h"

namespace tbox {
namespace sec {

class IpcProvService : public ProvServiceInterface {
public:
    IpcProvService(const std::string& socket_path = "/tmp/tbox-prov.sock");
    ~IpcProvService() override = default;

    ErrorCode initialize() override;
    ErrorCode get_vehicle_info(VehicleInfo& info) override;
    bool is_connected() const override;
    std::string get_service_status() const override;

private:
    tbox::prov::ProvClient client_;
};

} // namespace sec
} // namespace tbox

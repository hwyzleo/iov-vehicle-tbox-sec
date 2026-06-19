#pragma once

#include <string>
#include <chrono>
#include <map>
#include <nlohmann/json.hpp>

namespace tbox {
namespace sec {

enum class ProvisionState {
    NONE,
    KEY_GENERATED,
    CSR_BUILT,
    CSR_SUBMITTED,
    CERT_INSTALLED,
    FAILED
};

std::string provision_state_to_string(ProvisionState state);
ProvisionState string_to_provision_state(const std::string& str);

struct ProvisionStatus {
    std::string vin;
    std::string ecu_uid;
    ProvisionState state;
    std::string last_error;
    int retry_count;
    std::chrono::system_clock::time_point last_updated;

    nlohmann::json to_json() const;
    static ProvisionStatus from_json(const nlohmann::json& j);
};

class ProvisionStateManager {
public:
    ProvisionStateManager(const std::string& state_file_path);

    bool load_state();
    bool save_state() const;

    ProvisionStatus get_status(const std::string& vin, const std::string& ecu_uid) const;
    bool update_status(const ProvisionStatus& status);
    bool reset_status(const std::string& vin, const std::string& ecu_uid);

private:
    std::string state_file_path_;
    std::map<std::string, ProvisionStatus> status_map_;

    std::string make_key(const std::string& vin, const std::string& ecu_uid) const;
};

} // namespace sec
} // namespace tbox

#include "provision_state.h"
#include <fstream>
#include <iomanip>
#include <sstream>

namespace tbox {
namespace sec {

std::string provision_state_to_string(ProvisionState state) {
    switch (state) {
        case ProvisionState::NONE: return "NONE";
        case ProvisionState::KEY_GENERATED: return "KEY_GENERATED";
        case ProvisionState::CSR_BUILT: return "CSR_BUILT";
        case ProvisionState::CSR_SUBMITTED: return "CSR_SUBMITTED";
        case ProvisionState::CERT_INSTALLED: return "CERT_INSTALLED";
        case ProvisionState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

ProvisionState string_to_provision_state(const std::string& str) {
    if (str == "NONE") return ProvisionState::NONE;
    if (str == "KEY_GENERATED") return ProvisionState::KEY_GENERATED;
    if (str == "CSR_BUILT") return ProvisionState::CSR_BUILT;
    if (str == "CSR_SUBMITTED") return ProvisionState::CSR_SUBMITTED;
    if (str == "CERT_INSTALLED") return ProvisionState::CERT_INSTALLED;
    if (str == "FAILED") return ProvisionState::FAILED;
    return ProvisionState::NONE;
}

nlohmann::json ProvisionStatus::to_json() const {
    nlohmann::json j;
    j["vin"] = vin;
    j["ecu_uid"] = ecu_uid;
    j["state"] = provision_state_to_string(state);
    j["last_error"] = last_error;
    j["retry_count"] = retry_count;

    auto time_t = std::chrono::system_clock::to_time_t(last_updated);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    j["last_updated"] = ss.str();

    return j;
}

ProvisionStatus ProvisionStatus::from_json(const nlohmann::json& j) {
    ProvisionStatus status;
    status.vin = j["vin"].get<std::string>();
    status.ecu_uid = j["ecu_uid"].get<std::string>();
    status.state = string_to_provision_state(j["state"].get<std::string>());
    status.last_error = j["last_error"].get<std::string>();
    status.retry_count = j["retry_count"].get<int>();

    std::string time_str = j["last_updated"].get<std::string>();
    std::tm tm = {};
    std::istringstream ss(time_str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    status.last_updated = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    return status;
}

ProvisionStateManager::ProvisionStateManager(const std::string& state_file_path)
    : state_file_path_(state_file_path) {}

bool ProvisionStateManager::load_state() {
    try {
        std::ifstream file(state_file_path_);
        if (!file.is_open()) {
            return false;
        }

        nlohmann::json j;
        file >> j;

        status_map_.clear();
        for (const auto& [key, value] : j.items()) {
            status_map_[key] = ProvisionStatus::from_json(value);
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ProvisionStateManager::save_state() const {
    try {
        nlohmann::json j;
        for (const auto& [key, status] : status_map_) {
            j[key] = status.to_json();
        }

        std::ofstream file(state_file_path_);
        if (!file.is_open()) {
            return false;
        }

        file << j.dump(4);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

ProvisionStatus ProvisionStateManager::get_status(const std::string& vin, const std::string& ecu_uid) const {
    std::string key = make_key(vin, ecu_uid);
    auto it = status_map_.find(key);
    if (it != status_map_.end()) {
        return it->second;
    }

    ProvisionStatus status;
    status.vin = vin;
    status.ecu_uid = ecu_uid;
    status.state = ProvisionState::NONE;
    status.retry_count = 0;
    status.last_updated = std::chrono::system_clock::now();
    return status;
}

bool ProvisionStateManager::update_status(const ProvisionStatus& status) {
    std::string key = make_key(status.vin, status.ecu_uid);
    status_map_[key] = status;
    return save_state();
}

bool ProvisionStateManager::reset_status(const std::string& vin, const std::string& ecu_uid) {
    std::string key = make_key(vin, ecu_uid);
    status_map_.erase(key);
    return save_state();
}

std::string ProvisionStateManager::make_key(const std::string& vin, const std::string& ecu_uid) const {
    return vin + ":" + ecu_uid;
}

} // namespace sec
} // namespace tbox

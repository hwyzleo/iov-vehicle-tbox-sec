#pragma once

#include <string>
#include <cstdint>

namespace tbox {
namespace sec {

/// SEC 个性化状态信息（通过 IPC 返回给调用方）
struct SecProvisionStatus {
    std::string vin;
    std::string ecu_uid;
    std::string state;
    std::string last_error;
    int retry_count = 0;
};

} // namespace sec
} // namespace tbox

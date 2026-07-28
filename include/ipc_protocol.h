#pragma once

#include <cstdint>

namespace tbox {
namespace sec {
namespace ipc {

/// SEC IPC 方法 ID（与 framework-ipc RequestHeader.method_id 一致）。
///
/// 传输层由 framework-ipc 负责，序列化/编解码在 SecIpcDispatcher 中完成。
/// 此枚举仅定义方法号，供 dispatcher、retry policy、client facade 共享。
enum class MethodId : uint32_t {
    INITIALIZE = 1,
    GENERATE_KEY_PAIR = 2,
    GET_CSR = 3,
    SUBMIT_CSR = 4,
    INJECT_CERTIFICATE = 5,
    APPLY_CERTIFICATE = 6,
    SET_CA_CERTIFICATE = 7,
    GET_SEED = 8,
    VERIFY_KEY = 9,
    GET_STATUS = 10,
    GET_DEVICE_INFO = 11,
    RESET_STATUS = 12,
    EXPORT_PRIVATE_KEY = 13,
};

} // namespace ipc
} // namespace sec
} // namespace tbox

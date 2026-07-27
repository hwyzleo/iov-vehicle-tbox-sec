#pragma once

#include <cstdint>
#include "ipc_protocol.h"

namespace tbox {
namespace sec {

/// SEC 安全方法重试策略
///
/// framework-ipc Client 提供传输失败后的单次重连能力，
/// 但 SecRetryPolicy 按 method 分类决定是否允许自动重放：
///
/// - 只读/幂等：允许一次重试
/// - 业务幂等（同 key_id 已有有效密钥）：确认服务端幂等后允许一次
/// - 一次性/消费型（getSeed/verifyKey）：禁止自动重放
/// - 写入型（installCertificate 等）：默认禁止
class SecRetryPolicy {
public:
    /// 方法安全类别
    enum class Category : uint8_t {
        kReadOnly,          ///< 只读/幂等，允许一次重试
        kBusinessIdempotent,///< 业务幂等（如 generateKeyPair）
        kOneShot,           ///< 一次性/消费型（getSeed/verifyKey），禁止重放
        kWrite              ///< 写入型，默认禁止
    };

    /// 返回指定 method_id 的安全类别
    static Category categorize(uint32_t method_id);

    /// 传输失败后是否允许自动重试
    static bool should_retry(uint32_t method_id);
};

} // namespace sec
} // namespace tbox

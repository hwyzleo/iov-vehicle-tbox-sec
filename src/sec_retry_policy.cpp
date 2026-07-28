#include "sec_retry_policy.h"

namespace tbox {
namespace sec {

SecRetryPolicy::Category SecRetryPolicy::categorize(uint32_t method_id) {
    switch (static_cast<ipc::MethodId>(method_id)) {
        // 只读/幂等：允许一次重试
        case ipc::MethodId::GET_STATUS:
        case ipc::MethodId::GET_DEVICE_INFO:
        case ipc::MethodId::GET_CSR:
        case ipc::MethodId::EXPORT_PRIVATE_KEY:
        case ipc::MethodId::RESET_STATUS:
            return Category::kReadOnly;

        // 业务幂等：generateKeyPair（同 key_id 已有有效密钥时幂等）
        case ipc::MethodId::GENERATE_KEY_PAIR:
            return Category::kBusinessIdempotent;

        // 一次性/消费型：禁止自动重放
        case ipc::MethodId::GET_SEED:
        case ipc::MethodId::VERIFY_KEY:
            return Category::kOneShot;

        // 写入型：默认禁止
        case ipc::MethodId::INJECT_CERTIFICATE:
        case ipc::MethodId::APPLY_CERTIFICATE:
        case ipc::MethodId::SET_CA_CERTIFICATE:
        case ipc::MethodId::SUBMIT_CSR:
            return Category::kWrite;

        // INITIALIZE 归只读
        case ipc::MethodId::INITIALIZE:
            return Category::kReadOnly;

        // TLS 只读查询：允许一次重试
        case ipc::MethodId::GET_TLS_CREDENTIAL:
        case ipc::MethodId::GET_TLS_CREDENTIAL_STATE:
            return Category::kReadOnly;

        // TLS 签名：一次性/禁止自动重放（超时为 unknown outcome）
        case ipc::MethodId::SIGN_TLS:
            return Category::kOneShot;

        // TLS 订阅：独立连接，不归入 call/callOnce 重试
        case ipc::MethodId::SUBSCRIBE_TLS_CREDENTIAL_CHANGED:
            return Category::kOneShot;

        default:
            return Category::kOneShot;  // 未知方法保守处理
    }
}

bool SecRetryPolicy::should_retry(uint32_t method_id) {
    Category cat = categorize(method_id);
    return cat == Category::kReadOnly || cat == Category::kBusinessIdempotent;
}

} // namespace sec
} // namespace tbox

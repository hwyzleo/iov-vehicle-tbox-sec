#pragma once

//
// V2C 业务密钥非权威安全元数据 ledger（TBOX-SEC-DSN-CR-019 §6）。
//
// framework-store 仅保存非权威诊断/恢复副本：keyId 只存摘要，slotRef 不入库，
// 不得保存密钥、明文 slot handle 或未认证 ACTIVE 状态。每次查询与 provider 权威
// slot 相互校验；不一致返回 INVALID/UNKNOWN（fail-closed）。
//

#include "tbox/sec/business_key.h"
#include "error_codes.h"

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace hwyz {
namespace store {
class Store;
}
} // namespace hwyz

namespace tbox {
namespace sec {

struct BusinessKeyMetadata {
    bool present = false;
    std::string business_domain;
    std::string purpose;
    std::string key_id_digest;
    uint64_t business_key_version = 0;
    std::string algorithm;
    int64_t valid_from_ms = 0;
    int64_t valid_to_ms = 0;
    uint64_t active_generation = 0;
    std::string request_id_digest;
    int64_t created_at_ms = 0;
    int64_t committed_at_ms = 0;
};

class SecureMetadataLedger {
public:
    explicit SecureMetadataLedger(hwyz::store::Store store);
    ~SecureMetadataLedger();

    /// 从 store 加载已有 ledger。
    ErrorCode load();

    bool get(const std::string& domain, const std::string& purpose,
             BusinessKeyMetadata& out) const;

    ErrorCode put(const BusinessKeyMetadata& meta);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sec
} // namespace tbox

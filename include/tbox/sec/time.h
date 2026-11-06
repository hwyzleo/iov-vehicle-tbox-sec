#pragma once

//
// TBOX-SEC-DSN-CR-024：SEC 只读可信时间 SDK wire DTO。
//
// - 新增 additive 类型，不改旧二进制/枚举/错误码顺序；
// - Unknown/Untrusted 是**可查询业务状态**，经 envelope.valid / trust_state 表达，
//   与 transport 错误（error_class）独立；
// - 枚举语义以稳定字符串符号承载（trust_state/source/reason/source_kind/auth_status），
//   消费者（MQTT 等）按稳定符号映射自身枚举，不依赖数值序；
// - reason 使用版本化稳定符号，与既有错误层次分离。
//
// envelope 参考时刻语义（跨进程契约）：
//   - remaining_validity_ms 为 SEC 序列化时刻的剩余租约（SEC 已扣 TIME→SEC 一跳
//     RTT/缓存年龄；消费方再扣自身 SEC→本进程 RTT 与本地缓存年龄，只扣一次）。
//   - freshness_age_ms / utc_epoch_ms / uncertainty_ms 为 SEC 序列化时刻的有效值
//     （UTC 已按年龄推进、uncertainty 已含漂移增长）。
//

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace tbox {
namespace sec {

/// 只读可信时间查询结果 envelope（wire/SDK 公共 DTO）。
///
/// valid=true 表示结构完整可判定（trust_state 可为 trusted/untrusted/unknown 任一）；
/// valid=false 表示整体不可判定（缺失关键字段/契约不完整），error_class 说明原因。
struct TrustedTimeEnvelope {
    // ---- 契约/能力 ----
    uint32_t contract_version = 0;  ///< 0 = 契约未知/不可用
    std::string capabilities;       ///< 能力描述（未知必需能力整体拒绝）
    bool contract_complete = false; ///< 关键语义齐备（由 SEC 判定）

    // ---- SEC 实例/状态序列 ----
    uint64_t sec_daemon_epoch = 0;        ///< SEC 实例标识（重启改变）
    uint64_t sec_time_event_sequence = 0; ///< SEC 时间状态序列（状态事实变化才递增）

    // ---- TIME 来源实例/代次 ----
    uint64_t time_daemon_epoch = 0;    ///< TIME 服务实例标识
    uint64_t time_event_sequence = 0;  ///< TIME 状态序列
    std::string source_id;             ///< 非秘密来源标识
    std::string source_kind;           ///< 稳定符号：ntp_network/cellular/gnss/hardware_rtc/none
    uint64_t source_epoch = 0;         ///< 仅同来源/实例内解释，不跨来源比较
    std::string policy_version;        ///< 时间策略版本（认证绑定用）

    // ---- 信任判定 ----
    std::string trust_state;  ///< 稳定符号：trusted/untrusted/unknown
    std::string source;       ///< 稳定符号：platform_sync/hardware_rtc/fake_test/none
    std::string reason;       ///< 稳定 reason 符号（见 trusted_time.h TimeReason）

    // ---- UTC 事实（SEC 序列化时刻有效值）----
    bool utc_valid = false;
    int64_t utc_epoch_ms = 0;          ///< UTC epoch 毫秒（未知不写零）
    int64_t freshness_age_ms = 0;      ///< 有效年龄（单调计龄）
    bool uncertainty_valid = false;
    int64_t uncertainty_ms = 0;        ///< 保守误差上界（含漂移增长）

    // ---- 租约（参考时刻 = SEC 序列化时刻）----
    int64_t remaining_validity_ms = 0; ///< 剩余可信有效期；消费方再扣自身一跳
    int64_t drift_bound_ppm = 0;       ///< 可用漂移上界（0 = 未界定）

    // ---- 执行时钟对齐（与 trust_state 独立的事实）----
    bool system_clock_aligned = false;
    int64_t alignment_error_ms = 0;

    // ---- 认证证据（受控引用，非凭据正文）----
    std::string auth_status;   ///< 稳定符号：unknown/unverified/verified/failed
    std::string evidence_ref;  ///< 受控证据引用

    // ---- 完整性与错误分类 ----
    bool valid = false;        ///< 结构完整可判定
    /// 稳定错误分类（与 trust_state 分离）："" | "timeout" | "unavailable"
    /// | "unsupported" | "malformed" | "internal" | "acl_denied"
    std::string error_class;
};

// ============================================================================
// envelope ↔ JSON（wire 编解码；dispatcher 与 SDK 共享同一实现）
// ============================================================================

inline nlohmann::json trusted_time_envelope_to_json(const TrustedTimeEnvelope& e) {
    nlohmann::json j;
    j["contract_version"] = e.contract_version;
    j["capabilities"] = e.capabilities;
    j["contract_complete"] = e.contract_complete;
    j["sec_daemon_epoch"] = e.sec_daemon_epoch;
    j["sec_time_event_sequence"] = e.sec_time_event_sequence;
    j["time_daemon_epoch"] = e.time_daemon_epoch;
    j["time_event_sequence"] = e.time_event_sequence;
    j["source_id"] = e.source_id;
    j["source_kind"] = e.source_kind;
    j["source_epoch"] = e.source_epoch;
    j["policy_version"] = e.policy_version;
    j["trust_state"] = e.trust_state;
    j["source"] = e.source;
    j["reason"] = e.reason;
    j["utc_valid"] = e.utc_valid;
    j["utc_epoch_ms"] = e.utc_epoch_ms;
    j["freshness_age_ms"] = e.freshness_age_ms;
    j["uncertainty_valid"] = e.uncertainty_valid;
    j["uncertainty_ms"] = e.uncertainty_ms;
    j["remaining_validity_ms"] = e.remaining_validity_ms;
    j["drift_bound_ppm"] = e.drift_bound_ppm;
    j["system_clock_aligned"] = e.system_clock_aligned;
    j["alignment_error_ms"] = e.alignment_error_ms;
    j["auth_status"] = e.auth_status;
    j["evidence_ref"] = e.evidence_ref;
    j["valid"] = e.valid;
    j["error_class"] = e.error_class;
    return j;
}

inline bool trusted_time_envelope_from_json(const nlohmann::json& j,
                                            TrustedTimeEnvelope* out) {
    if (!j.is_object()) return false;
    // 缺关键字段视为畸形（AT-02：缺字段/未知不按支持处理，不默认 Trusted）
    if (!j.contains("trust_state") || !j.contains("sec_daemon_epoch") ||
        !j.contains("valid") || !j.contains("contract_version")) {
        return false;
    }
    try {
        TrustedTimeEnvelope e;
        e.contract_version = j.value("contract_version", 0u);
        e.capabilities = j.value("capabilities", "");
        e.contract_complete = j.value("contract_complete", false);
        e.sec_daemon_epoch = j.value("sec_daemon_epoch", 0ULL);
        e.sec_time_event_sequence = j.value("sec_time_event_sequence", 0ULL);
        e.time_daemon_epoch = j.value("time_daemon_epoch", 0ULL);
        e.time_event_sequence = j.value("time_event_sequence", 0ULL);
        e.source_id = j.value("source_id", "");
        e.source_kind = j.value("source_kind", "");
        e.source_epoch = j.value("source_epoch", 0ULL);
        e.policy_version = j.value("policy_version", "");
        e.trust_state = j.value("trust_state", "");
        e.source = j.value("source", "");
        e.reason = j.value("reason", "");
        e.utc_valid = j.value("utc_valid", false);
        e.utc_epoch_ms = j.value("utc_epoch_ms", 0LL);
        e.freshness_age_ms = j.value("freshness_age_ms", 0LL);
        e.uncertainty_valid = j.value("uncertainty_valid", false);
        e.uncertainty_ms = j.value("uncertainty_ms", 0LL);
        e.remaining_validity_ms = j.value("remaining_validity_ms", 0LL);
        e.drift_bound_ppm = j.value("drift_bound_ppm", 0LL);
        e.system_clock_aligned = j.value("system_clock_aligned", false);
        e.alignment_error_ms = j.value("alignment_error_ms", 0LL);
        e.auth_status = j.value("auth_status", "");
        e.evidence_ref = j.value("evidence_ref", "");
        e.valid = j.value("valid", false);
        e.error_class = j.value("error_class", "");
        *out = e;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace sec
} // namespace tbox

#pragma once

//
// TBOX-SEC-DSN-CR-017：可信时间生产契约。
//
// 目标：移除 production 的 SystemClockTrustedTimeProvider(trusted=true) 过渡语义，
// 建立 fail-closed 的证书注入时间门禁。生产唯一注入点为 CompositeTrustedTimeProvider
// （平台同步时间 → 硬件 RTC 顺序选择），任何 UNTRUSTED/UNKNOWN 一律不得 commit，
// 绝不回退墙钟、进程启动时间或文件时间（CR-016 §3.2 / CR-017 §2）。
//
// 依赖：平台时间服务 / 硬件 RTC 的真实查询后端为平台团队实施前阻塞项（CR-017 §9），
// 未落地前对应 Adapter 返回不可用 → 证书注入 fail-closed。
//

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace tbox {
namespace sec {

// ============================================================================
// 状态模型（CR-017 §3）
// ============================================================================

/// 信任状态。证书注入时间校验只接受 Trusted。
enum class TimeTrustState { Trusted, Untrusted, Unknown };

/// 时间来源。
enum class TimeSource { PlatformSync, HardwareRtc, FakeTest, None };

/// 稳定 reason（CR-017 §3/§7：日志脱敏字段，不记录授时认证材料/报文）。
enum class TimeReason {
    // 平台同步时间（§4.1）
    PlatformSynced,               ///< 合格
    PlatformNotSynchronized,      ///< sync_state != SYNCHRONIZED
    PlatformNotAuthenticated,     ///< 来源未认证/未纳入可信时间链
    PlatformTooOld,               ///< 超 freshness 门限
    PlatformUncertaintyTooHigh,   ///< uncertainty 超上限
    PlatformRollbackDetected,     ///< 回拨
    PlatformInterfaceUnavailable, ///< 平台接口不可用/未落地
    PlatformMalformed,            ///< 返回内容不完整/不可判定
    // 硬件 RTC（§4.2）
    RtcProvisioned,               ///< 合格
    RtcNotProvisioned,            ///< 未 provision/信任状态不可判定
    RtcNotHealthy,                ///< 电池/后备电源/振荡器/设备状态失效
    RtcOutOfRange,                ///< UTC 超平台允许范围
    RtcRollbackDetected,          ///< 回拨/默认纪元
    RtcReadError,                 ///< 读取失败/校验错误
    RtcInterfaceUnavailable,      ///< 后端未落地/不可用
    // 通用
    NoSourceAvailable,            ///< 无合格来源
    FakeTest,                     ///< dev/test 显式注入
};

/// 一次可信时间采样（CR-017 §3）。
struct TrustedTimeSample {
    std::chrono::system_clock::time_point utc_now{};
    TimeTrustState trust_state = TimeTrustState::Unknown;
    TimeSource source = TimeSource::None;
    /// 距最近一次同步的龄期。必须由单调时钟（steady_clock）计算，
    /// 不得以 system_clock 差值计算自身 freshness（CR-017 §3/§4.1）。
    std::chrono::milliseconds freshness_age{0};
    std::chrono::milliseconds uncertainty{0};  ///< 不确定度
    TimeReason reason = TimeReason::NoSourceAvailable;
    uint64_t source_epoch = 0;  ///< 可信同步/RTC 信任代次，用于检测来源重置与回拨；非安全秘密
};

/// 可信时间提供方。生产唯一注入点为 CompositeTrustedTimeProvider；
/// dev/test 可经显式 profile 注入 FakeTrustedTimeProvider。
class TrustedTimeProvider {
public:
    virtual ~TrustedTimeProvider() = default;
    /// 不得抛出：捕获来源接口错误并映射为 Untrusted/Unknown，禁止 fail-open。
    virtual TrustedTimeSample now() noexcept = 0;
};

/// 平台时间服务来源契约（CR-017 §4.1）。平台团队落地 getTrustedUtc() 等价接口后
/// 实现真实后端；缺失 synchronized/authenticated/last_sync_monotonic/uncertainty/epoch
/// 任一关键语义按不可信处理（PlatformMalformed/InterfaceUnavailable）。
class PlatformTimeSource {
public:
    virtual ~PlatformTimeSource() = default;
    virtual TrustedTimeSample query() noexcept = 0;
};

/// 硬件 RTC 来源契约（CR-017 §4.2）。RTC 不套用平台同步的 300s freshness，
/// 但信任状态必须可判定（provision/健康/回拨/范围）。
class HardwareRtcSource {
public:
    virtual ~HardwareRtcSource() = default;
    virtual TrustedTimeSample query() noexcept = 0;
};

/// 平台时间服务适配器（CR-017 §7 占位实现）。
/// 平台团队落地 getTrustedUtc() 等价接口（synchronized/authenticated/
/// last_sync_monotonic/uncertainty/source_epoch）后在此接入真实后端；
/// 当前返回 Untrusted(PlatformInterfaceUnavailable) → 生产注入 fail-closed
/// （CR-017 §9：缺任一关键语义按不可信处理，不视为可用）。
class PlatformTimeAdapter final : public PlatformTimeSource {
public:
    TrustedTimeSample query() noexcept override;
};

/// 硬件 RTC 适配器（CR-017 §7 占位实现）。
/// 真实后端（provision 标记/健康/回拨检查）落地后接入；
/// 当前返回 Untrusted(RtcInterfaceUnavailable) → 生产注入 fail-closed。
class HardwareRtcAdapter final : public HardwareRtcSource {
public:
    TrustedTimeSample query() noexcept override;
};

/// 可信时间配置（CR-017 §5，sec.trusted_time.*）。
struct TrustedTimeConfig {
    bool platform_enabled = true;
    std::chrono::milliseconds max_freshness{300000};     ///< 缺省 300s
    std::chrono::milliseconds max_uncertainty{2000};
    bool hw_rtc_enabled = true;
    bool hw_rtc_require_provisioned = true;
    std::chrono::milliseconds rollback_tolerance{2000};
};

/// 生产唯一可信时间提供方（CR-017 §2/§4.3）。
/// - 来源优先级：平台同步时间 → 硬件 RTC；两者均不合格返回 UNTRUSTED。
/// - freshness 基于单调时钟（来源侧计算 freshness_age），超门限拒绝。
/// - uncertainty 超上限拒绝；时间比较采用闭区间并计入 uncertainty（CR-017 §3）。
/// - 进程内 last-known-good 回拨保护：来源切换/来源 epoch 变化后
///   新 UTC 不得低于 LKG - rollback_tolerance；超容差立即 UNTRUSTED。
/// - 持久化 LKG 属安全存储工作，待平台接口落地后接入（CR-017 §7）。
/// 非线程安全假设不成立：内部以互斥量保护 LKG 状态。
class CompositeTrustedTimeProvider final : public TrustedTimeProvider {
public:
    CompositeTrustedTimeProvider(PlatformTimeSource* platform,
                                 HardwareRtcSource* hw_rtc,
                                 TrustedTimeConfig cfg = {});
    TrustedTimeSample now() noexcept override;

private:
    TrustedTimeSample gatePlatform(const TrustedTimeSample& s) const noexcept;
    TrustedTimeSample gateHardwareRtc(const TrustedTimeSample& s) const noexcept;
    void acceptAsKnownGood(const TrustedTimeSample& s) noexcept;

    PlatformTimeSource* platform_;
    HardwareRtcSource* hw_rtc_;
    TrustedTimeConfig cfg_;
    mutable std::mutex mu_;
    // 进程内 last-known-good（CR-017 §4.3）
    std::chrono::system_clock::time_point last_known_good_{};
    bool has_lkg_ = false;
    uint64_t last_epoch_ = 0;
    bool has_epoch_ = false;
};

/// dev/test 专用 fake（CR-017 §5/§8）：仅可由显式 dev/test profile 注入，
/// production 构造禁止；时间与属性由测试注入，不继承生产配置。
class FakeTrustedTimeProvider final : public TrustedTimeProvider {
public:
    explicit FakeTrustedTimeProvider(TrustedTimeSample sample);
    TrustedTimeSample now() noexcept override;
    void set_now(TrustedTimeSample sample) noexcept;

private:
    TrustedTimeSample sample_;
};

// ============================================================================
// PlatformTimeAdapter / HardwareRtcAdapter（CR-017 §4 契约占位）
// ============================================================================

// ============================================================================
// 稳定字符串化（日志脱敏字段）
// ============================================================================

const char* timeTrustStateToString(TimeTrustState s) noexcept;
const char* timeSourceToString(TimeSource s) noexcept;
const char* timeReasonToString(TimeReason r) noexcept;

} // namespace sec
} // namespace tbox

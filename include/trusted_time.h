#pragma once

//
// TBOX-SEC-DSN-CR-017 / TBOX-SEC-DSN-CR-024：可信时间生产契约。
//
// CR-017：移除 production 的 SystemClockTrustedTimeProvider(trusted=true) 过渡语义，
// 建立 fail-closed 的证书注入时间门禁。生产唯一注入点为 CompositeTrustedTimeProvider
// （平台同步时间 → 硬件 RTC 顺序选择），任何 UNTRUSTED/UNKNOWN 一律不得 commit，
// 绝不回退墙钟、进程启动时间或文件时间。
//
// CR-024：经 TIME 正式 client（tbox::time::TimeClient）读取/订阅真实事实，扩展
// 可信判定（SYNCHRONIZED+认证证据绑定+契约完整+门限+回拨）、只读可信时间
// IPC/SDK、变化事件与双跳短租约；保留 SEC-017/KL1 既有门禁。
//
// 关键语义（CR-024 §2/§3/§4）：
// - 单跳 RTT 由 TIME client 已测但**未扣减**；SEC 记录并一次性扣减，禁止重复扣，
//   也禁止漏扣；跨进程不比较 monotonic 绝对值，各跳以本地 elapsed 扣减。
// - 认证不能只看 auth_status：verified 必须绑定已批准策略版本 + 受控证据引用 +
//   （配置的）已批准来源；未认证 NTP 继续拒绝。
// - HOLDOVER 不满足平台 SYNCHRONIZED 条件；拒绝该平台分支后才考虑合格 RTC。
// - system_clock_aligned 与 trust_state 是不同事实；来源可信但墙钟不齐可报告
//   Trusted+aligned=false，消费者不得只检查 Trusted。
// - dev/test 的 `provider: fake` 也经同一只读快照源契约（FakeTrustedTimeSnapshotSource）
//   暴露到 IPC/SDK，否则 MQTT 时间门禁在 dev/test 车端只能拿到 NOT_IMPLEMENTED。
//   fake 依旧被 is_production + 显式 profile 双重约束，不新增生产放行口子。
//

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "tbox/sec/time.h"  // TrustedTimeEnvelope（wire/SDK DTO）
#include "tbox/time/types.h"       // tbox::time 类型（TIME 公开 SDK）
#include "tbox/time/time_snapshot.h"  // TimeSnapshot / TimeStateEvent

namespace tbox {
namespace sec {

// ============================================================================
// 状态模型（CR-017 §3 / CR-024 扩展）
// ============================================================================

/// 信任状态。证书注入时间校验只接受 Trusted。
enum class TimeTrustState { Trusted, Untrusted, Unknown };

/// 时间来源。
enum class TimeSource { PlatformSync, HardwareRtc, FakeTest, None };

/// TIME 同步状态（CR-024：对齐 tbox::time::TimeState 语义；SEC 侧独立枚举）。
enum class TimeSyncState : uint8_t { Unsynch, Syncing, Synced, Holdover, Fault };

/// TIME 来源种类（CR-024：对齐 tbox::time::SourceKind 语义）。
enum class TimeSourceKind : uint8_t { None, NtpNetwork, Cellular, Gnss, HardwareRtc };

/// 认证证据状态（CR-024：对齐 tbox::time::AuthStatus 语义）。
enum class TimeAuthStatus : uint8_t { Unknown, Unverified, Verified, Failed };

/// 稳定 reason（CR-017 §3/§7：日志脱敏字段，不记录授时认证材料/报文）。
enum class TimeReason {
    // 平台同步时间（§4.1 / CR-024 §3）
    PlatformSynced,               ///< 合格
    PlatformNotSynchronized,      ///< sync_state != SYNCHRONIZED（含 HOLDOVER/UNSYNCH/SYNCING/FAULT）
    PlatformNotAuthenticated,     ///< 来源未认证/认证失败（unverified/failed）
    PlatformAuthUnverifiable,     ///< 认证证据未知或无法绑定已批准策略/后端/证据（Unknown）
    PlatformContractIncomplete,   ///< 契约不完整/未知能力/关键字段缺失/数值越界（Unknown）
    PlatformTooOld,               ///< 超 freshness 门限
    PlatformUncertaintyTooHigh,   ///< uncertainty 超上限
    PlatformRollbackDetected,     ///< 回拨
    PlatformValidityExpired,      ///< 剩余有效期/租约 ≤ 0，不授权
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
    TimeExpired,                  ///< 监测到期撤销（缓存/租约超时，无人查询也撤销）
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

// ============================================================================
// CR-024：TIME 事实契约
// ============================================================================

/// SEC 侧对 TIME 只读 client 的最小依赖接口（CR-024 §2）。
/// 生产绑定 tbox::time::TimeClient（TIME 已发布 SDK）；单元测试注入 fake。
/// 不链接 TIME daemon/私有实现，不 add_subdirectory(TIME)。
class TimeSourceClient {
public:
    virtual ~TimeSourceClient() = default;
    virtual bool connect() = 0;
    virtual void disconnect() = 0;
    virtual bool is_connected() const = 0;
    struct QueryResult {
        enum class Error : uint8_t {
            kOk,
            kTimeUnavailable,   ///< 服务可达但时间不可用（快照仍返回）
            kServiceUnreachable,
            kTimeout,
            kUnsupported,
            kInvalidData,
            kInternalError,
        };
        Error error = Error::kInternalError;
        tbox::time::TimeSnapshot snapshot;
        int64_t rtt_ms = 0;  ///< TIME client 已测的请求-响应 RTT（**未扣减**）
    };
    virtual QueryResult get_time_snapshot() = 0;

    /// 订阅 TIME 状态变化（TIME client 保证先订阅缓冲再对账；乱序/重复/丢失处理
    /// 在 TIME client 内部）。返回 RAII 句柄，析构自动取消。
    virtual std::shared_ptr<void> subscribe_state_changed(
        std::function<void(const tbox::time::TimeStateEvent&)> cb) = 0;
};

/// 生产 TimeSourceClient：绑定 TIME 已发布 SDK（tbox::time::TimeClient）。
/// socket_path = TIME IPC socket（默认 /tmp/tbox-time.sock）。
std::shared_ptr<TimeSourceClient> makeTimeClientBridge(std::string socket_path);

/// TIME 平台事实快照（CR-024 §2 PlatformTimeAdapter 必需字段全量）。
/// 语义与 tbox::time::TimeSnapshot 对齐；缺少关键语义时由 SEC 判
/// Unknown(PlatformContractIncomplete)，不由 SEC 填默认可信值。
struct TimeFactSnapshot {
    // ---- 契约/能力 ----
    uint32_t contract_version = 0;   ///< 0 = 契约未知
    std::string capabilities;        ///< 能力描述（未知必需能力 → 拒绝）
    // ---- TIME 服务实例与状态序列 ----
    uint64_t time_daemon_epoch = 0;  ///< TIME 重启改变
    uint64_t time_event_sequence = 0;
    TimeSyncState state = TimeSyncState::Unsynch;
    // ---- 来源 ----
    std::string source_id;
    TimeSourceKind source_kind = TimeSourceKind::None;
    uint64_t source_epoch = 0;       ///< 仅同来源/实例内解释
    // ---- UTC ----
    bool utc_valid = false;
    int64_t utc_epoch_ms = 0;        ///< 同步依据 UTC（epoch 毫秒）；未知不写零
    // ---- 本机执行时钟对齐 ----
    bool system_clock_aligned = false;
    int64_t alignment_error_ms = 0;
    // ---- 年龄/误差（TIME server 回复生成时计算）----
    int64_t freshness_age_ms = 0;    ///< 回复生成时刻的有效年龄（单调计龄）
    bool uncertainty_valid = false;
    int64_t uncertainty_ms = 0;      ///< 同步依据误差上界（回复生成时未增长）
    // ---- 有效期/漂移 ----
    int64_t remaining_validity_ms = 0;  ///< 回复生成时刻剩余
    int64_t drift_bound_ppm = 0;        ///< 可用漂移上界；0 = 未界定（契约缺口）
    // ---- 认证证据（受控引用）----
    TimeAuthStatus auth_status = TimeAuthStatus::Unknown;
    std::string evidence_ref;           ///< 受控证据引用，非凭据正文
    std::string policy_version;
    // ---- 单跳传输事实（SEC 记账）----
    int64_t rtt_ms = 0;                 ///< TIME client 测得（未扣减）
    int64_t received_boot_ms = 0;       ///< SEC 收到时刻（本地 BOOTTIME），本跳扣减基准
    // ---- 完整性 ----
    bool transport_ok = false;          ///< 传输层可达（查询成功/时间不可用均算可达）
    bool validated = false;             ///< 结构校验通过
    bool contract_complete = false;     ///< 关键语义齐备（SEC 判定）
    std::string error_detail;           ///< 传输/解析诊断（脱敏，日志用）
};

/// 平台时间服务来源契约（CR-017 §4.1 / CR-024 §2）。
/// CR-024 起返回 TIME 平台事实全量；缺失 synchronized/authenticated/证据/契约
/// 任一关键语义按不可信处理（Unknown(PlatformContractIncomplete) 等）。
class PlatformTimeSource {
public:
    virtual ~PlatformTimeSource() = default;
    virtual TimeFactSnapshot query() noexcept = 0;
};

/// 硬件 RTC 来源契约（CR-017 §4.2）。RTC 不套用平台同步的 300s freshness，
/// 但信任状态必须可判定（provision/健康/回拨/范围）。
class HardwareRtcSource {
public:
    virtual ~HardwareRtcSource() = default;
    virtual TrustedTimeSample query() noexcept = 0;
};

// ============================================================================
// CR-024：可信时间判定结果（门禁后样本 + 扩展事实）
// ============================================================================

/// CompositeTrustedTimeProvider::query() 返回的完整判定结果（CR-024）。
/// sample 为门禁后样本（utc_now 已按年龄推进、uncertainty 已含漂移增长、
/// freshness_age 已含本跳 RTT/流逝）；其余字段供 wire envelope 使用。
struct TrustedTimeResult {
    TrustedTimeSample sample;
    // ---- 扩展事实（envelope 字段）----
    uint32_t contract_version = 0;
    std::string capabilities;
    bool contract_complete = false;
    uint64_t sec_daemon_epoch = 0;        ///< SEC 实例标识（monitor 维护）
    uint64_t sec_time_event_sequence = 0; ///< SEC 时间状态序列（monitor 维护）
    uint64_t time_daemon_epoch = 0;
    uint64_t time_event_sequence = 0;
    std::string source_id;
    TimeSourceKind source_kind = TimeSourceKind::None;
    std::string policy_version;
    bool system_clock_aligned = false;
    int64_t alignment_error_ms = 0;
    int64_t remaining_validity_ms = 0;    ///< 序列化时刻剩余租约（已扣 SEC 本跳）
    int64_t drift_bound_ppm = 0;
    TimeAuthStatus auth_status = TimeAuthStatus::Unknown;
    std::string evidence_ref;
    bool utc_valid = false;
    /// 稳定错误分类（wire 层，与业务状态分离）："" | "stale"（token 拒绝迟到响应）
    std::string error_class;

    /// 转为 wire/SDK envelope（稳定字符串符号）。
    TrustedTimeEnvelope to_envelope() const noexcept;
};

// ============================================================================
// CR-024：只读快照源（SEC IPC/SDK 方法 24/25 的唯一读入口）
// ============================================================================

/// 可信时间只读快照源（CR-024 §4/§5/§6）。
/// 生产实现 = TrustedTimeMonitor（TIME → adapter → composite → monitor）；
/// dev/test 实现 = FakeTrustedTimeSnapshotSource（显式 provider=fake 且非生产）。
/// 两种实现都必须维持短租约语义、变化事件语义与请求 token 拒绝迟到响应，
/// 不得因实现差异放宽 §3 的认证/门限判定（fake 仅在 dev/test profile 下存在）。
class TrustedTimeSnapshotSource {
public:
    virtual ~TrustedTimeSnapshotSource() = default;

    /// 启动快照源（生产：连接 TIME/订阅/监测线程；fake：标注运行并发布首帧）。
    /// 失败不抛；启动顺序不代表 ready。
    virtual bool start() noexcept = 0;

    /// 停机：撤销缓存、失效查询 token、取消订阅（有界等待）。
    virtual void stop() noexcept = 0;

    /// 查询当前可信时间（SEC IPC/SDK 入口）。
    /// request_token = 调用方上次响应携带的 sec_daemon_epoch（0 = 首次/无）。
    /// token 与当前 SEC 实例不符 → 迟到响应拒绝（valid=false, error_class="stale"）。
    virtual TrustedTimeResult get(uint64_t request_token) noexcept = 0;

    /// 可信时间变化事件订阅（SEC IPC 事件；服务端按 client 订阅过滤推送）。
    /// 返回 RAII 句柄，析构自动取消。
    virtual std::shared_ptr<void> subscribe(
        std::function<void(const TrustedTimeResult&)> cb) = 0;
};

/// 可信时间配置（CR-017 §5 / CR-024 §8，sec.trusted_time.*）。
struct TrustedTimeConfig {
    bool platform_enabled = true;
    std::chrono::milliseconds max_freshness{300000};     ///< 缺省 300s
    std::chrono::milliseconds max_uncertainty{2000};
    bool hw_rtc_enabled = true;
    bool hw_rtc_require_provisioned = true;
    std::chrono::milliseconds rollback_tolerance{2000};
    // ---- CR-024 ----
    std::string time_socket_path = "/tmp/tbox-time.sock";
    std::chrono::milliseconds time_query_timeout{500};       ///< TIME 查询超时
    std::chrono::milliseconds monitor_refresh_interval{500}; ///< 正常监测/提前刷新间隔
    std::chrono::milliseconds lease_max{1000};               ///< SEC 授权租约上限
    std::chrono::milliseconds cache_max_age{1000};           ///< 缓存上限
    std::vector<std::string> approved_policy_versions = {"1"}; ///< 已批准策略版本
    std::vector<std::string> approved_sources;               ///< 已批准来源（空 = 无已批准认证来源）
    bool require_evidence = true;  ///< verified 必须携带受控证据引用
    bool monitor_enabled = true;   ///< 自主监测开关（生产必须 true）
    /// 单调钟注入（BOOTTIME 语义；测试用）。空 = 真实时钟。
    std::function<int64_t()> boot_clock;
};

/// 生产唯一可信时间提供方（CR-017 §2/§4.3 / CR-024 §3）。
/// - 来源优先级：平台同步时间 → 硬件 RTC；两者均不合格返回 UNTRUSTED。
/// - 平台 Trusted 同时满足：TIME SYNCHRONIZED + UTC/误差可用 + 认证证据绑定
///   （verified + 已批准策略 + 证据引用 + 已批准来源）+ freshness≤300s +
///   uncertainty≤2s + 回拨检查 + 契约完整；缺任一关键语义为 Unknown。
/// - 租约 ≤ min(lease_max, TIME 剩余有效期-已耗, freshness/uncertainty 剩余预算)；
///   ≤0 不授权。
/// - 进程内 last-known-good 回拨保护；持久化 LKG 属安全存储工作。
/// 内部以互斥量保护 LKG 状态。
class CompositeTrustedTimeProvider final : public TrustedTimeProvider {
public:
    CompositeTrustedTimeProvider(PlatformTimeSource* platform,
                                 HardwareRtcSource* hw_rtc,
                                 TrustedTimeConfig cfg = {});
    /// 兼容入口（证书注入等）：返回 query().sample。
    TrustedTimeSample now() noexcept override;
    /// CR-024 完整判定结果（门禁 + 扩展事实 + 剩余租约）。
    TrustedTimeResult query() noexcept;

private:
    TrustedTimeResult gatePlatform(const TimeFactSnapshot& f) noexcept;
    TrustedTimeResult gateHardwareRtc(const TrustedTimeSample& s) noexcept;
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

/// 平台时间服务适配器（CR-017 §7 占位 → CR-024 真实 TIME client 接入）。
/// 经 TimeSourceClient（生产 = tbox::time::TimeClient bridge）查询/订阅真实事实，
/// 记录单跳 RTT 与收到时刻（received_boot_ms），连接代次用于迟到回调拒绝。
/// 缺少关键语义 → validated/contract_complete=false，由 Composite 判 Unknown。
class PlatformTimeAdapter final : public PlatformTimeSource {
public:
    explicit PlatformTimeAdapter(std::shared_ptr<TimeSourceClient> client,
                                 std::function<int64_t()> boot_clock = nullptr);
    TimeFactSnapshot query() noexcept override;

    /// 连接 TIME（有界超时；失败不抛）。返回是否已连接。
    bool connect() noexcept;
    void disconnect() noexcept;
    bool is_connected() const noexcept;

    /// 订阅 TIME 状态变化（内部转发 TimeStateEvent → on_change()）。
    /// 返回 RAII 句柄；析构自动取消。
    std::shared_ptr<void> subscribe(std::function<void()> on_change);

    /// 连接代次：重启/断连重连递增；用于旧回调/旧缓存拒绝。
    uint64_t connection_generation() const noexcept;

private:
    TimeFactSnapshot mapSnapshot(const tbox::time::TimeSnapshot& snap,
                                 int64_t rtt_ms) noexcept;

    std::shared_ptr<TimeSourceClient> client_;
    mutable std::mutex mu_;
    std::function<int64_t()> boot_clock_;  ///< 单调钟注入（测试用）；空 = 真实时钟
    uint64_t connection_generation_ = 0;
    int64_t last_query_boot_ms_ = 0;
    bool ever_connected_ = false;
};

/// 硬件 RTC 适配器（CR-017 §7 占位实现）。
/// 真实后端（provision 标记/健康/回拨检查）落地后接入；
/// 当前返回 Untrusted(RtcInterfaceUnavailable) → 生产注入 fail-closed。
class HardwareRtcAdapter final : public HardwareRtcSource {
public:
    TrustedTimeSample query() noexcept override;
};

// ============================================================================
// CR-024：可信时间监测器（自主监测 / 事件 / 短租约 / 生命周期）
// ============================================================================

/// 可信时间监测器（CR-024 §5/§6）：
/// - 无人查询也运行：TIME 事件 + 周期刷新（monitor_refresh_interval）+ 到期检查；
/// - 原子状态提交 → 递增 SEC 时间事件序列 → 发布变化事件（信任/来源/代次/对齐/
///   关键 reason 变化才发；高频数值不逐次广播）；
/// - 缓存键含 SEC daemon_epoch / TIME daemon_epoch / source_id/source_epoch /
///   TIME 状态版本 / adapter 连接代次；请求 token 拒绝迟到响应；
/// - 租约到期/失信先撤销旧有效状态再退避恢复；停机拒绝新授权、撤销缓存、
///   取消轮询/订阅、失效查询 token、关闭 client（有界等待）。
class TrustedTimeMonitor : public TrustedTimeSnapshotSource {
public:
    TrustedTimeMonitor(PlatformTimeAdapter* platform, HardwareRtcSource* hw_rtc,
                       TrustedTimeConfig cfg);
    ~TrustedTimeMonitor() override;

    TrustedTimeMonitor(const TrustedTimeMonitor&) = delete;
    TrustedTimeMonitor& operator=(const TrustedTimeMonitor&) = delete;

    /// 开始监测：连接 TIME、订阅变化、启动监测线程。失败不抛（可重试）。
    bool start() noexcept override;
    /// 停止监测：撤销缓存、取消订阅/计时、失效 token、关闭 client（有界等待）。
    void stop() noexcept override;

    /// 查询当前可信时间（SEC IPC/SDK 入口）。
    /// request_token = 调用方上次响应携带的 sec_daemon_epoch（0 = 首次/无）。
    /// token 与当前 SEC 实例不符 → 迟到响应拒绝（valid=false, error_class="stale"）。
    TrustedTimeResult get(uint64_t request_token) noexcept override;

    /// 可信时间变化事件订阅（SEC IPC 事件；服务端按 client 订阅过滤推送）。
    /// 返回 RAII 句柄，析构自动取消。
    std::shared_ptr<void> subscribe(
        std::function<void(const TrustedTimeResult&)> cb) override;

    /// 供 SecService 使用的提供方（同一 composite；证书注入/KL1 复用）。
    std::shared_ptr<TrustedTimeProvider> provider() const noexcept;

    /// SEC 实例标识（重启改变；作为查询 token 基准）。
    uint64_t sec_daemon_epoch() const noexcept;

    /// 触发一次立即刷新（供外部事件/测试）。
    void refresh_now() noexcept;

private:
    void refreshLocked() noexcept;
    void runLoop() noexcept;
    void publishIfChangedLocked(const TrustedTimeResult& r) noexcept;
    void revokeLocked(TimeReason reason) noexcept;
    int64_t nowBootMs() const noexcept;

    PlatformTimeAdapter* platform_;
    HardwareRtcSource* hw_rtc_;
    TrustedTimeConfig cfg_;
    std::shared_ptr<CompositeTrustedTimeProvider> composite_;

    mutable std::mutex mu_;
    std::thread loop_thread_;
    bool running_ = false;
    bool refresh_pending_ = false;      ///< 事件驱动的合并刷新标志
    uint64_t sec_daemon_epoch_ = 0;
    uint64_t sec_time_event_sequence_ = 0;
    uint64_t connection_generation_ = 0;
    bool tokens_invalidated_ = false;   ///< stop() 后旧 token 拒绝，start() 时清标志
    int64_t last_refresh_boot_ms_ = 0;
    int64_t last_connect_attempt_ms_ = 0;  ///< 未连接时有界重试（2s 间隔）
    bool has_cached_ = false;
    TrustedTimeResult cached_;
    TrustedTimeResult last_published_;
    bool has_published_ = false;
    struct SubSlot;  ///< 订阅槽（cpp 内定义）；句柄析构即失效
    std::vector<std::weak_ptr<SubSlot>> subscribers_;
    std::shared_ptr<void> time_sub_;    ///< TIME 事件订阅句柄
};

/// dev/test 专用 fake（CR-017 §5/§8）：仅可由显式 dev/test profile 注入，
/// production 构造禁止；时间与属性由测试注入，不继承生产配置。
class FakeTrustedTimeProvider final : public TrustedTimeProvider {
public:
    /// @param track_wall_clock true = 每次 now() 取当前墙钟（dev/test 车端 profile，
    ///        避免把进程启动瞬间的墙钟固化成"可信时间"，坏初始时钟/NTP 调时后被作废）；
    ///        false = 固定注入样本（单元/集成夹具的确定性用）。
    explicit FakeTrustedTimeProvider(TrustedTimeSample sample,
                                     bool track_wall_clock = false);
    TrustedTimeSample now() noexcept override;
    void set_now(TrustedTimeSample sample) noexcept;

private:
    TrustedTimeSample sample_;
    bool track_wall_clock_ = false;
};

/// dev/test 只读快照源（CR-017 §5 dev profile + CR-024 §4/§6 wire 契约）。
/// 仅当 `sec.trusted_time.provider=fake` 且非生产环境由组合根构造：
/// - 样本来自 FakeTrustedTimeProvider，UTC/年龄在查询时刻现算；
/// - 不产生任何生产放行口子（production 构造禁止；无 accept_unverified/bypass）；
/// - 与 monitor 同构维护 daemon_epoch/事件序列/请求 token，使 MQTT 时间门禁在
///   dev/test 得到可正向验证的真实只读 IPC 契约（不再 NOT_IMPLEMENTED）。
class FakeTrustedTimeSnapshotSource final : public TrustedTimeSnapshotSource {
public:
    FakeTrustedTimeSnapshotSource(std::shared_ptr<TrustedTimeProvider> provider,
                                  TrustedTimeConfig cfg = {});

    bool start() noexcept override;
    void stop() noexcept override;
    TrustedTimeResult get(uint64_t request_token) noexcept override;
    std::shared_ptr<void> subscribe(
        std::function<void(const TrustedTimeResult&)> cb) override;

    /// SEC 实例标识（重启改变；作为查询 token 基准）。
    uint64_t sec_daemon_epoch() const noexcept;

private:
    TrustedTimeResult snapshotLocked() noexcept;
    void publishIfChangedLocked(const TrustedTimeResult& r) noexcept;

    std::shared_ptr<TrustedTimeProvider> provider_;
    TrustedTimeConfig cfg_;
    mutable std::mutex mu_;
    bool running_ = false;
    bool tokens_invalidated_ = true;  ///< start() 前/stop() 后旧 token 拒绝
    uint64_t sec_daemon_epoch_ = 0;
    uint64_t sec_time_event_sequence_ = 0;
    bool has_published_ = false;
    TrustedTimeResult last_published_;
    struct SubSlot;  ///< 订阅槽（cpp 内定义）；句柄析构即失效
    std::vector<std::weak_ptr<SubSlot>> subscribers_;
};

// ============================================================================
// 稳定字符串化（日志脱敏字段 / wire 稳定符号）
// ============================================================================

const char* timeTrustStateToString(TimeTrustState s) noexcept;
const char* timeSourceToString(TimeSource s) noexcept;
const char* timeReasonToString(TimeReason r) noexcept;
const char* timeSyncStateToString(TimeSyncState s) noexcept;
const char* timeSourceKindToString(TimeSourceKind k) noexcept;
const char* timeAuthStatusToString(TimeAuthStatus a) noexcept;

} // namespace sec
} // namespace tbox

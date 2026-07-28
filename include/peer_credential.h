#pragma once

#include <string>
#include <cstdint>

namespace tbox {
namespace sec {

/// 调用方身份（由 framework-ipc client_fd 解析得到）
struct PeerIdentity {
    bool valid = false;            ///< 是否成功解析
    int32_t pid = 0;               ///< Unix peer PID
    uint32_t uid = 0;              ///< Unix peer UID
    uint32_t gid = 0;              ///< Unix peer GID
    std::string service_name;      ///< 解析到的 systemd unit（如 tbox-mqtt.service），空表示未知
};

/// Peer credential 解析接口
///
/// framework-ipc 不直接暴露 peer credential，SEC 在 RequestHandler 收到 client_fd 后
/// 自行解析 Unix peer PID/UID/GID 并映射 systemd 服务身份。该接口可注入测试替身。
class PeerCredentialResolver {
public:
    virtual ~PeerCredentialResolver() = default;
    /// 从 client_fd 解析调用方身份
    virtual PeerIdentity resolve(int client_fd) = 0;
};

/// 默认实现：Linux 使用 SO_PEERCRED 解析 PID/UID/GID，
/// 读取 /proc/<pid>/cgroup 解析 systemd unit；非 Linux 或解析失败返回 invalid（fail-closed）。
class SystemdPeerCredentialResolver : public PeerCredentialResolver {
public:
    PeerIdentity resolve(int client_fd) override;
};

/// 开发/测试用解析器（仅限非生产环境）。
///
/// 固定返回 valid=true 且 service_name 为配置的服务名，用于在缺少 SO_PEERCRED
/// 的平台（如 macOS）本地联调时绕过 systemd 身份校验。
/// 严禁在生产环境启用（会使 TLS 凭据 ACL 形同虚设）。
class DevPeerCredentialResolver : public PeerCredentialResolver {
public:
    explicit DevPeerCredentialResolver(std::string service_name)
        : service_name_(std::move(service_name)) {}
    PeerIdentity resolve(int client_fd) override;

private:
    std::string service_name_;
};

} // namespace sec
} // namespace tbox

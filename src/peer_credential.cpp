#include "peer_credential.h"
#include "sec_log_adapter.h"

#include <cstring>

#ifdef __linux__
#include <sys/socket.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <regex>
#endif

namespace tbox {
namespace sec {

PeerIdentity SystemdPeerCredentialResolver::resolve(int client_fd) {
    PeerIdentity identity;
#ifdef __linux__
    struct ucred uc;
    socklen_t len = sizeof(uc);
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) {
        return identity;  // valid=false, fail-closed
    }
    identity.valid = true;
    identity.pid = uc.pid;
    identity.uid = uc.uid;
    identity.gid = uc.gid;

    // 读取 /proc/<pid>/cgroup 解析 systemd unit，例如：
    //   0::/system.slice/tbox-mqtt.service
    std::string path = "/proc/" + std::to_string(uc.pid) + "/cgroup";
    std::ifstream f(path);
    if (f.is_open()) {
        std::string line;
        // 匹配 <unit>.service 形式的服务名
        std::regex re("([a-zA-Z0-9_@:-]+\\.service)");
        while (std::getline(f, line)) {
            std::smatch m;
            if (std::regex_search(line, m, re)) {
                identity.service_name = m[1].str();
                break;
            }
        }
    }
#else
    // 非 Linux 平台：无法解析 SO_PEERCRED，返回 invalid（fail-closed）。
    // 测试应注入 MockPeerCredentialResolver。
    (void)client_fd;
#endif
    return identity;
}

PeerIdentity DevPeerCredentialResolver::resolve(int client_fd) {
    // 开发/测试专用：不校验真实对端身份，固定放行为配置的服务名。
    (void)client_fd;
    PeerIdentity identity;
    identity.valid = true;
    identity.service_name = service_name_;
    return identity;
}

} // namespace sec
} // namespace tbox

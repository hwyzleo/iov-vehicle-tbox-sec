#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "ipc_protocol.h"

namespace tbox {
namespace sec {

class SecService;

namespace ipc {

class IpcServer {
public:
    using RequestHandler = std::function<std::string(const std::string&)>;

    IpcServer(const std::string& socket_path = DEFAULT_SOCKET_PATH);
    ~IpcServer();

    bool start(SecService* service);
    void stop();

    bool is_running() const { return running_; }

private:
    std::string socket_path_;
    int server_fd_;
    int shutdown_pipe_[2];
    std::atomic<bool> running_;
    std::thread accept_thread_;
    SecService* service_;

    void accept_connections();
    void handle_client(int client_fd);
    std::string handle_request(const std::string& request_data);
};

} // namespace ipc
} // namespace sec
} // namespace tbox

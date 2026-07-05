#include "ipc_server.h"
#include "sec_service.h"
#include "ipc_protocol.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <nlohmann/json.hpp>

namespace tbox {
namespace sec {
namespace ipc {

IpcServer::IpcServer(const std::string& socket_path)
    : socket_path_(socket_path), server_fd_(-1), running_(false), service_(nullptr) {
    shutdown_pipe_[0] = -1;
    shutdown_pipe_[1] = -1;
}

IpcServer::~IpcServer() {
    stop();
}

bool IpcServer::start(SecService* service) {
    if (running_) {
        return true;
    }

    service_ = service;

    if (pipe(shutdown_pipe_) < 0) {
        std::cerr << "Failed to create shutdown pipe: " << strerror(errno) << std::endl;
        return false;
    }

    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }

    int opt = 1;
    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    unlink(socket_path_.c_str());

    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    if (listen(server_fd_, 5) < 0) {
        std::cerr << "Failed to listen on socket: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&IpcServer::accept_connections, this);

    std::cout << "IPC server started on " << socket_path_ << std::endl;
    return true;
}

void IpcServer::stop() {
    if (!running_) {
        return;
    }

    std::cout << "IpcServer::stop() called" << std::endl;
    running_ = false;

    if (shutdown_pipe_[1] >= 0) {
        char c = 1;
        write(shutdown_pipe_[1], &c, 1);
    }

    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    if (server_fd_ >= 0) {
        close(server_fd_);
        server_fd_ = -1;
    }

    if (shutdown_pipe_[0] >= 0) { close(shutdown_pipe_[0]); shutdown_pipe_[0] = -1; }
    if (shutdown_pipe_[1] >= 0) { close(shutdown_pipe_[1]); shutdown_pipe_[1] = -1; }

    unlink(socket_path_.c_str());

    std::cout << "IPC server stopped" << std::endl;
}

void IpcServer::accept_connections() {
    std::cout << "[accept] thread started, server_fd=" << server_fd_ << std::endl;

    while (running_) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(server_fd_, &rfds);
        FD_SET(shutdown_pipe_[0], &rfds);
        int maxfd = (server_fd_ > shutdown_pipe_[0]) ? server_fd_ : shutdown_pipe_[0];

        int ret = select(maxfd + 1, &rfds, nullptr, nullptr, nullptr);
        if (ret < 0) {
            if (errno == EINTR) continue;
            std::cerr << "[accept] select failed: " << strerror(errno) << std::endl;
            break;
        }

        if (FD_ISSET(shutdown_pipe_[0], &rfds)) {
            std::cout << "[accept] shutdown pipe signaled, exiting" << std::endl;
            break;
        }

        if (!FD_ISSET(server_fd_, &rfds)) {
            continue;
        }

        int client_fd = accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_) {
                std::cerr << "[accept] accept failed: " << strerror(errno) << std::endl;
            }
            continue;
        }

        std::cout << "[accept] new connection, client_fd=" << client_fd << std::endl;

        std::thread client_thread(&IpcServer::handle_client, this, client_fd);
        client_thread.detach();
    }

    std::cout << "[accept] thread exiting" << std::endl;
}

void IpcServer::handle_client(int client_fd) {
    std::cout << "[client:" << client_fd << "] handler started" << std::endl;
    try {
        struct timeval tv;
        tv.tv_sec = 60;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        std::cout << "[client:" << client_fd << "] long connection established" << std::endl;

        while (true) {
            RequestHeader header;
            memset(&header, 0, sizeof(header));
            size_t header_received = 0;
            while (header_received < sizeof(header)) {
                ssize_t bytes_read = recv(client_fd, reinterpret_cast<uint8_t*>(&header) + header_received, sizeof(header) - header_received, 0);
                if (bytes_read <= 0) {
                    if (bytes_read == 0) {
                        std::cout << "[client:" << client_fd << "] connection closed by peer" << std::endl;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        std::cout << "[client:" << client_fd << "] idle timeout, closing" << std::endl;
                    } else {
                        std::cerr << "[client:" << client_fd << "] recv header failed: " << strerror(errno) << std::endl;
                    }
                    close(client_fd);
                    return;
                }
                header_received += bytes_read;
            }

            std::cout << "[client:" << client_fd << "] header received, method=" << header.method_id
                      << " params_length=" << header.params_length << std::endl;

            if (header.params_length > 10 * 1024 * 1024) {
                std::cerr << "[client:" << client_fd << "] request too large: " << header.params_length << std::endl;
                close(client_fd);
                return;
            }

            std::vector<uint8_t> request_data(sizeof(header) + header.params_length);
            memcpy(request_data.data(), &header, sizeof(header));

            size_t data_received = 0;
            while (data_received < header.params_length) {
                ssize_t bytes_read = recv(client_fd, request_data.data() + sizeof(header) + data_received, header.params_length - data_received, 0);
                if (bytes_read <= 0) {
                    std::cerr << "[client:" << client_fd << "] recv params failed" << std::endl;
                    close(client_fd);
                    return;
                }
                data_received += bytes_read;
            }

            std::cout << "[client:" << client_fd << "] request fully read, dispatching" << std::endl;

            std::string response = handle_request(std::string(request_data.begin(), request_data.end()));

            size_t total_sent = 0;
            while (total_sent < response.size()) {
                ssize_t bytes_sent = send(client_fd, response.data() + total_sent, response.size() - total_sent, 0);
                if (bytes_sent <= 0) {
                    std::cerr << "[client:" << client_fd << "] send response failed" << std::endl;
                    close(client_fd);
                    return;
                }
                total_sent += bytes_sent;
            }

            std::cout << "[client:" << client_fd << "] response sent, waiting for next request" << std::endl;
        }
    } catch (const std::length_error& e) {
        std::cerr << "[client:" << client_fd << "] std::length_error: " << e.what() << std::endl;
    } catch (const std::bad_alloc& e) {
        std::cerr << "[client:" << client_fd << "] std::bad_alloc: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[client:" << client_fd << "] std::exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[client:" << client_fd << "] unknown exception type" << std::endl;
    }

    close(client_fd);
}

std::string IpcServer::handle_request(const std::string& request_data) {
    MethodId method;
    std::string params_json;

    try {
        if (!IpcSerializer::deserialize_request(std::vector<uint8_t>(request_data.begin(), request_data.end()), method, params_json)) {
            auto resp = IpcSerializer::serialize_response(-1, "{\"error\":\"Invalid request\"}");
            return std::string(resp.begin(), resp.end());
        }
    } catch (const std::exception& e) {
        auto resp = IpcSerializer::serialize_response(-1, "{\"error\":\"Deserialize failed\"}");
        return std::string(resp.begin(), resp.end());
    }

    std::string result_json;
    int32_t status_code = 0;

    try {
        std::cout << "[dispatch] method=" << static_cast<int>(method) << " params_json=\"" << params_json << "\"" << std::endl;

        nlohmann::json params = nlohmann::json::parse(params_json.empty() ? "{}" : params_json);

        switch (method) {
            case MethodId::INITIALIZE: {
                auto result = service_->initialize();
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::GENERATE_KEY_PAIR: {
                auto result = service_->generate_key_pair();
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::GET_CSR: {
                std::vector<uint8_t> csr_der;
                auto result = service_->get_csr(csr_der);
                if (result == ErrorCode::SUCCESS) {
                    result_json = "{\"csr\":\"" + IpcSerializer::base64_encode(csr_der) + "\"}";
                } else {
                    result_json = "{\"success\":false}";
                }
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::SUBMIT_CSR: {
                auto result = service_->submit_csr();
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::INJECT_CERTIFICATE: {
                std::string cert_b64 = params.value("cert", "");
                std::vector<uint8_t> cert_der = IpcSerializer::base64_decode(cert_b64);
                auto result = service_->inject_certificate(cert_der);
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::APPLY_CERTIFICATE: {
                auto result = service_->apply_certificate();
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::SET_CA_CERTIFICATE: {
                std::string ca_cert_b64 = params.value("cert", "");
                std::vector<uint8_t> ca_cert_der = IpcSerializer::base64_decode(ca_cert_b64);
                auto result = service_->set_ca_certificate(ca_cert_der);
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::GET_SEED: {
                uint8_t level = static_cast<uint8_t>(params.value("level", 0));
                std::vector<uint8_t> seed;
                auto result = service_->get_seed(level, seed);
                if (result == ErrorCode::SUCCESS) {
                    result_json = "{\"seed\":\"" + IpcSerializer::base64_encode(seed) + "\"}";
                } else {
                    result_json = "{\"success\":false}";
                }
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::VERIFY_KEY: {
                uint8_t level = static_cast<uint8_t>(params.value("level", 0));
                std::string key_b64 = params.value("key", "");
                std::vector<uint8_t> key = IpcSerializer::base64_decode(key_b64);
                auto result = service_->verify_key(level, key);
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            case MethodId::GET_STATUS: {
                auto status = service_->get_provision_status();
                nlohmann::json j;
                j["vin"] = status.vin;
                j["ecu_uid"] = status.ecu_uid;
                j["state"] = provision_state_to_string(status.state);
                j["last_error"] = status.last_error;
                j["retry_count"] = status.retry_count;
                result_json = j.dump();
                status_code = 0;
                break;
            }
            case MethodId::GET_DEVICE_INFO: {
                std::string info = service_->get_device_info();
                nlohmann::json j;
                j["device_info"] = info;
                result_json = j.dump();
                status_code = 0;
                break;
            }
            case MethodId::RESET_STATUS: {
                auto result = service_->reset_provision_status();
                result_json = "{\"success\":" + std::string(result == ErrorCode::SUCCESS ? "true" : "false") + "}";
                status_code = static_cast<int32_t>(result);
                break;
            }
            default:
                result_json = "{\"error\":\"Unknown method\"}";
                status_code = -1;
                break;
        }
    } catch (const std::exception& e) {
        std::cerr << "[dispatch] caught std::exception: " << e.what() << std::endl;
        result_json = "{\"error\":\"" + std::string(e.what()) + "\"}";
        status_code = -1;
    } catch (...) {
        std::cerr << "[dispatch] caught unknown exception" << std::endl;
        result_json = "{\"error\":\"Unknown exception in dispatch\"}";
        status_code = -1;
    }

    if (result_json.empty()) {
        result_json = "{\"error\":\"Unknown error\"}";
        status_code = -1;
    }

    std::cout << "[dispatch] result_json=" << result_json << " status_code=" << status_code << std::endl;

    try {
        auto resp = IpcSerializer::serialize_response(status_code, result_json);
        return std::string(resp.begin(), resp.end());
    } catch (const std::exception& e) {
        std::cerr << "[dispatch] serialize_response exception: " << e.what() << std::endl;
        throw;
    }
}

} // namespace ipc
} // namespace sec
} // namespace tbox

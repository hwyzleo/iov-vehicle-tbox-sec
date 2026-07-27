#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include "tbox/sec/types.h"
#include "tbox/sec/errors.h"

namespace tbox {
namespace sec {

/// SEC 客户端 facade
///
/// 调用方（DIAG / RSMS / TSP 等）通过此接口与 SEC daemon 交互。
/// IPC 传输细节封装在库内部，对调用方不可见。
/// 内部使用 framework-ipc Client + SecRetryPolicy。
class SecClient {
public:
    SecClient(const std::string& socket_path = "/tmp/tbox-sec.sock");
    ~SecClient();

    // 连接到 SEC 服务
    bool connect();
    void disconnect();
    bool is_connected() const;

    // 初始化服务
    ErrorCode initialize();

    // 密钥操作
    ErrorCode generate_key_pair();
    ErrorCode export_private_key(std::vector<uint8_t>& private_key);

    // CSR 操作
    ErrorCode get_csr(std::vector<uint8_t>& csr_der);
    ErrorCode submit_csr();

    // 证书操作
    ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);
    ErrorCode apply_certificate();
    ErrorCode set_ca_certificate(const std::vector<uint8_t>& ca_cert_der);

    // 安全访问（Seed-Key）
    ErrorCode get_seed(uint8_t level, std::vector<uint8_t>& seed);
    ErrorCode verify_key(uint8_t level, const std::vector<uint8_t>& key);

    // 状态查询
    SecProvisionStatus get_provision_status();
    std::string get_device_info();

    // 重置状态
    ErrorCode reset_provision_status();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sec
} // namespace tbox

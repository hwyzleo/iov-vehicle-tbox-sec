# TBOX-SEC-DSN-CR-002 迁移指南

## 概述

本指南说明如何从旧的UdsHandler架构迁移到新的DIAG服务抽象架构。

## 变更原因

根据设计变更TBOX-SEC-DSN-CR-002，SEC模块需要：
1. 剥离诊断协议处理逻辑
2. 改为对接外部DIAG诊断服务
3. 实现SEC仅消费DIAG标准接口的架构目标

## 迁移步骤

### 1. 更新依赖注入

**旧代码：**
```cpp
auto sec_service = std::make_shared<SecService>(config);
auto uds_handler = std::make_unique<UdsHandler>(sec_service);
```

**新代码：**
```cpp
auto diag_service = std::make_shared<DiagServiceAdapter>();
auto sec_service = std::make_unique<SecService>(config, diag_service);
```

### 2. 移除UdsHandler依赖

不再需要：
- `#include "uds_handler.h"`
- UdsHandler类的使用
- UDS协议相关的处理逻辑

### 3. 使用新的DIAG服务接口

SEC服务现在通过DiagServiceInterface与外部诊断服务交互：

```cpp
// 初始化
sec_service->initialize();

// 生成密钥对（通过DIAG服务）
sec_service->generate_key_pair();

// 读取CSR（通过DIAG服务）
std::vector<uint8_t> csr;
sec_service->get_csr(csr);

// 注入证书（通过DIAG服务）
sec_service->inject_certificate(cert_der);
```

## 变更说明

- 旧的UdsHandler已完全移除
- 必须使用新的DIAG服务架构
- 所有诊断相关功能通过DiagServiceInterface实现

## 测试

运行测试验证迁移：
```bash
cd build && cmake .. && make TboxSecTests
./TboxSecTests --gtest_filter=SecService*Diag*
```

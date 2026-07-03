# TBOX Security Service API Documentation

## Overview

The TBOX Security Service provides APIs for managing device security identity initialization during production line. The service handles key pair generation, CSR creation, PKI certificate application, and certificate injection verification.

## Core APIs

### SecService

#### initialize()
Initialize the security service with configuration.

**Returns:** `ErrorCode::SUCCESS` on success

#### generate_key_pair()
Generate device key pair in secure element.

**Returns:** `ErrorCode::SUCCESS` on success, `ErrorCode::KEY_ALREADY_EXISTS` if key exists

#### get_csr()
Get Certificate Signing Request for the device.

**Parameters:**
- `csr_der`: Output vector containing DER-encoded CSR

**CSR Subject 格式 (TBOX-SEC-DSN-CR-005):**
```
CN=device_sn, OU=TBOX-TSP, O=OpenIOV, C=CN
```

**Returns:** `ErrorCode::SUCCESS` on success

#### submit_csr()
Submit CSR to PKI via cloud API.

**Returns:** `ErrorCode::SUCCESS` on success

#### inject_certificate()
Inject certificate into device after validation.

**Parameters:**
- `cert_der`: DER-encoded certificate

**Returns:** `ErrorCode::SUCCESS` on success, `ErrorCode::CERT_KEY_MISMATCH` if key doesn't match

## DIAG服务接口

### DiagServiceInterface

抽象接口，定义SEC服务需要消费的诊断服务标准能力。

#### 方法

- `initialize()` - 初始化DIAG服务连接
- `send_request()` - 异步发送请求
- `send_request_sync()` - 同步发送请求
- `is_connected()` - 检查连接状态
- `get_service_status()` - 获取服务状态

### 请求类型

- `GENERATE_KEY_PAIR` - 生成密钥对
- `READ_CSR` - 读取CSR
- `SUBMIT_CSR` - 提交CSR
- `INJECT_CERTIFICATE` - 注入证书
- `READ_PROVISION_STATE` - 读取Provision状态

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | SUCCESS | Operation successful |
| 1001 | KEY_GENERATION_FAILED | Failed to generate key pair |
| 1002 | KEY_ALREADY_EXISTS | Key already exists |
| 2001 | CSR_BUILD_FAILED | Failed to build CSR |
| 3001 | PKI_REJECTED | PKI rejected the request |
| 3002 | PKI_TIMEOUT | PKI request timeout |
| 4001 | CERT_VALIDATION_FAILED | Certificate validation failed |
| 4002 | CERT_KEY_MISMATCH | Certificate key doesn't match |
| 5001 | HSM_INIT_FAILED | HSM initialization failed |
| 6001 | STORAGE_WRITE_FAILED | Storage write failed |
| 7001 | UDS_SESSION_TIMEOUT | UDS session timeout |
| 7002 | UDS_SECURITY_DENIED | UDS security access denied |

## 配置项说明

### 公共配置（common.yaml）
- `cloud.endpoint`: 云端API端点
- `cloud.timeout_ms`: 请求超时时间（毫秒）
- `cloud.retry_count`: 重试次数
- `cloud.retry_delay_ms`: 重试延迟（毫秒）
- `environment.is_production`: 是否生产环境

### SEC服务配置（conf.d/sec.yaml）
- `hsm.type`: HSM类型（soft_file/hardware）
- `hsm.library_path`: HSM库路径
- `key_provisioning.mode`: 密钥配置模式（soft_file/hsm）
- `soft_key.path`: 软件密钥存储路径
- `soft_key.encryption_algo`: 加密算法
- `soft_key.encryption_key_path`: 加密密钥路径
- `storage.state_file`: 状态文件路径
- `storage.ca_cert`: CA证书路径
- `storage.cert_store`: 证书存储路径

## UDS Services

### Diagnostic Session Control (0x10)
Switch between diagnostic sessions.

### Security Access (0x29)
Perform security access for authenticated operations.

### Read Data By Identifier (0x22)
Read data from device.

**Supported DIDs:**
- `0xF100`: Provision state
- `0xF101`: CSR

### Write Data By Identifier (0x2E)
Write data to device.

**Supported DIDs:**
- `0xF102`: Certificate

### Routine Control (0x31)
Execute routines.

**Supported RIDs:**
- `0xFF00`: Generate key pair

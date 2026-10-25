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

**CSR Subject 格式 (TBOX-SEC-DSN-CR-005/007):**
```
CN=hsm_uid(ecu_uid), OU=TBOX-TSP, O=OpenIOV, C=CN   // 证书不含 VIN
```

**Returns:** `ErrorCode::SUCCESS` on success

#### submit_csr()
经 DIAG 诊断服务将 CSR 提交至产线 MES 中继通道（设计选型：MES → OAPI → PKI，TBOX 不直连云端）。
无 DIAG 服务时返回 `NOT_IMPLEMENTED`（旧 CloudClient 直连 HTTPS 签发路径已删除）。

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

## KL1 契约快照与租约准入（TBOX-SEC-DSN-CR-023；additive）

### IPC 方法号（已冻结；framework-ipc 传输层 method_id 为不透明 uint32，无全局登记）

| MethodId | 方法 | 说明 |
|---|---|---|
| 22 | `IMPORT_WRAPPED_BUSINESS_KEYS_KL1` | KL1 租约准入导入（携带 admission_expire_at_ms / capability_epoch / kl1_profile_version） |
| 23 | `GET_KEYPROV_CONTRACT_SNAPSHOT` | 只读 KL1 契约快照（result_contract_version / query_semantics_version / capability_epoch / storage_ready / supports_atomic_dual_commit / supports_lease_admission / kl1_profile_version / build_id） |

既有方法号（1..21）、旧符号与旧结构布局不变；未知方法返回传输失败，新 SDK 判为「不支持 KL1」，不得降级调用旧 import（方法 19）。

### SDK 新符号（旧函数不变）

- `get_keyprov_contract_snapshot(KeyprovContractSnapshot&)`：typed 原值透传，缺省 = UNAVAILABLE，不是支持；
- `import_wrapped_business_keys_kl1(request_id, domain, items, context, out, attach)`：SDK 侧 fail-closed（profile/epoch 缺失直接 NOT_READY）；
- `get_business_key_import_result_kl1(request_id, out, attach)`：结果附带同一快照 epoch/contract 与已存在 request 身份/证据摘要。

### KL1 错误码（1029/1030 不是强 NOT_FOUND）

| 码 | 符号 | 触发 | TSP 后续 |
|---|---|---|---|
| 1029 | `KL1_ADMISSION_REJECTED` | 新 operation、时间健康但 U≥E（含锁内重检） | 既定过期处置；新 E 受一次 freshen 与持久预算限制 |
| 1030 | `KL1_CAPABILITY_EPOCH_MISMATCH` | 调用方 epoch ≠ 当前 SEC epoch | 重新 probe，清零跨 epoch NF 稳定化计数，按原 rid 查询；不能凭 probe 成功自动重发 |

1022/1023/1025 复用既有语义（同 rid 不同 digest 冲突 / item·cert 有效期覆盖 E / 能力·时间·存储不健康）。

### 锁内处理顺序（事实优先级）

1. 匹配 COMMITTED → 恢复原结果/proof（旧 E 过期不否定事实，不重签）；
2. STAGED/PROCESSING/UNKNOWN 或可疑残留 → 原精确状态或既有 UNKNOWN/1024，交恢复/对账，不建第二 operation；
3. 确属新 operation → 存储/能力/可信时间不健康 1025 → epoch 不匹配 1030 → U≥E 1029 → 全部门禁满足才建 journal。

### 共享向量

`tests/fixtures/keyprov-kl1-v1/lifecycle-vectors.json` 为 PAR-PROTO-DSN-CR-010 原件本地副本
（SHA256 `5226b92733a93634d9bdd11ec7090b1ba655979e3beca0399784e9db7de855e3`），
责任映射见 `tests/fixtures/keyprov-kl1-v1/keyprov_kl1_manifest.json`
（direct/cross-end/sec-derived/other 四类；LC07/LC20/LC24 属其他端或 SEC 专属派生，不记为原用例 PASS）。

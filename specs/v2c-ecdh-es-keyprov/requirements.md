# V2C ECDH-ES v1 信封解封与双用途原子导入 - Requirements

> SSOT：Notion `TBOX-SEC-REQ-CR-020`
> （Page ID `8e30e349-c7c3-4b41-a1d5-01e9edba61f3`，变更类型「修改」，增量修订 `TBOX-SEC-REQ-CR-019` `e342897c387a485f97978e8bbb7969e2`）。
> 本文件为 Notion 需求的可追溯镜像，不替代 Notion 原文；冲突时以 Notion 为准。

## 1. Overview
让 TBOX-SEC 在 SEC/HSM/eSE 边界内解封 `ECDH-ES P-256 + HKDF-SHA-256 + AES-256-GCM` 的 V2C 业务密钥信封，并以单事务原子激活 UPLINK/DOWNLINK 两用途，返回绑定 `envelopeDigest`/`KCV` 的 ACK 与 import proof。

## 2. Background & Goals
- **背景**：CR-019 已落地 V2C Wrapped Key 的状态查询、双槽 staging/commit、安全 journal 与不可导出基线，但未冻结信封格式、实际解密算法、证书 ECDH 能力门禁与 canonical 校验。
- **目标**：
  - 冻结唯一信封格式 `KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1`；
  - 证书 `keyAgreement` + 私钥 derive 能力门禁（fail-closed）；
  - canonical AAD / envelopeDigest / KCV / proofInput 校验；
  - 双用途原子导入、幂等与断电恢复；
  - 能力探测与 readiness 合取。
- **非目标**：V2C payload 加解密、在线轮换/吊销、变更 MQTT/VMD/KMS 边界、变更设备证书注入流程。
- **发布约束**：PKI/step-ca 兼容证书未部署前，代码/测试/诊断可交付，但 V2C ECDH-ES capability 必须保持关闭；禁止关闭 KU 校验、导出私钥、明文下发业务密钥或在普通应用层执行 ECDH 作为兼容方案。

## 3. User Stories（US-ID 与 Notion 需求正文一致）

### US-015：信封格式与套件校验
**As a** TBOX-SEC, **I want** 只接受已协商的信封格式与套件, **so that** 未知/降级输入 fail-closed。
**Acceptance Criteria** (EARS):
- WHEN 收到导入批次 THE SYSTEM SHALL 校验 envelopeFormat=`ECDH_ES_P256_V1`、wrappingSuite=`ECDH_ES_P256_HKDF_SHA256_AES256GCM`、keyAlgorithm=`AES-256`、parameters 可解析、format/suite/算法/参数版本命中 allowlist。
- WHEN UPLINK_AEAD 与 DOWNLINK_AEAD item THE SYSTEM SHALL 各恰好接受一个。
- IF 版本未知、关键枚举未知、组合不匹配或字段缺失 THEN THE SYSTEM SHALL 整批拒绝且不执行任何密码操作（`BUSINESS_KEY_UNSUPPORTED`）。

### US-016：设备证书与 ECDH 能力门禁
**As a** TBOX-SEC, **I want** 在执行解封前确认证书与私钥能力, **so that** 签名身份不被误用为解封装身份。
**Acceptance Criteria**:
- WHILE 声明支持或执行解封 THE SYSTEM SHALL 同时确认：ACTIVE 证书为预期终端实体、公钥为允许的 P-256 EC、KeyUsage 含 `keyAgreement`、证书摘要与 `recipient_certificate_digest` 匹配、对应私钥存在于 SEC/HSM/eSE 且策略允许 ECDH derive、私钥不可导出。
- IF 证书仅含 `digitalSignature` THEN THE SYSTEM SHALL 判定能力未就绪/不支持且安全硬件调用 0 次（`BUSINESS_KEY_NOT_READY`）。
- THE SYSTEM SHALL NOT 用签名接口模拟 ECDH。

### US-017：受控边界内解封
**As a** TBOX-SEC, **I want** 在 SEC/HSM/eSE 内完成 ECDH/HKDF/AEAD, **so that** 中间秘密不离开安全边界。
**Acceptance Criteria**:
- WHEN 解封 THE SYSTEM SHALL 校验服务端临时 P-256 公钥为 65 字节非压缩点（首字节 0x04）、在曲线上且非无穷点。
- THE SYSTEM SHALL 用设备私钥执行 ECDH、以 32 字节 salt + canonical context 执行 HKDF-SHA-256 生成 32 字节 KEK、以 AES-256-GCM（12 字节 nonce、16 字节 tag、canonical AAD）解封并将明文直接导入 staging slot。
- IF shared secret/KEK/临时明文 THE SYSTEM SHALL 立即清零。
- THE SYSTEM SHALL NOT 让中间秘密出现在 IPC、日志、异常、崩溃转储或普通进程堆。

### US-018：Canonical AAD 与摘要校验
**As a** TBOX-SEC, **I want** 从外层上下文重建 AAD 并重算摘要, **so that** 上下文与信封一致性可被常量时间验证。
**Acceptance Criteria**:
- THE SYSTEM SHALL 校验 `aadDigest = SHA-256(canonicalAad)`。
- THE SYSTEM SHALL 按 PAR-PROTO canonical framing 重算 `envelopeDigest` 并常量时间比较。
- THE SYSTEM SHALL 将 `businessKeyVersion` canonical 值固定编码为 8 字节 unsigned big-endian，再添加 uint32 BE 长度前缀。
- THE SYSTEM SHALL 使用字符串 UTF-8、枚举规范 unsigned varint、bytes 原样进入 framing。
- IF requestId/businessDomain/purpose/keyId/版本/suite/证书摘要/operationId 与当前上下文不一致 THEN THE SYSTEM SHALL 拒绝（`WRAPPED_KEY_INVALID`）。
- THE SYSTEM SHALL NOT 使用 JSON、平台默认字符集、native struct 或 protobuf 普通 uint64 varint 替代 canonical 规则。

### US-019：KCV 与双用途原子导入
**As a** TBOX-SEC, **I want** 在 staging 校验 KCV 后单事务激活, **so that** 不出现单边激活。
**Acceptance Criteria**:
- THE SYSTEM SHALL 计算/验证 `KCV = first_3_bytes(SHA-256(businessKey))`。
- WHEN UPLINK_AEAD 与 DOWNLINK_AEAD 均完成认证解密、KCV 校验与策略校验 THEN THE SYSTEM SHALL 单事务提交为 ACTIVE。
- IF 任一 item 失败、超时或断电恢复不确定 THEN THE SYSTEM SHALL NOT 单边激活；旧版本保持可用；staging 按恢复规则回滚或续办（`BUSINESS_KEY_PARTIAL_ROLLBACK`）。

### US-020：ACK 与导入证明绑定
**As a** TBOX-SEC, **I want** ACK 原样回传并给出 proof, **so that** 云端可确认持钥。
**Acceptance Criteria**:
- WHEN 成功 ACK THE SYSTEM SHALL 回传每 item 的 purpose、keyId、businessKeyVersion、envelopeFormat、envelopeDigest、keyCheckValue、导入结果与受控 import proof。
- THE SYSTEM SHALL 以固定域分隔符、requestId、businessDomain、purpose、keyIdDigest、8 字节 uint64be businessKeyVersion、envelopeDigest、KCV 构成 proofInput，并在 SEC/HSM/eSE 内由已批准安全密钥生成证明。

### US-021：幂等、冲突与断电恢复
**As a** TBOX-SEC, **I want** 以 requestId + canonical request digest 建立安全 journal, **so that** 重放/冲突/断电可收敛。
**Acceptance Criteria**:
- WHEN 同 requestId 同 digest THEN THE SYSTEM SHALL 返回原结果，不重复解封或导入。
- WHEN 同 requestId 不同 digest THEN THE SYSTEM SHALL 返回冲突（`BUSINESS_KEY_CONFLICT`）。
- WHEN PROCESSING/OUTCOME_UNKNOWN THEN THE SYSTEM SHALL 先恢复或对账，不新建第二次安全操作。
- WHEN SUCCEEDED THEN THE SYSTEM SHALL 返回原 ACK/proof 结果。
- THE SYSTEM SHALL 让 journal 覆盖 wrappedKey、parameters、envelopeDigest、KCV、format、suite、证书摘要与业务版本。

### US-022：能力与 readiness
**As a** TBOX-SEC, **I want** READY 是能力合取, **so that** 任一能力缺失时只允许状态查询。
**Acceptance Criteria**:
- THE SYSTEM SHALL 要求：PAR-PROTO release/DescriptorSet-hash/format capability 已安装；HSM/eSE 支持 P-256 ECDH、HKDF-SHA-256、AES-256-GCM、staging/atomic commit；ACTIVE 证书含 `keyAgreement` 且私钥句柄支持 derive；trusted time、安全 journal/ledger 与 import proof key 可用；golden vectors 通过。
- IF 任一条件不满足 THEN THE SYSTEM SHALL 仅允许状态查询/诊断，不接受新信封（`BUSINESS_KEY_NOT_READY`）。

## 4. 错误语义
沿用 CR-019 错误码编号（见 design.md §错误映射；CR 正文 `SEC-1016..1021` 为逻辑名，映射到实现编号 `1021..1026`）。

## 5. 验收标准
= US-015…US-022 的合取，对应 DSN-CR-020 §13 测试矩阵 1..11。

## 6. Out of Scope / Open Items
- Java Provider ↔ C++ SEC 跨语言 golden 一致（DSN §13.1）：本仓先冻结 C++ golden vectors；Java 侧对账为发布门禁，未完成前 capability 保持关闭。
- PKI `keyAgreement` 兼容证书未部署，量产 capability 不开启。
- FW-SEC `EnvelopeAadV1` 精确字节布局：以 DSN-CR-020 §7.2 字段序 + canonical length-prefix 落地，待 FW-SEC test vector 交叉确认。

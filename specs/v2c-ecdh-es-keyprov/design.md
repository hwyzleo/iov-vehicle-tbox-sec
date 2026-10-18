# V2C ECDH-ES v1 信封解封与双用途原子导入 - Design

> SSOT：Notion `TBOX-SEC-DSN-CR-020`
> （Page ID `dddd2c87-5ed5-491f-9382-26d5d9a7421d`，变更类型「修改（增量修订 CR-019）」）。
> 依赖：`TBOX-SEC-DSN-CR-019`（`44ad3277b7ea4896800a6c1d3f86bff7`）、
> `FW-SEC-DSN-CR-014`（`5be1efc1ec184b4eac5898c90f8a994f`）、
> `PAR-PROTO-DSN-CR-007`（`b56a5a596bc248a3b9729dbf21ac6e91`）。
> 本文件为 Notion 设计的可追溯镜像；冲突时以 Notion 为准。

## 1. 结论
首期只实现 `KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1`。全部校验在解封前完成；ECDH、HKDF、AES-GCM 解封与业务密钥导入均在 SEC/HSM/eSE 边界内执行；UPLINK/DOWNLINK 两 staging slot 通过安全 journal 原子提交，ACK 绑定 envelopeDigest、KCV 与 import proof。

## 2. 目标架构（DSN §3）
`TBOX-TSP → BusinessKeyProvisioningService → EnvelopeValidator → DeviceKeyAgreementAdapter → SEC/HSM/eSE → Secure Journal/Ledger`。
业务进程只持有协议密文、摘要与安全句柄；不得获得 shared secret、KEK 或业务密钥明文。

## 3. 模型（DSN §4）
- `enum class KeyEnvelopeFormat : uint32_t { UNSPECIFIED=0, ECDH_ES_P256_V1=1 };`
- `EcdhEsP256EnvelopeParametersV1`（deterministic Protobuf）：formatVersion、serverEphemeralPublicKey(65B SEC1 uncompressed)、hkdfSalt(32B)、hkdfContextVersion("v1")、nonce(12B)、authenticationTag(16B)、canonicalAad、aadDigest(32B)、rootKeyVersion、derivationVersion、recipientCertificateDigest(32B)、operationId。
- `WrappedBusinessKeyItem`：purpose、keyId、businessKeyVersion、keyAlgorithm、wrappingSuite、envelopeFormat、wrappedKey(ciphertext only)、parameters(deterministic protobuf bytes)、envelopeDigest、keyCheckValue(3B)。
- `parameters` 原始 bytes MUST 保留用于 envelopeDigest 重算；禁止 parse 后重新序列化替换原字节。

## 4. 分层组件（DSN §5）
| 组件 | 责任 | 落地文件 |
| --- | --- | --- |
| BusinessKeyProvisioningService | 批次编排、幂等、双用途完整性、事务提交、ACK | `src/business_key_provisioning.cpp` |
| EnvelopeValidator | format/suite/算法、长度、版本、外层字段、AAD、digest、证书摘要校验 | `include/business_key_envelope.h` / `src/business_key_envelope.cpp` |
| DeviceKeyAgreementAdapter | 解析 ACTIVE 证书、公钥曲线/KU、定位私钥句柄、检查 derive 权限 | `include/device_key_agreement.h` / `src/device_key_agreement.cpp` |
| SecureKeyImporter | 调用 HSM/eSE 执行 ECDH、HKDF、AES-GCM、KCV、staging/commit/rollback | `src/soft_file_business_key_provider.cpp` + `HsmInterface` |
| CanonicalEncodingV1 | length-prefix、uint64be、envelopeDigest、proofInput 构造 | `include/canonical_encoding.h` / `src/canonical_encoding.cpp` |
| ProvisioningJournal | requestDigest、状态、槽位句柄、原 ACK/proof 与断电恢复 | `business_key_provider.h` journal（沿用 CR-019） |
| CapabilityReporter | 汇总协议、证书、密码能力、可信时间和存储 readiness | `include/business_key_capability.h` |

## 5. 校验流水线（DSN §6，解封前顺序）
1. 请求状态、requestId、businessDomain、两个 purpose 完整性；
2. envelopeFormat/wrappingSuite/keyAlgorithm/formatVersion allowlist；
3. 解析 deterministic Protobuf parameters 并执行长度上限；
4. 临时公钥恰好 65B、首字节 0x04、P-256 在曲线上且非无穷点；
5. 当前 ACTIVE 证书、P-256、公钥摘要、`keyAgreement`、私钥 derive capability；
6. 重建 canonical AAD，与承载值和 aadDigest 比较；
7. 以收到的原始 wrappedKey + parameters 重算 envelopeDigest，常量时间比较；
8. rootKeyVersion、derivationVersion、operationId、业务版本、有效期；
9. 生成 requestDigest，进入 journal 状态机；
10. 仅全部通过后调用安全硬件。
任何失败均不得留下 staging key 或推进 ACTIVE 版本。

## 6. Canonical 编码（DSN §7）
```
envelopeDigest = SHA-256(lengthPrefixed(envelopeFormat, requestId, businessDomain,
  purpose, keyId, uint64be(businessKeyVersion), wrappingSuite, wrappedKey, parameters))
```
每段：内容 bytes + unsigned uint32 big-endian 长度前缀。string=UTF-8；enum=规范 unsigned varint；bytes=原始内容；businessKeyVersion=固定 8 字节 unsigned BE（范围 1..2^63-1；127 与 128 内容段必须均为 8 字节）。
```
proofInput = lengthPrefixed(UTF8("openiov|keyprov-ack|v1"), UTF8(requestId),
  UTF8(businessDomain), enumValue(purpose), SHA-256(UTF8(keyId)),
  uint64be(businessKeyVersion), envelopeDigest, keyCheckValue)
```
AAD：TBOX-SEC 从外层上下文确定性构建 FW-SEC `EnvelopeAadV1`（envelopeVersion、wrappingSuite、requestId、businessDomain、purpose、keyId、businessKeyVersion、rootKeyVersion、derivationVersion、recipientCertificateFingerprint，同 canonical framing）；信封 `canonical_aad` 为比对材料。任一不一致即拒绝。
> Open item：FW-SEC `EnvelopeAadV1` 精确字节布局待 FW-SEC test vector 交叉确认（见 requirements.md §6）。

## 7. 安全硬件流程（DSN §8）
```
validate(serverEphemeralPublicKey)
keyHandle = resolvePrivateKey(activeCertificate)
assert keyHandle.canDerive(P-256 ECDH)
Z = HSM.ECDH(keyHandle, serverEphemeralPublicKey)
KEK = HSM.HKDF_SHA256(Z, hkdfSalt, canonicalInfo, 32)
stagingHandle = HSM.AES_GCM_DECRYPT_TO_SLOT(KEK, nonce, canonicalAad, ciphertext, authenticationTag)
actualKcv = HSM.KCV_SHA256_3(stagingHandle)
constantTimeAssert(actualKcv == expectedKcv)
zeroize(Z, KEK, transient buffers)
```
优先 decrypt-to-slot/import wrapped key；芯片不支持则 readiness DOWN；不得回退到普通应用内存解密。

## 8. 双用途事务与状态机（DSN §9）
```
NEW → VALIDATED → PROCESSING
  → UPLINK_STAGED → BOTH_STAGED → COMMITTING → SUCCEEDED
                                 ↘ ROLLING_BACK → FAILED
                    ↘ OUTCOME_UNKNOWN → RECOVERING → SUCCEEDED | FAILED
```
- 两 staging slot 同一 provisioning transaction 下创建；
- commit 前验证两 KCV、版本、目的、句柄策略；
- 支持原子 alias/version switch 则一次切换，否则带事务标记的双阶段提交 + 启动恢复；
- COMMITTING/OUTCOME_UNKNOWN 重启后查询 ledger/slot，不重新执行 ECDH 或生成第二组结果；
- 仅 SUCCEEDED 可生成/返回 IMPORTED ACK；
- 回滚后旧 ACTIVE 版本保持不变。

## 9. 幂等摘要与安全 journal（DSN §10）
`requestDigest` 覆盖：requestId + businessDomain + item[purpose,keyId,businessKeyVersion,keyAlgorithm] + wrappingSuite + envelopeFormat + wrappedKeyDigest + parametersDigest + envelopeDigest + KCV + recipientCertificateDigest + rootKeyVersion + derivationVersion + operationId。
journal 允许保存摘要、状态、安全槽位句柄、非敏感版本、原 ACK/proof 与必要密文；禁止保存业务密钥明文、KEK、ECDH shared secret 或设备私钥。
同 requestId 同 digest → 原 canonical ACK；不同 digest → `BUSINESS_KEY_CONFLICT`；PROCESSING/OUTCOME_UNKNOWN 只允许恢复与对账。

## 10. 能力与 readiness（DSN §11）
```c++
struct V2cKeyProvisioningCapability {
  bool protoReleaseMatched;
  bool envelopeFormatV1;
  bool p256Ecdh;
  bool hkdfSha256;
  bool aes256GcmDecryptToSlot;
  bool atomicDualSlotCommit;
  bool activeCertificateKeyAgreement;
  bool activePrivateKeyCanDerive;
  bool secureJournalReady;
  bool proofKeyReady;
  bool trustedTimeReady;
};
```
READY = 以上合取。PKI 未签发兼容证书时，代码/测试可发布，但 capability 不上报 v1、导入接口返回 `BUSINESS_KEY_NOT_READY`。证书更新后必须重新探测 KU、指纹和私钥权限。

## 11. 错误映射（DSN §12，映射到实现编号）
| 失败点 | 逻辑码 | 实现 ErrorCode | 处理 |
| --- | --- | --- | --- |
| format/suite/算法/硬件能力不支持 | SEC-1016 | `BUSINESS_KEY_UNSUPPORTED` (1021) | fail-closed，不执行密码操作 |
| requestId 摘要冲突 | SEC-1017 | `BUSINESS_KEY_CONFLICT` (1022) | 拒绝，不覆盖 journal |
| point/参数/AAD/digest/tag/KCV 非法 | SEC-1018 | `WRAPPED_KEY_INVALID` (1023) | 清理 staging，整批拒绝 |
| 安全调用结果未知 | SEC-1019 | `BUSINESS_KEY_OUTCOME_UNKNOWN` (1028) | 标记 OUTCOME_UNKNOWN，启动对账 |
| 证书 KU/私钥 derive/时间/存储未就绪 | SEC-1020 | `BUSINESS_KEY_NOT_READY` (1025) | readiness DOWN |
| 双槽提交失败且回滚 | SEC-1021 | `BUSINESS_KEY_PARTIAL_ROLLBACK` (1026) | 保留旧版本，返回回滚结果 |
> 说明：CR 正文逻辑码 `SEC-1016..1021` 与已发布的 TLS 材料码 `SEC-1015..1020` 冲突；实现沿用 CR-019 已落地编号 `1021..1026`（ABI/wire 稳定），仅新增 OUTCOME_UNKNOWN。GCM tag 失败、AAD/digest/KCV 不匹配均为确定性输入拒绝，不得自动用新 requestId 重试。

## 12. 取代与保留范围（DSN §15）
- 取代 CR-019 的模型、解封算法、proof context、幂等摘要、错误映射和 readiness；
- 保留 CR-019 的服务边界、状态查询、双用途 staging/commit、安全 journal 与不可导出原则；
- 现有项 → 建议项映射：
  | CR-019 现有项 | CR-020 修订项 |
  | --- | --- |
  | WrappedKeyItem 可扩展 JSON parameters | 固定 `ECDH_ES_P256_V1` + deterministic Protobuf 子消息 |
  | ECIES/HPKE/ECDH-ES 可选方向 | 首期固定 ECDH-ES P-256/HKDF-SHA-256/AES-256-GCM |
  | import proof 绑定请求与业务版本 | 增加 envelopeDigest、KCV 与 envelopeFormat 绑定 |
  | requestId 幂等（JSON digest） | 完整 canonical 请求摘要 + 断电恢复 + 冲突判定 |
  | SEC ready（provider.isReady） | 证书 KU + 私钥 ECDH 权限 + 协议 release/hash + 安全槽位门禁合取 |
  | AAD = 字符串拼接 | canonical `EnvelopeAadV1` 重建 + aadDigest |
  | HKDF salt="" info=AAD | salt=hkdfSalt(32B) info=canonicalInfo |
  | 无 KCV | KCV = first_3_bytes(SHA-256(businessKey)) |
  | proof context 字符串拼接版本/摘要 | canonical proofInput（uint64be + envelopeDigest + KCV） |

## 13. Protobuf 依赖与锁版（DSN §14 / PAR-PROTO-DSN-CR-007）
- 引入 protobuf runtime + protoc 构建流程；
- 受控同步 `proto/security/keyprov/v1/key_provisioning.proto`（package `security.keyprov.v1`）；
- 固定 PAR-PROTO release、source hash、DescriptorSet hash、生成器版本（记录于 proto 头 + 编译期常量）；
- 本仓生成 `.pb.h/.pb.cc` 并使用生成代码解析 `EcdhEsP256EnvelopeParametersV1`；
- 禁止手写字段 1～12 的 Protobuf wire codec；
- 锁版校验测试：从生成 DescriptorSet 计算 SHA-256 并与固定值比较，不一致即失败。

## 14. 发布顺序（DSN §14）
PAR-PROTO artifact/hash 锁定 → TBOX-SEC codec + validator + golden tests → HSM/eSE capability 验证 → journal/atomic commit/ACK proof → 与 FW-SEC 联调 → 安装 `keyAgreement` 兼容设备证书 → readiness 复核 → 灰度开启 envelope v1 capability。
证书未就绪不阻止前五步开发，但阻止 capability 开启和生产导入。

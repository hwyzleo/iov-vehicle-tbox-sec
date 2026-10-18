# V2C ECDH-ES v1 信封解封与双用途原子导入 - Tasks

> 阶段 C 开发计划。每条任务关联至少一个 US-ID 与 design.md 章节。
> SSOT：Notion `TBOX-SEC-DSN-CR-020` / `TBOX-SEC-REQ-CR-020`。
> 完成一项后更新勾选，再进入下一项。

## 约束
- 未确认本计划前不写业务代码。
- 不执行 `git add/commit/push`；不修改无关文件。
- `tests/fixtures/` 的确定性向量仅在人工批准后提交。
- 每完成一批任务运行 `cmake --build` + 相关 gtest，最后 `graphify update .`。

## 任务

- [x] **T1 公共模型扩展**（US-015/018/020，design §3/§4）
  - `include/tbox/sec/business_key.h`：新增 `KeyEnvelopeFormat`；`WrappedKeyItem` 增加 `wrapping_suite`、`envelope_format`、`envelope_digest`、`key_check_value[3]`、`root_key_version`、`derivation_version`、`operation_id`；`BusinessKeyStatus` 增加 ACK 字段 `envelope_format`/`envelope_digest`/`key_check_value`；`BusinessKeyImportState` 扩展状态机取值（§8）。
  - 保持 `SecureBuffer`/枚举序列化向后兼容（字符串序列化）。

- [x] **T2 CanonicalEncodingV1**（US-018/020，design §6）
  - 新增 `include/canonical_encoding.h` + `src/canonical_encoding.cpp`。
  - `lengthPrefixed`/`appendUint32be`/`appendUint64be`/`appendEnumVarint`；`computeEnvelopeDigest`；`computeKcv`；`buildProofInput`；`buildEnvelopeAadV1` + `computeAadDigest`；常量时间比较。
  - `businessKeyVersion` 恒 8 字节 BE；长度前缀 uint32 BE。

- [x] **T3 Protobuf 依赖与参数解析**（US-015，design §13）
  - `proto/security/keyprov/v1/key_provisioning.proto`（受控副本，头注释固定 PAR-PROTO release/source hash/descriptor hash/protoc 版本）。
  - CMake：`find_package(Protobuf REQUIRED)` + `protobuf_generate_cpp`；protoc 版本 guard；链接 `protobuf::libprotobuf`。
  - `include/business_key_envelope.h` + `src/business_key_envelope.cpp`：`parseEcdhEsP256Parameters`（生成代码）+ 长度上限 + 未知字段拒绝。
  - `test_keyprov_proto_lock.cpp`：DescriptorSet SHA-256 锁版校验。

- [x] **T4 EnvelopeValidator**（US-015/018，design §5/§6）
  - format/suite/算法/版本 allowlist；临时公钥 65B/0x04/P-256 曲线点/非无穷点；salt 32 / nonce 12 / tag 16 / aadDigest 32 / certDigest 32 / canonicalAad ≤1KiB / parameters ≤2KiB / wrappedKey ≤4KiB / KCV 3；AAD 重建比对；envelopeDigest 重算常量时间比对。

- [x] **T5 设备证书 ECDH 门禁**（US-016，design §5/§10）
  - `include/device_key_agreement.h` + `src/device_key_agreement.cpp`：`hasKeyUsageKeyAgreement`、SPKI/指纹摘要、私钥 derive 能力探测；`digitalSignature`-only → 未就绪且 0 次硬件调用。
  - 复用/扩展 `src/cert_validator.cpp` 的 KU 工具。

- [x] **T6 HSM 原语**（US-017，design §7）
  - `HsmInterface` 新增 ECDH + HKDF(salt,info) + AES-GCM(分离 tag) + KCV 原语；`SoftFileHsm` 实现并在 None/失败路径清零。
  - 变更 `unwrap_ecdh_es` 语义或新增 `wrap_unwrap_v1`（旧调用点同步更新）。

- [x] **T7 Provider 更新**（US-017/019/022，design §7/§10/§11）
  - `SoftFileBusinessKeyProvider`：canonical unwrap、KCV 计算/校验、capability 结构。
  - `HsmBusinessKeyProvider`：capability 全 false → fail-closed。

- [x] **T8 服务编排**（US-018/019/021/022，design §5/§8/§9/§11/§12）
  - §6 十步校验顺序；§8 状态机；§9 canonical `requestDigest`；§10 同 digest 返回原 ACK / 异 digest 冲突 / PROCESSING|OUTCOME_UNKNOWN 恢复；§11 capability 合取 readiness；§12 错误映射 + 新增 `BUSINESS_KEY_OUTCOME_UNKNOWN`。

- [x] **T9 IPC / SDK / 配置**（US-020，design §4/§13）
  - `sec_ipc_dispatcher.cpp`、`sec_client.cpp`、`tbox/sec/client.h` 传递 suite/format/digest/KCV。
  - `config/sec.default.yaml` + schema：suite 改为 `ECDH_ES_P256_HKDF_SHA256_AES256GCM`；新增 envelope format 相关键。

- [x] **T10 单元测试**（US-015..022，design §5..§11）
  - `test_business_key_canonical_encoding.cpp`：framing + `businessKeyVersion` 1/127/128/255/256/2^32/2^63-1 固定 8 字节 + proofInput/digest golden。
  - `test_business_key_envelope_validator.cpp`：点/长度/format/suite/版本/摘要错配拒绝。
  - 更新 `test_business_key_provisioning.cpp`：KCV、篡改 salt/nonce/AAD/ciphertext/tag/params/digest/KCV、KCU 门禁 0 次硬件调用、双槽原子性与断电恢复、重放不增槽。
  - 更新 `test_business_key_ipc_handlers.cpp`。

- [x] **T11 集成测试与向量**（US-017/020/021，design §6/§13）
  - `tests/fixtures/keyprov_ecdh_es_v1_vector.json`：固定非生产 P-256 夹具 + canonical 输入 + 期望 ECDH shared/KEK/明文/AAD digest/envelopeDigest/KCV/proofInput，由独立参考实现（Python/OpenSSL）生成或校验。
  - 更新 `test_business_key_integration.cpp`：全链路 import/status/result + ACK 字段 + 重放/冲突。

- [x] **T12 收尾**
  - 日志/异常/指标/core dump/IPC/debug formatter 敏感数据扫描（DSN §13.11）。
  - `graphify update .`；汇总实现与测试结果。

## 完成标准
- `cmake --build` 通过；`TboxSecTests` 全绿。
- DSN-CR-020 §13 测试矩阵除跨语言（#1 Java 侧）外全部覆盖；#1 明确标注为未满足的发布门禁。
- capability 在无兼容证书/无跨语言向量时为 DOWN。

## 状态（实现收尾）
- 构建：`cmake --build cmake-build-debug --target TboxSecTests` 通过（宿主系统 Protobuf/libprotoc 35.1 + 独立 Abseil 补齐链接）。
- 测试：`TboxSecTests` 339/339 全绿（从仓库根目录运行；`FrameworkIntegrationTest.ConfigLoading` 为既有 CWD 依赖用例，非本 CR 引入，与 `/tmp` 运行对比可复现）。
- 金标向量：`tests/fixtures/keyprov_ecdh_es_v1_vector.json` 由独立 Python/OpenSSL 参考实现生成，C++ `buildEcdhEsP256EnvelopeV1` 逐字段比对通过；`parameters` 为 deterministic protobuf（生成代码解析）。
- DescriptorSet 锁版：`tests/test_keyprov_proto_lock.cpp` 固定 SHA-256 `08c79dd490cea54f32b80f150d93db25f70f2504cb89fc75ac9d3e99addd46de`。

### 未满足的发布门禁 / 后续项（capability 保持 DOWN）
1. §13.1 跨语言（Java Provider）向量交叉验证未完成 → 不得在量产上报 v1、不得签发兼容证书。
2. FW-SEC `EnvelopeAadV1` 字节布局待与 FW-SEC CR-014 交叉复核（当前冻结 TBOX-SEC 解释）。
3. PAR-PROTO CR-006 枚举数值待回填官方原文（当前按已冻结数值锁定）。
4. PKI `keyAgreement` 证书未部署，组合根能力探测保持 fail-closed。
5. conan 打包：`conanfile.txt` 尚未加入 protobuf/abseil；当前依赖宿主系统 `find_package(Protobuf)`（已记录为跟进项）。
6. `test_sec_config_checker`/`config/dev/sec.yaml` 已同步新 suite/format 键。

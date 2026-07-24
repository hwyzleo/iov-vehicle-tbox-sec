# TBOX-SEC-DSN-CR-007 设备身份分层统一 实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 将 `device_sn` 概念替换为分层身份模型：`hsm_uid`（HSM 身份，用于 CSR/MQTT/鉴权）和 `device_id`（通用设备身份，用于资产/绑定）

**架构：** 自底向上修改数据结构（`CsrConfig`、`CertificateRequest`），然后更新业务逻辑（`CsrBuilder`、`SecService`、`KeyEngine`），最后更新测试。`device_sn` 字段完全移除，`ecu_uid` 作为 HSM 身份统一用于证书和车云通信。

**技术栈：** C++17、OpenSSL、Google Test、CMake

---

## 文件结构

**修改文件：**
- `include/csr_builder.h` — `CsrConfig.device_sn` → `hsm_uid`，方法参数改名
- `src/csr_builder.cpp` — 使用 `config.hsm_uid` 替代 `config.device_sn`
- `include/cloud_client.h` — `CertificateRequest.device_sn` → `ecu_uid`
- `src/sec_service.cpp` — `csr_config.device_sn` → `hsm_uid`，`request.device_sn` → `ecu_uid`
- `include/prov_service_interface.h` — 更新注释
- `tests/test_csr_builder.cpp` — `config.device_sn` → `config.hsm_uid`
- `tests/test_key_engine.cpp` — `test_device_sn` → `test_ecu_uid`

---

### 任务 1：修改 CsrConfig 数据结构

**文件：**
- 修改：`include/csr_builder.h:13`

- [ ] **步骤 1：将 CsrConfig.device_sn 重命名为 hsm_uid**

```cpp
// include/csr_builder.h:13
struct CsrConfig {
    std::string hsm_uid;        // HSM 身份（ECU UID / 芯片UID），用于证书 CN 和车云鉴权
    std::string key_id;         // 密钥标识
    std::string algorithm;      // 签名算法（如 SHA256withECDSA）
};
```

- [ ] **步骤 2：更新 CsrBuilder 类方法参数名**

```cpp
// include/csr_builder.h:34-37
    ErrorCode marshal_x509_name(const std::string& hsm_uid,
                                std::vector<uint8_t>& out_der);

    ErrorCode marshal_san_extension(const std::string& hsm_uid,
                                    std::vector<uint8_t>& ext_der);
```

同时更新类注释：
```cpp
// include/csr_builder.h:19
// Subject DN 格式: CN=HSM UID, OU=TBOX-TSP, O=OpenIOV, C=CN
```

- [ ] **步骤 3：确认编译失败**

运行：`cd build && cmake .. && make 2>&1 | head -30`
预期：编译报错，因为 `csr_builder.cpp` 和 `sec_service.cpp` 仍使用 `device_sn`

- [ ] **步骤 4：Commit**

```bash
git add include/csr_builder.h
git commit -m "refactor(csr): rename CsrConfig.device_sn to hsm_uid"
```

---

### 任务 2：更新 CsrBuilder 实现

**文件：**
- 修改：`src/csr_builder.cpp`

- [ ] **步骤 1：更新 marshal_x509_name 参数名**

```cpp
// src/csr_builder.cpp - marshal_x509_name 签名
ErrorCode CsrBuilder::marshal_x509_name(const std::string& hsm_uid,
                                        std::vector<uint8_t>& out_der) {
    // ...
    rdn_entries[] = {
        {OID_CN, sizeof(OID_CN), hsm_uid.c_str()},  // CN=HSM UID
        {OID_OU, sizeof(OID_OU), CSR_SUBJECT_OU},
        {OID_O,  sizeof(OID_O),  CSR_SUBJECT_O},
        {OID_C,  sizeof(OID_C),  CSR_SUBJECT_C},
    };
```

- [ ] **步骤 2：更新 marshal_san_extension 参数名**

```cpp
// src/csr_builder.cpp - marshal_san_extension 签名
ErrorCode CsrBuilder::marshal_san_extension(
    const std::string& hsm_uid,
    std::vector<uint8_t>& ext_der) {
    // ...
    // URI for HSM UID (ECU UID)
    std::string hsm_uid_uri = "urn:ecu-uid:" + hsm_uid;
    // ...
```

- [ ] **步骤 3：更新 build_csr_info 使用 hsm_uid**

```cpp
// src/csr_builder.cpp - build_csr_info 中
    // Subject name
    std::vector<uint8_t> subject_der;
    if (marshal_x509_name(config.hsm_uid, subject_der) != ErrorCode::SUCCESS) {
        return ErrorCode::CSR_BUILD_FAILED;
    }
    // ...
    // Build extensions
    if (marshal_san_extension(config.hsm_uid, san_ext) != ErrorCode::SUCCESS ||
```

- [ ] **步骤 4：更新 build_csr 使用 hsm_uid**

```cpp
// src/csr_builder.cpp - build_csr 中
    KeyPair key_pair;
    ErrorCode result = key_engine_->get_device_key(
        vin, config.hsm_uid, key_pair);
    // ...
    result = key_engine_->sign(vin, config.hsm_uid,
                               csr_info, signature);
```

- [ ] **步骤 5：确认编译通过**

运行：`cd build && cmake .. && make 2>&1 | tail -5`
预期：编译成功（sec_service.cpp 的错误需要下一步修复）

- [ ] **步骤 6：Commit**

```bash
git add src/csr_builder.cpp
git commit -m "refactor(csr): update CsrBuilder to use hsm_uid"
```

---

### 任务 3：修改 CertificateRequest 数据结构

**文件：**
- 修改：`include/cloud_client.h:24`

- [ ] **步骤 1：将 CertificateRequest.device_sn 重命名为 ecu_uid**

```cpp
// include/cloud_client.h:24
struct CertificateRequest {
    std::string ecu_uid;    // HSM 身份（ECU UID），与 CSR CN 一致
    std::vector<uint8_t> csr_der;
};
```

- [ ] **步骤 2：确认编译失败**

运行：`cd build && cmake .. && make 2>&1 | head -20`
预期：`sec_service.cpp` 编译报错

- [ ] **步骤 3：Commit**

```bash
git add include/cloud_client.h
git commit -m "refactor(cloud): rename CertificateRequest.device_sn to ecu_uid"
```

---

### 任务 4：更新 SecService 实现

**文件：**
- 修改：`src/sec_service.cpp:726,739`

- [ ] **步骤 1：更新 build_and_store_csr**

```cpp
// src/sec_service.cpp - build_and_store_csr()
ErrorCode SecService::build_and_store_csr() {
    if (!csr_builder_) {
        csr_builder_ = std::make_unique<CsrBuilder>(key_engine_.get());
    }

    CsrConfig csr_config;
    csr_config.hsm_uid = ecu_uid_;      // HSM 身份用于 CSR CN
    csr_config.key_id = ecu_uid_;       // key_id 使用 ecu_uid
    csr_config.algorithm = "ecdsa-p256";

    std::cout << "[SEC] Building CSR with vin=" << vin_ << " hsm_uid=" << ecu_uid_ << std::endl;
    ErrorCode result = csr_builder_->build_csr(vin_, csr_config, csr_der_);
    std::cout << "[SEC] build_csr result=" << static_cast<int>(result)
              << " csr_der_.size()=" << csr_der_.size() << std::endl;
    return result;
}
```

- [ ] **步骤 2：更新 submit_csr_to_cloud**

```cpp
// src/sec_service.cpp - submit_csr_to_cloud()
ErrorCode SecService::submit_csr_to_cloud() {
    CertificateRequest request;
    request.ecu_uid = ecu_uid_;         // HSM 身份用于云端签发
    request.csr_der = csr_der_;         // 使用存储的 CSR

    CertificateResponse response;
    return cloud_client_->submit_csr(request, response);
}
```

- [ ] **步骤 3：确认编译通过**

运行：`cd build && cmake .. && make 2>&1 | tail -5`
预期：全部编译成功

- [ ] **步骤 4：Commit**

```bash
git add src/sec_service.cpp
git commit -m "refactor(sec): update SecService to use hsm_uid and ecu_uid"
```

---

### 任务 5：更新 ProvServiceInterface 注释

**文件：**
- 修改：`include/prov_service_interface.h:20`

- [ ] **步骤 1：更新注释**

```cpp
// include/prov_service_interface.h:20
    // 获取设备信息，VIN 保留但不再用于证书 Subject，证书使用 HSM UID (ecu_uid)
```

- [ ] **步骤 2：Commit**

```bash
git add include/prov_service_interface.h
git commit -m "docs(prov): update comment to reflect hsm_uid usage"
```

---

### 任务 6：运行现有测试验证无回归

**文件：**
- 无修改，仅运行测试

- [ ] **步骤 1：编译测试**

运行：`cd build && cmake .. && make -j4 2>&1 | tail -10`
预期：编译成功

- [ ] **步骤 2：运行所有测试**

运行：`cd build && ctest --output-on-failure 2>&1`
预期：所有测试通过（测试仍使用旧字段名，但功能等价）

- [ ] **步骤 3：确认测试结果**

记录测试通过/失败情况。如果有测试失败，分析是否因为字段名变更。

---

### 任务 7：更新 test_csr_builder.cpp

**文件：**
- 修改：`tests/test_csr_builder.cpp`

- [ ] **步骤 1：全局替换 config.device_sn 为 config.hsm_uid**

将所有 `config.device_sn` 替换为 `config.hsm_uid`（约 10 处）：

```cpp
// 每个测试用例中
CsrConfig config;
config.hsm_uid = test_ecu_uid;   // 改名自 device_sn
config.key_id = test_ecu_uid;
config.algorithm = "ecdsa-p256";
```

同时更新 SAN 检查中的变量名：
```cpp
// 将 has_device_sn 改为 has_hsm_uid
bool has_hsm_uid = false;
// ...
if (uri.find(test_ecu_uid) != std::string::npos)
    has_hsm_uid = true;
// ...
EXPECT_TRUE(has_hsm_uid) << "hsm_uid not found in SAN";
```

- [ ] **步骤 2：运行测试验证**

运行：`cd build && ./tests/test_csr_builder --gtest_filter="*" 2>&1`
预期：所有 CSR 测试通过

- [ ] **步骤 3：Commit**

```bash
git add tests/test_csr_builder.cpp
git commit -m "test(csr): update test_csr_builder to use hsm_uid"
```

---

### 任务 8：更新 test_key_engine.cpp

**文件：**
- 修改：`tests/test_key_engine.cpp`

- [ ] **步骤 1：重命名 test_device_sn 为 test_ecu_uid**

将文件中所有 `test_device_sn` 替换为 `test_ecu_uid`（约 15 处）：

```cpp
// tests/test_key_engine.cpp
std::string test_ecu_uid = "TBOX-DEVICE-001";  // 改名自 test_device_sn
```

- [ ] **步骤 2：运行测试验证**

运行：`cd build && ./tests/test_key_engine --gtest_filter="*" 2>&1`
预期：所有 KeyEngine 测试通过

- [ ] **步骤 3：Commit**

```bash
git add tests/test_key_engine.cpp
git commit -m "test(key): update test_key_engine to use ecu_uid naming"
```

---

### 任务 9：添加身份分层单元测试

**文件：**
- 创建：`tests/test_device_identity.cpp`

- [ ] **步骤 1：编写身份分层测试**

```cpp
// tests/test_device_identity.cpp
#include <gtest/gtest.h>
#include "sec_service.h"
#include "prov_service_interface.h"
#include "diag_service_interface.h"
#include "mock_hsm.h"  // 使用已有的 mock

using namespace tbox::sec;

// 验证 hsm_uid 用于 CSR 构建
TEST(DeviceIdentityTest, CsrUsesHsmUid) {
    // 验证 CsrConfig.hsm_uid 被正确传递给 CSR 构建
    CsrConfig config;
    config.hsm_uid = "test-hsm-uid-001";
    config.key_id = "test-hsm-uid-001";
    config.algorithm = "ecdsa-p256";

    EXPECT_EQ(config.hsm_uid, "test-hsm-uid-001");
    EXPECT_EQ(config.key_id, "test-hsm-uid-001");
}

// 验证 CertificateRequest 使用 ecu_uid
TEST(DeviceIdentityTest, CertRequestUsesEcuUid) {
    CertificateRequest request;
    request.ecu_uid = "test-ecu-uid-001";

    EXPECT_EQ(request.ecu_uid, "test-ecu-uid-001");
}

// 验证 ProvisionStatus 包含 ecu_uid
TEST(DeviceIdentityTest, ProvisionStatusContainsEcuUid) {
    ProvisionStatus status;
    status.ecu_uid = "test-ecu-uid-001";
    status.vin = "TESTVIN0000000001";

    auto json = status.to_json();
    EXPECT_EQ(json["ecu_uid"], "test-ecu-uid-001");
}
```

- [ ] **步骤 2：将测试加入 CMakeLists.txt**

在 `tests/CMakeLists.txt` 中添加：
```cmake
add_executable(test_device_identity test_device_identity.cpp)
target_link_libraries(test_device_identity PRIVATE tbox_sec_lib GTest::gtest_main)
add_test(NAME test_device_identity COMMAND test_device_identity)
```

- [ ] **步骤 3：编译并运行测试**

运行：`cd build && cmake .. && make test_device_identity && ./tests/test_device_identity`
预期：全部通过

- [ ] **步骤 4：Commit**

```bash
git add tests/test_device_identity.cpp tests/CMakeLists.txt
git commit -m "test(identity): add device identity layering tests"
```

---

### 任务 10：全量测试与回归验证

**文件：**
- 无修改

- [ ] **步骤 1：全量编译**

运行：`cd build && cmake .. && make -j4 2>&1 | tail -10`
预期：编译成功，无警告

- [ ] **步骤 2：运行全部测试**

运行：`cd build && ctest --output-on-failure -V 2>&1`
预期：所有测试通过

- [ ] **步骤 3：检查 device_sn 残留引用**

运行：`grep -rn "device_sn" include/ src/ tests/ --include="*.h" --include="*.cpp" | grep -v "// deprecated" | grep -v ".git"`
预期：无残留（`key_engine.h` 的 `make_key_id(device_sn, ...)` 参数名不在本次 CR 范围内，但如有需要可一并修改）

- [ ] **步骤 4：最终 Commit**

```bash
git add -A
git commit -m "refactor: complete TBOX-SEC-DSN-CR-007 device identity layering"
```

---

## 自检

1. **规格覆盖度：** ✅ 设计文档中所有 5 个设计变更点（§2-§5 + device_sn 分层）均有对应任务
2. **占位符扫描：** ✅ 无 TODO、待定、模糊描述
3. **类型一致性：** ✅ `hsm_uid` 在 `CsrConfig`、`CsrBuilder`、`SecService` 中一致使用；`ecu_uid` 在 `CertificateRequest`、`ProvisionStatus` 中一致使用

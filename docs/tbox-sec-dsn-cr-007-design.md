# TBOX-SEC-DSN-CR-007 设计文档

## 变更概述

本设计变更落实 **TBOX-SEC-REQ-CR-007**，纠正将"设备ID"表述为独立 `device_sn` 所造成的歧义。车云通信身份统一使用 **HSM UID（即 ECU UID）**，证书 CN 的实际取值保持不变；VIN 继续不进入证书。

## 背景

### CR-007 设计变更内容

- **统一身份契约**：
  - `device_id := device_sn`（通用设备身份）
  - `hsm_uid := ecu_uid`（HSM 身份）
  - TBOX 的 CN、CSR、MQTT 与鉴权使用 HSM UID

- **设计变更**：
  - §2"设备身份"：Subject DN 调整为 `CN=HSM UID, OU=TBOX-TSP, O=OpenIOV, C=CN`；SAN 不含 VIN
  - §3 `CSR.subject`：由含糊的 `device_sn` 明确为 `hsm_uid`
  - §3 重签幂等键：统一为 `hsm_uid + key_id`
  - §4 SEC 经 `PROV.readBinding()` 获取 `VIN + ECU UID`，其中 `ECU UID` 直接作为 CSR CN
  - §5 证书 profile 与云端签发元数据统一使用 UID

### 现有代码结构

- `CsrConfig` 结构体包含 `device_sn` 字段
- `SecService` 类使用 `ecu_uid_` 字段作为 HSM 身份
- `CsrBuilder` 类使用 `config.device_sn` 作为证书 CN

## 设计方案

### 1. 数据结构变更

#### 1.1 新增 DeviceIdentity 结构体

```cpp
struct DeviceIdentity {
    std::string device_id;  // 通用设备身份（从 TBOX-PROV 获取）
    std::string hsm_uid;    // HSM 身份（从 HSM 获取）
};
```

#### 1.2 修改 CsrConfig 结构体

```cpp
struct CsrConfig {
    std::string hsm_uid;    // 改名自 device_sn，用于证书 CN
    std::string key_id;     // 密钥标识
    std::string algorithm;  // 签名算法
};
```

### 2. SecService 变更

#### 2.1 新增身份管理

```cpp
class SecService {
private:
    // 新增身份管理
    DeviceIdentity device_identity_;
    bool identity_loaded_ = false;
    
    // 获取身份信息（带重试机制）
    ErrorCode load_device_identity();
    
    // 身份验证
    ErrorCode validate_identity();
    
    // 向后兼容接口（标记为 deprecated）
    [[deprecated("Use get_hsm_uid() instead")]]
    std::string get_device_sn() const { return device_identity_.hsm_uid; }
    
    std::string get_hsm_uid() const { return device_identity_.hsm_uid; }
    std::string get_device_id() const { return device_identity_.device_id; }
};
```

#### 2.2 身份获取实现

```cpp
ErrorCode SecService::load_device_identity() {
    if (identity_loaded_) {
        return ErrorCode::SUCCESS;
    }
    
    // 重试机制
    const int max_retries = 3;
    for (int i = 0; i < max_retries; ++i) {
        // 从 HSM 获取 hsm_uid
        auto hsm_uid = key_engine_->get_hsm_uid();
        if (hsm_uid.empty()) {
            std::cerr << "[SEC] Failed to get HSM UID, attempt " << i + 1 << std::endl;
            continue;
        }
        
        // 从 TBOX-PROV 获取 device_id
        auto device_id = prov_service_->get_device_id();
        if (device_id.empty()) {
            std::cerr << "[SEC] Failed to get device ID, attempt " << i + 1 << std::endl;
            continue;
        }
        
        device_identity_.hsm_uid = hsm_uid;
        device_identity_.device_id = device_id;
        identity_loaded_ = true;
        
        std::cout << "[SEC] Device identity loaded: hsm_uid=" << hsm_uid 
                  << ", device_id=" << device_id << std::endl;
        return ErrorCode::SUCCESS;
    }
    
    return ErrorCode::IDENTITY_LOAD_FAILED;
}
```

### 3. CsrBuilder 变更

```cpp
ErrorCode CsrBuilder::build_csr(const std::string& vin,
                                const CsrConfig& config,
                                std::vector<uint8_t>& csr_der) {
    // 使用 config.hsm_uid 替代 config.device_sn
    // Subject DN: CN=HSM UID, OU=TBOX-TSP, O=OpenIOV, C=CN
    
    // 获取密钥对
    KeyPair key_pair;
    ErrorCode result = key_engine_->get_device_key(vin, config.hsm_uid, key_pair);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    // 构建 CSR
    std::vector<uint8_t> csr_info;
    result = build_csr_info(vin, config, key_pair, csr_info);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    // 签名
    std::vector<uint8_t> signature;
    result = key_engine_->sign(vin, config.hsm_uid, csr_info, signature);
    if (result != ErrorCode::SUCCESS) {
        return ErrorCode::CSR_SIGN_FAILED;
    }
    
    // 组装最终 CSR
    // ...
    
    return ErrorCode::SUCCESS;
}
```

### 4. 调用点更新

#### 4.1 SecService::build_and_store_csr()

```cpp
ErrorCode SecService::build_and_store_csr() {
    // 加载身份信息
    ErrorCode result = load_device_identity();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    if (!csr_builder_) {
        csr_builder_ = std::make_unique<CsrBuilder>(key_engine_.get());
    }

    CsrConfig csr_config;
    csr_config.hsm_uid = device_identity_.hsm_uid;  // 改名自 device_sn
    csr_config.key_id = device_identity_.hsm_uid;   // key_id 使用 hsm_uid
    csr_config.algorithm = "ecdsa-p256";

    std::cout << "[SEC] Building CSR with vin=" << vin_ 
              << " hsm_uid=" << device_identity_.hsm_uid << std::endl;
    return csr_builder_->build_csr(vin_, csr_config, csr_der_);
}
```

#### 4.2 SecService::submit_csr_to_cloud()

```cpp
ErrorCode SecService::submit_csr_to_cloud() {
    CertificateRequest request;
    request.ecu_uid = device_identity_.hsm_uid;  // 改名自 device_sn
    request.csr_der = csr_der_;

    CertificateResponse response;
    return cloud_client_->submit_csr(request, response);
}
```

### 5. 测试策略

#### 5.1 单元测试更新

- 修改现有测试使用 `hsm_uid` 字段
- 更新测试用例中的 `CsrConfig` 初始化

#### 5.2 新增测试

```cpp
// 测试身份分层逻辑
TEST_F(SecServiceTest, DeviceIdentityLayering) {
    // 模拟 HSM 和 PROV 服务
    MockHsm mock_hsm;
    MockProv mock_prov;
    
    // 设置期望值
    EXPECT_CALL(mock_hsm, get_hsm_uid()).WillOnce(Return("test_hsm_uid"));
    EXPECT_CALL(mock_prov, get_device_id()).WillOnce(Return("test_device_id"));
    
    // 执行测试
    SecService service(config, mock_hsm, mock_prov);
    auto identity = service.get_device_identity();
    
    // 验证结果
    EXPECT_EQ(identity.hsm_uid, "test_hsm_uid");
    EXPECT_EQ(identity.device_id, "test_device_id");
}
```

#### 5.3 集成测试

- 使用模拟 HSM 和真实 TBOX-PROV 服务
- 测试完整的证书申请流程

### 6. 向后兼容性

- 保留 `get_device_sn()` 接口，标记为 deprecated
- 添加注释说明迁移路径
- 保持现有接口签名不变

### 7. 日志和监控

#### 7.1 日志记录

```cpp
// 身份获取日志
std::cout << "[SEC] Loading device identity..." << std::endl;
std::cout << "[SEC] Device identity loaded: hsm_uid=" << hsm_uid 
          << ", device_id=" << device_id << std::endl;

// 错误日志
std::cerr << "[SEC] Failed to get HSM UID, attempt " << attempt << std::endl;
```

#### 7.2 性能监控

- 记录身份获取耗时
- 监控重试次数和成功率

### 8. 实施计划

#### 8.1 实施顺序（自底向上）

1. **数据结构变更**：修改 `CsrConfig` 结构体
2. **业务逻辑变更**：更新 `SecService` 和 `CsrBuilder`
3. **调用点更新**：更新所有使用 `device_sn` 的代码
4. **测试更新**：修改和新增测试用例
5. **文档更新**：同步更新文档和注释

#### 8.2 提交策略（功能分组）

1. **提交 1**：数据结构变更
2. **提交 2**：业务逻辑变更
3. **提交 3**：测试更新
4. **提交 4**：文档更新

## 一致性约束

- SEC SHALL 校验 CSR CN 与 `PROV.readBinding().ecu_uid` 一致
- 平台 SHALL 校验签发请求 `ecu_uid` 与 CSR CN 一致
- MQTT / VAGW / TSP SHALL 使用同一 UID 完成连接身份、Topic 隔离及设备档案查询

## 影响范围

- 不改变私钥生成、存储和证书注入流程
- 不改变"证书不含 VIN"的决策
- 明确 `device_sn` 与 HSM UID 的分层定位：前者是通用设备身份，后者是 TBOX 硬件安全与车云鉴权身份；二者保持 1:1 绑定，不再混用字段语义

## 验收标准

1. **功能验收**：
   - 证书申请流程正常工作
   - 证书 CN 使用 HSM UID
   - VIN 不进入证书

2. **测试验收**：
   - 单元测试覆盖率 ≥ 70%
   - 集成测试通过
   - 手动测试验证

3. **质量验收**：
   - 代码审查通过
   - 静态分析无警告
   - 文档同步更新
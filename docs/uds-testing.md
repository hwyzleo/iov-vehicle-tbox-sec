# UDS 测试工具使用指南

## 方式1：运行单元测试（最简单）

```bash
# 编译项目
./scripts/build-local.sh

# 运行UDS相关测试
cd build
./TboxSecTests --gtest_filter=UdsHandlerTest.*

# 或者运行所有测试
ctest
```

## 方式2：使用Python模拟器（需要网络接口）

当前main.cpp没有实现UDS服务器，需要先添加。

### 临时方案：添加UDS TCP服务器

在 `src/main.cpp` 中添加：

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

// 在 main() 函数的 while 循环中替换为：
int server_fd = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in address;
address.sin_family = AF_INET;
address.sin_addr.s_addr = INADDR_ANY;
address.sin_port = htons(5000);

bind(server_fd, (struct sockaddr*)&address, sizeof(address));
listen(server_fd, 3);

std::cout << "UDS Server listening on port 5000" << std::endl;

while (g_running) {
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) continue;
    
    uint8_t buffer[1024];
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer));
    
    if (bytes_read > 0) {
        // Parse UDS request and call handler
        UdsRequest request;
        // ... parse buffer to request ...
        
        UdsResponse response = g_uds_handler->handle_request(request);
        
        // Send response
        write(client_fd, response.data.data(), response.data.size());
    }
    
    close(client_fd);
}
```

然后运行：
```bash
# 终端1：启动服务
./build/TboxSecService

# 终端2：运行模拟器
python3 scripts/uds_simulator.py --host localhost --port 5000 --workflow
```

## 方式3：直接测试UDS Handler代码

无需网络，直接在代码中调用：

```cpp
#include "uds_handler.h"
#include "sec_service.h"

int main() {
    // 创建配置
    SecServiceConfig config;
    config.vin = "TESTVIN1234567890";
    config.ecu_uid = "TBOX-ECU-001";
    config.hsm_type = "software";
    config.hsm_config_path = "/tmp/test_hsm";
    config.state_file_path = "/tmp/test_state.json";
    
    // 初始化服务
    auto sec_service = std::make_shared<SecService>(config);
    sec_service->initialize();
    
    // 创建UDS处理器
    UdsHandler uds_handler(sec_service);
    uds_handler.initialize();
    
    // 模拟诊断会话控制
    UdsRequest request;
    request.service = UdsService::DIAGNOSTIC_SESSION_CONTROL;
    request.sub_function = 0x03; // Extended session
    
    UdsResponse response = uds_handler.handle_request(request);
    
    // 模拟安全访问
    request.service = UdsService::SECURITY_ACCESS;
    request.sub_function = 0x29; // Request seed
    
    response = uds_handler.handle_request(request);
    
    // ... 继续其他操作
}
```

## 方式4：使用Python脚本测试

```bash
# 显示UDS命令参考
python3 scripts/test_uds.py --commands

# 运行单元测试
python3 scripts/test_uds.py --unit-test

# 测试二进制文件
python3 scripts/test_uds.py --binary
```

## UDS命令速查

| 服务 | 请求 | 说明 |
|------|------|------|
| 诊断会话 | `10 03` | 切换到扩展会话 |
| 安全访问-种子 | `29 29` | 请求安全访问种子 |
| 安全访问-密钥 | `29 2A <key>` | 发送安全访问密钥 |
| 读取状态 | `22 F1 00` | 读取Provision状态 |
| 读取CSR | `22 F1 01` | 读取CSR数据 |
| 生成密钥 | `31 01 FF 00` | 生成密钥对 |
| 写入证书 | `2E F1 02 <cert>` | 写入证书 |

## 常见问题

### Q: 为什么单元测试中的安全访问总是成功？
A: 当前实现是简化版，密钥验证被跳过了。生产环境需要与HSM配合进行真正的密钥验证。

### Q: 如何测试真实的UDS通信？
A: 需要：
1. 实现UDS over CAN/Ethernet的传输层
2. 连接真实的诊断仪
3. 配置正确的安全访问密钥算法

### Q: 如何查看UDS请求/响应的详细信息？
A: 启用日志：
```yaml
# config.yaml
logging:
  level: "DEBUG"
```

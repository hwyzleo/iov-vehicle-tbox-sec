# TBOX Security Service 部署指南

## 1. 环境准备

### 1.1 开发机（macOS）

```bash
# 安装依赖
brew install cmake openssl yaml-cpp curl nlohmann-json googletest

# 安装交叉编译工具（可选）
brew install aarch64-elf-gcc

# 或者使用Docker进行交叉编译（推荐）
docker pull multiarch/debian-debootstrap:arm64-buster
```

### 1.2 目标设备（TBOX Linux）

确保TBOX上已安装：
- OpenSSL 1.1+
- yaml-cpp
- libcurl
- nlohmann-json

## 2. 编译

### 2.1 本地编译（开发测试）

```bash
# 方法1：使用系统依赖
./scripts/build-local.sh

# 方法2：使用Conan管理依赖
./scripts/build-local.sh conan

# 运行测试
cd build && ctest
```

### 2.2 交叉编译（部署到TBOX）

#### 方法1：使用Docker（推荐）

```bash
# 创建Dockerfile
cat > Dockerfile.cross << 'EOF'
FROM multiarch/debian-debootstrap:arm64-buster

RUN apt-get update && apt-get install -y \
    build-essential cmake libssl-dev libyaml-cpp-dev \
    libcurl4-openssl-dev nlohmann-json3-dev libgtest-dev

WORKDIR /build
COPY . /build

RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)
EOF

# 构建
docker build -f Dockerfile.cross -t tbox-sec-builder .
docker run --rm -v $(pwd)/output:/output tbox-sec-builder \
    cp /build/build/TboxSecService /output/
```

#### 方法2：使用交叉编译工具链

```bash
# 安装工具链
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# 交叉编译
mkdir build-aarch64 && cd build-aarch64
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=../toolchain-aarch64-linux-gnu.cmake \
    -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## 3. 部署到TBOX

### 3.1 自动部署

```bash
# 使用部署脚本
./scripts/deploy.sh 192.168.1.100 root
```

### 3.2 手动部署

```bash
# 1. 创建目录
ssh root@192.168.1.100 "mkdir -p /opt/tbox-sec/{config,lib}"

# 2. 拷贝文件
scp build/TboxSecService root@192.168.1.100:/opt/tbox-sec/
scp config/config.yaml root@192.168.1.100:/opt/tbox-sec/config/

# 3. 拷贝依赖库（如果需要）
scp /usr/lib/aarch64-linux-gnu/libyaml-cpp.so* root@192.168.1.100:/opt/tbox-sec/lib/
scp /usr/lib/aarch64-linux-gnu/libcurl.so* root@192.168.1.100:/opt/tbox-sec/lib/

# 4. 安装服务
scp scripts/tbox-sec.service root@192.168.1.100:/etc/systemd/system/
ssh root@192.168.1.100 "systemctl daemon-reload"
```

## 4. 配置

### 4.1 修改配置文件

```bash
# 编辑TBOX上的配置
ssh root@192.168.1.100 "vi /opt/tbox-sec/config/config.yaml"
```

关键配置项：
```yaml
tbox:
  hsm:
    type: "pkcs11"           # 生产环境使用pkcs11
    library_path: "/usr/lib/softhsm2/libsofthsm2.so"
    
  cloud:
    oapi_endpoint: "https://实际OAPI地址:10805"
```

**注意**：VIN和ECU UID现在从PROV服务获取，不再需要在配置文件中配置。

### 4.2 创建必要目录

```bash
ssh root@192.168.1.100 "
mkdir -p /var/lib/tbox/sec/keys
mkdir -p /var/lib/tbox/sec/certs
mkdir -p /var/log/tbox
chown -R tbox:tbox /var/lib/tbox /var/log/tbox
"
```

## 5. 启动服务

```bash
# 启动
ssh root@192.168.1.100 "systemctl start tbox-sec"

# 检查状态
ssh root@192.168.1.100 "systemctl status tbox-sec"

# 查看日志
ssh root@192.168.1.100 "journalctl -u tbox-sec -f"
```

## 6. 验证

### 6.1 检查服务运行

```bash
ssh root@192.168.1.100 "ps aux | grep TboxSecService"
```

### 6.2 测试UDS通信

使用诊断仪发送UDS请求：
```
# 读取Provision状态
22 F1 00

# 生成密钥对（需要先安全访问）
29 29  -> 获取种子
29 2A [密钥]  -> 发送密钥
31 01 FF 00  -> 生成密钥对
```

## 7. 故障排查

### 7.1 服务启动失败

```bash
# 检查日志
journalctl -u tbox-sec -n 100

# 检查依赖库
ldd /opt/tbox-sec/TboxSecService

# 手动运行测试
/opt/tbox-sec/TboxSecService /opt/tbox-sec/config/config.yaml
```

### 7.2 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 找不到libyaml-cpp | 依赖库缺失 | 拷贝到/opt/tbox-sec/lib/ |
| HSM初始化失败 | HSM配置错误 | 检查hsm.type和library_path |
| 云端连接失败 | 网络或配置问题 | 检查oapi_endpoint和网络 |
| 权限拒绝 | 文件权限问题 | 检查tbox用户权限 |

## 8. 生产环境注意事项

1. **HSM配置**：生产环境必须使用硬件HSM（PKCS11或TrustZone）
2. **证书验证**：确保OAPI的SSL证书已正确配置
3. **日志级别**：生产环境建议使用INFO或WARN级别
4. **监控**：集成到TBOX的监控系统
5. **备份**：定期备份/var/lib/tbox/sec/目录

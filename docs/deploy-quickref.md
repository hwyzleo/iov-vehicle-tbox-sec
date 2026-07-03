# TBOX Security Service 快速部署参考卡

## 一键部署命令

```bash
# 1. 编译（选择一种方式）

# 方式A: 本地编译（开发测试）
./scripts/build-local.sh

# 方式B: Docker交叉编译（部署到TBOX）
docker build -f Dockerfile.cross -t tbox-sec .
docker run --rm -v $(pwd)/output:/dest tbox-sec

# 方式C: 直接交叉编译
mkdir build-aarch64 && cd build-aarch64
cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-aarch64-linux-gnu.cmake
make -j$(nproc)

# 2. 部署到TBOX
./scripts/deploy.sh <TBOX_IP> root

# 3. 配置TBOX
ssh root@<TBOX_IP> "vi /etc/tbox/common.yaml"
ssh root@<TBOX_IP> "vi /etc/tbox/conf.d/sec.yaml"

# 4. 启动服务
ssh root@<TBOX_IP> "systemctl start tbox-sec"

# 5. 验证
ssh root@<TBOX_IP> "systemctl status tbox-sec"
ssh root@<TBOX_IP> "journalctl -u tbox-sec -f"
```

## 目录结构（TBOX上）

```
/etc/tbox/
├── common.yaml             # 公共配置（cloud, environment）
└── conf.d/
    └── sec.yaml            # SEC服务配置

/var/lib/tbox/sec/
├── provision_state.json    # ProvisionState
├── device_cert.der         # 设备证书
├── ca_cert.der             # CA证书
└── keys/                   # 密钥存储（SOFT_FILE模式）
    ├── metadata_<key_id>.json
    └── encrypted_<key_id>.bin

/var/log/tbox/
└── sec_service.log         # 日志文件
```

## 配置文件模板

### 公共配置（common.yaml）
```yaml
cloud:
  endpoint: "https://实际地址:10805"
  timeout_ms: 30000
  retry_count: 3
  retry_delay_ms: 1000
environment:
  is_production: false
```

### SEC服务配置（conf.d/sec.yaml）
```yaml
hsm:
  type: "soft_file"           # 生产环境用hardware
  library_path: "/usr/lib/softhsm2/libsofthsm2.so"
key_provisioning:
  mode: "soft_file"           # 生产环境用hsm
soft_key:
  path: "/var/lib/tbox/sec/keys"
  encryption_algo: "aes-256-gcm"
  encryption_key_path: "/var/lib/tbox/sec/soft_key_enc.key"
storage:
  state_file: "/var/lib/tbox/sec/provision_state.json"
  ca_cert: "/var/lib/tbox/sec/ca_cert.der"
  cert_store: "/var/lib/tbox/sec/"
```

## 诊断仪测试命令

```
# 读取Provision状态
22 F1 00

# 安全访问
29 29           # 请求种子
29 2A <密钥>    # 发送密钥

# 生成密钥对
31 01 FF 00

# 读取CSR
22 F1 01

# 写入证书
2E F1 02 <证书数据>
```

## 常见问题速查

| 问题 | 命令 |
|------|------|
| 查看日志 | `journalctl -u tbox-sec -f` |
| 重启服务 | `systemctl restart tbox-sec` |
| 检查依赖 | `ldd /opt/tbox-sec/TboxSecService` |
| 手动运行 | `/opt/tbox-sec/TboxSecService /etc/tbox/common.yaml` |
| 检查端口 | `netstat -tlnp \| grep TboxSecService` |

## 文件清单

```
scripts/
├── deploy.sh           # 自动部署脚本
├── build-local.sh      # 本地编译脚本
└── setup-dev.sh        # 开发环境配置

toolchain-aarch64-linux-gnu.cmake  # 交叉编译工具链
Dockerfile.cross                    # Docker交叉编译
docs/deployment.md                  # 完整部署文档
```

//
// TBOX-SEC-DSN-CR-013 §13 / SEC-CONFIG-REQ-008
// sec_config_checker 单元测试（通过子进程调用 checker 二进制）
//
// 覆盖：
//   - production 接受合法 HSM 配置
//   - production 拒绝：顶层 common、soft_file 模式、soft_key.*、PIN/Token、
//     private_key_ref、dev_peer_service、..路径、相对路径
//   - test 允许 soft_file、soft_key.*、dev_peer_service
//   - 文件不存在 / YAML 解析错误 -> 退出码 2
//   - 未知字段 -> warn 但 pass（退出码 0）
//   - 输出不回显配置值
//

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <sys/wait.h>

#ifndef SEC_CONFIG_CHECKER_BIN
#error "SEC_CONFIG_CHECKER_BIN must be defined by CMake"
#endif

namespace {

// 进程执行结果
struct CheckResult {
    int exit_code = -1;
    std::string output;
};

// 写临时 YAML 文件，返回路径
std::string writeTempConfig(const std::string& name, const std::string& content) {
    namespace fs = std::filesystem;
    static std::string test_dir = [] {
        auto dir = fs::temp_directory_path() / ("sec_checker_test_" +
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
        fs::create_directories(dir);
        return dir.string();
    }();
    std::string path = test_dir + "/" + name;
    std::ofstream f(path);
    f << content;
    f.close();
    return path;
}

// 执行 checker 子进程（路径已由调用方保证无需转义：测试控制的临时文件）
CheckResult runChecker(const std::string& config_path, const std::string& profile) {
    std::string cmd = std::string(SEC_CONFIG_CHECKER_BIN) +
                      " --check-config \"" + config_path + "\""
                      " --profile " + profile + " 2>&1";
    CheckResult result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        result.exit_code = -1;
        return result;
    }
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result.output += buffer;
    }
    int status = pclose(pipe);
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

// 合法 production 配置（默认模板等价）
const std::string kValidProduction = R"yaml(
sec:
  ipc:
    socket_path: "/tmp/tbox-sec.sock"
hsm:
  type: "software"
  library_path: ""
key_provisioning:
  mode: "hsm"
cloud:
  endpoint: ""
  timeout_ms: 5000
  retry_count: 3
  retry_delay_ms: 1000
storage:
  state_file: ""
  ca_cert: ""
  cert_store: ""
environment:
  is_production: false
)yaml";

// 合法 test 配置（含 soft_file / soft_key / dev_peer）
const std::string kValidTest = R"yaml(
common:
  store:
    root: "./data"
hsm:
  type: "software"
key_provisioning:
  mode: "soft_file"
soft_key:
  path: "./keys"
  encryption_algo: "aes-256-gcm"
  encryption_key_path: "./kek"
storage:
  state_file: "./state.json"
  cert_store: "./certs"
environment:
  is_production: false
sec:
  ipc:
    socket_path: "/tmp/tbox-sec.sock"
  tls:
    dev_peer_service: "tbox-mqtt.service"
)yaml";

} // namespace

// =========================================================================
// production profile - 合法配置通过
// =========================================================================
TEST(SecConfigCheckerTest, ProductionAcceptsValidHsmConfig) {
    auto path = writeTempConfig("valid_prod.yaml", kValidProduction);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find("PASS"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝顶层 common
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsToplevelCommon) {
    std::string cfg = "common:\n  store:\n    root: \"/var/tbox\"\n" +
                      kValidProduction;
    auto path = writeTempConfig("has_common.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("no_toplevel_common"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝 soft_file 模式
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsSoftFileMode) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "soft_file"
hsm:
  type: "software"
)yaml";
    auto path = writeTempConfig("soft_file_mode.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("production_hsm_only"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝 soft_key 节
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsSoftKeySection) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
soft_key:
  path: "/var/lib/tbox/sec/soft_keys"
  encryption_algo: "aes-256-gcm"
)yaml";
    auto path = writeTempConfig("has_soft_key.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("production_no_soft_key"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝秘密字段（PIN/Token/private_key_ref）
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsSecretFields) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
hsm:
  type: "pkcs11"
  pin: "123456"
  token: "my-token"
  private_key_ref: "ref-001"
)yaml";
    auto path = writeTempConfig("has_secrets.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("pin"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("token"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("private_key_ref"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("production_no_secret"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝 dev_peer_service
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsDevPeerService) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
sec:
  tls:
    dev_peer_service: "tbox-mqtt.service"
)yaml";
    auto path = writeTempConfig("has_dev_peer.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("production_no_dev_peer"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝 .. 路径越界
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsTraversalPath) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
storage:
  state_file: "/var/lib/../../../etc/passwd"
)yaml";
    auto path = writeTempConfig("traversal.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("no_traversal"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝相对路径
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsRelativePath) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
storage:
  cert_store: "./certs"
)yaml";
    auto path = writeTempConfig("relative.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("production_absolute"), std::string::npos) << r.output;
}

// =========================================================================
// production profile - 拒绝个人目录（~）
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRejectsPersonalDir) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
storage:
  ca_cert: "~/ca.pem"
)yaml";
    auto path = writeTempConfig("personal.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("no_personal_dir"), std::string::npos) << r.output;
}

// =========================================================================
// test profile - 允许 soft_file / soft_key / dev_peer
// =========================================================================
TEST(SecConfigCheckerTest, TestAcceptsSoftFileAndSoftKey) {
    auto path = writeTempConfig("valid_test.yaml", kValidTest);
    auto r = runChecker(path, "test");
    EXPECT_EQ(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find("PASS"), std::string::npos) << r.output;
}

// =========================================================================
// test profile - 秘密字段产生 warn（不 fail）
// =========================================================================
TEST(SecConfigCheckerTest, TestWarnsOnSecretFields) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "soft_file"
hsm:
  type: "software"
  pin: "123456"
)yaml";
    auto path = writeTempConfig("test_secrets.yaml", cfg);
    auto r = runChecker(path, "test");
    // test profile 秘密字段为 warn，不 fail
    EXPECT_EQ(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find("test_no_secret"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("warnings"), std::string::npos) << r.output;
}

// =========================================================================
// 未知字段 - warn 但 pass
// =========================================================================
TEST(SecConfigCheckerTest, UnknownFieldWarnsButPasses) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
unknown_section:
  foo: "bar"
)yaml";
    auto path = writeTempConfig("unknown.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find("unknown_field"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("1 warnings"), std::string::npos) << r.output;
}

// =========================================================================
// 文件不存在 - 退出码 2
// =========================================================================
TEST(SecConfigCheckerTest, MissingFileReturnsUsageError) {
    auto r = runChecker("/nonexistent/sec/config.yaml", "production");
    EXPECT_EQ(r.exit_code, 2) << r.output;
}

// =========================================================================
// YAML 解析错误 - 退出码 2
// =========================================================================
TEST(SecConfigCheckerTest, MalformedYamlReturnsUsageError) {
    std::string cfg = "this: is: not: valid: yaml: [unclosed";
    auto path = writeTempConfig("malformed.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 2) << r.output;
    EXPECT_NE(r.output.find("parse error"), std::string::npos) << r.output;
}

// =========================================================================
// 缺少 --profile - 退出码 2
// =========================================================================
TEST(SecConfigCheckerTest, MissingProfileReturnsUsageError) {
    auto path = writeTempConfig("no_profile.yaml", kValidProduction);
    std::string cmd = std::string(SEC_CONFIG_CHECKER_BIN) +
                      " --check-config \"" + path + "\" 2>&1";
    CheckResult r;
    FILE* pipe = popen(cmd.c_str(), "r");
    ASSERT_NE(pipe, nullptr);
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe)) r.output += buffer;
    int pstatus = pclose(pipe);
    r.exit_code = WEXITSTATUS(pstatus);
    EXPECT_EQ(r.exit_code, 2) << r.output;
}

// =========================================================================
// 输出不回显配置值（秘密保护）
// =========================================================================
TEST(SecConfigCheckerTest, OutputDoesNotLeakConfigValues) {
    std::string secret_value = "SUPER_SECRET_VALUE_12345";
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
hsm:
  type: "pkcs11"
  pin: ")yaml" + secret_value + R"yaml("
)yaml";
    auto path = writeTempConfig("secret_value.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    // 报告字段路径但不回显值
    EXPECT_EQ(r.output.find(secret_value), std::string::npos)
        << "output must not contain config values: " << r.output;
}

// =========================================================================
// production 缺少 key_provisioning.mode - 错误
// =========================================================================
TEST(SecConfigCheckerTest, ProductionRequiresKeyProvisioningMode) {
    std::string cfg = R"yaml(
hsm:
  type: "software"
)yaml";
    auto path = writeTempConfig("no_mode.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("key_provisioning"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("required"), std::string::npos) << r.output;
}

// =========================================================================
// hsm.type 非法值 - 错误
// =========================================================================
TEST(SecConfigCheckerTest, InvalidHsmTypeRejected) {
    std::string cfg = R"yaml(
key_provisioning:
  mode: "hsm"
hsm:
  type: "invalid_backend"
)yaml";
    auto path = writeTempConfig("bad_hsm_type.yaml", cfg);
    auto r = runChecker(path, "production");
    EXPECT_EQ(r.exit_code, 1) << r.output;
    EXPECT_NE(r.output.find("hsm.type"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("allowed_values"), std::string::npos) << r.output;
}

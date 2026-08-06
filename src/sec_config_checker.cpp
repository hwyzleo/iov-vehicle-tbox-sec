//
// sec_config_checker - TBOX-SEC-DSN-CR-013 §8/§9 / SEC-CONFIG-REQ-007/008
//
// 无副作用的 SEC 配置校验器：解析单个 YAML 目标文件并按 profile 校验。
//
// 用法：
//   sec_config_checker --check-config <path> --profile production|test
//
// 退出码：
//   0  校验通过（允许有 warn）
//   1  校验失败（存在 error）
//   2  用法错误 / 文件不存在 / YAML 解析错误
//
// 边界（纯校验，SEC-CONFIG-REQ-008）：
//   - 不访问网络、不执行密码学写操作、不打开/修改 HSM/SE
//   - 不写 framework-store、不监听 IPC、不读 provisioning 秘密
//   - 仅读取并解析目标 YAML 文件（stat/read），无其他文件系统副作用
//
// 输出：只报告规则、文件、字段路径，绝不回显配置值。
//

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// 退出码
// ---------------------------------------------------------------------------
constexpr int EXIT_PASS = 0;
constexpr int EXIT_VALIDATION_FAIL = 1;
constexpr int EXIT_USAGE_ERROR = 2;

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------
enum class Profile { Production, Test };

std::string profileToString(Profile p) {
    return p == Profile::Production ? "production" : "test";
}

// ---------------------------------------------------------------------------
// 校验发现
// ---------------------------------------------------------------------------
struct Finding {
    std::string severity;  // "ERROR" / "WARN"
    std::string rule;
    std::string field_path;
    std::string message;
};

// ---------------------------------------------------------------------------
// 已知 schema 结构（用于未知字段检测）
// ---------------------------------------------------------------------------
const std::set<std::string> kAllowedTopLevel = {
    "sec", "hsm", "key_provisioning", "cloud", "storage", "soft_key",
    "environment"
};

const std::set<std::string> kSecKeys = {"ipc", "tls"};
const std::set<std::string> kSecIpcKeys = {"socket_path"};
const std::set<std::string> kSecTlsKeys = {"dev_peer_service", "profiles"};
const std::set<std::string> kTlsProfileKeys = {
    "credential_id", "key_usage", "allowed_signature_algorithms",
    "peer_service", "notify_on_change", "ref_ttl_sec"
};
const std::set<std::string> kHsmKeys = {"type", "library_path"};
const std::set<std::string> kKeyProvKeys = {"mode"};
const std::set<std::string> kCloudKeys = {
    "endpoint", "timeout_ms", "retry_count", "retry_delay_ms"
};
const std::set<std::string> kStorageKeys = {"state_file", "ca_cert", "cert_store"};
const std::set<std::string> kSoftKeyKeys = {
    "path", "encryption_algo", "encryption_key_path"
};
const std::set<std::string> kEnvironmentKeys = {"is_production"};

// production 禁止的秘密字段名（小写精确匹配末段）
const std::set<std::string> kForbiddenSecretFields = {
    "pin", "token", "handle", "private_key_ref", "private_key",
    "tls_secret", "secret", "kek", "password", "passphrase", "slot_secret"
};

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------
std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

// ---------------------------------------------------------------------------
// 配置校验器
// ---------------------------------------------------------------------------
class ConfigChecker {
public:
    ConfigChecker(std::string file_path, Profile profile)
        : file_path_(std::move(file_path)), profile_(profile) {}

    // 返回 true 表示无 error（可能有 warn）
    bool run() {
        try {
            root_ = YAML::LoadFile(file_path_);
        } catch (const YAML::BadFile&) {
            std::cerr << "ERROR: cannot open config file: " << file_path_ << "\n";
            return false;  // 由调用方映射为 EXIT_USAGE_ERROR
        } catch (const YAML::Exception& e) {
            std::cerr << "ERROR: YAML parse error in " << file_path_ << ": "
                      << e.what() << "\n";
            return false;  // 由调用方映射为 EXIT_USAGE_ERROR
        }

        if (!root_.IsMap()) {
            emit("ERROR", "schema.root", "<root>",
                 "root node must be a YAML map");
            return hasNoErrors();
        }

        checkTopLevelKeys();
        checkKeyProvisioning();
        checkHsm();
        checkSoftKey();
        checkSec();
        checkCloud();
        checkStorage();
        checkEnvironment();
        checkSecretFieldsRecursive(root_, "");
        return hasNoErrors();
    }

    void printReport() const {
        for (const auto& f : findings_) {
            std::cout << f.severity << " [" << f.rule << "] "
                      << "field=" << (f.field_path.empty() ? "<root>" : f.field_path)
                      << ": " << f.message << "\n";
        }
        int errors = 0, warns = 0;
        for (const auto& f : findings_) {
            if (f.severity == "ERROR") ++errors;
            else if (f.severity == "WARN") ++warns;
        }
        std::cout << (errors == 0 ? "PASS" : "FAIL") << ": " << file_path_
                  << " (profile=" << profileToString(profile_)
                  << ", " << errors << " errors, " << warns << " warnings)\n";
    }

    const std::vector<Finding>& findings() const { return findings_; }

private:
    std::string file_path_;
    Profile profile_;
    YAML::Node root_;
    std::vector<Finding> findings_;

    void emit(std::string severity, std::string rule, std::string field_path,
              std::string message) {
        findings_.push_back({std::move(severity), std::move(rule),
                             std::move(field_path), std::move(message)});
    }

    void error(std::string rule, std::string field, std::string msg) {
        emit("ERROR", std::move(rule), std::move(field), std::move(msg));
    }

    void warn(std::string rule, std::string field, std::string msg) {
        emit("WARN", std::move(rule), std::move(field), std::move(msg));
    }

    bool hasNoErrors() const {
        for (const auto& f : findings_) {
            if (f.severity == "ERROR") return false;
        }
        return true;
    }

    bool isProduction() const { return profile_ == Profile::Production; }

    // 顶层键校验：production 禁止 common；未知顶层键 warn
    void checkTopLevelKeys() {
        for (const auto& kv : root_) {
            const std::string key = kv.first.as<std::string>();
            if (key == "common") {
                if (isProduction()) {
                    error("profile.no_toplevel_common", "common",
                          "production profile forbids top-level 'common:' block "
                          "(provided by BUILD /etc/tbox/common.yaml)");
                }
                // test profile 允许 common 覆盖（dev 调试模式）
                continue;
            }
            if (kAllowedTopLevel.find(key) == kAllowedTopLevel.end()) {
                warn("schema.unknown_field", key,
                     "unknown top-level key (allowed: " +
                     joinSet(kAllowedTopLevel) + ")");
            }
        }
    }

    void checkKeyProvisioning() {
        YAML::Node kp = root_["key_provisioning"];
        if (!kp || !kp.IsMap()) {
            if (isProduction()) {
                error("schema.required", "key_provisioning",
                      "key_provisioning section is required in production profile");
            } else {
                warn("schema.required", "key_provisioning",
                     "key_provisioning section missing (defaults to hsm)");
            }
            return;
        }
        checkUnknownFields(kp, kKeyProvKeys, "key_provisioning");

        YAML::Node mode = kp["mode"];
        if (!mode) {
            if (isProduction()) {
                error("schema.required", "key_provisioning.mode",
                      "key_provisioning.mode is required in production profile");
            } else {
                warn("schema.required", "key_provisioning.mode",
                     "key_provisioning.mode missing (defaults to hsm)");
            }
            return;
        }
        const std::string mode_str = toLower(trim(mode.as<std::string>()));
        if (mode_str != "hsm" && mode_str != "soft_file") {
            error("schema.allowed_values", "key_provisioning.mode",
                  "must be one of: hsm, soft_file");
            return;
        }
        if (isProduction() && mode_str == "soft_file") {
            error("profile.production_hsm_only", "key_provisioning.mode",
                  "production profile only allows key_provisioning.mode=hsm");
        }
    }

    void checkHsm() {
        YAML::Node hsm = root_["hsm"];
        if (!hsm || !hsm.IsMap()) {
            return;  // hsm 可选
        }
        checkUnknownFields(hsm, kHsmKeys, "hsm");

        YAML::Node type = hsm["type"];
        if (type) {
            const std::string t = toLower(trim(type.as<std::string>()));
            static const std::set<std::string> allowed = {
                "", "software", "pkcs11", "trustzone"
            };
            if (allowed.find(t) == allowed.end()) {
                error("schema.allowed_values", "hsm.type",
                      "must be one of: software, pkcs11, trustzone (or empty)");
            }
        }

        YAML::Node lib = hsm["library_path"];
        if (lib) {
            const std::string p = lib.as<std::string>();
            checkPath("hsm.library_path", p);
        }
    }

    void checkSoftKey() {
        YAML::Node sk = root_["soft_key"];
        if (!sk) return;
        if (isProduction()) {
            error("profile.production_no_soft_key", "soft_key",
                  "production profile forbids the entire soft_key section");
            return;
        }
        if (!sk.IsMap()) return;
        checkUnknownFields(sk, kSoftKeyKeys, "soft_key");

        checkPath("soft_key.path", sk["path"] ? sk["path"].as<std::string>() : "");
        checkPath("soft_key.encryption_key_path",
                  sk["encryption_key_path"] ? sk["encryption_key_path"].as<std::string>() : "");
    }

    void checkSec() {
        YAML::Node sec = root_["sec"];
        if (!sec) return;
        if (!sec.IsMap()) return;
        checkUnknownFields(sec, kSecKeys, "sec");

        YAML::Node ipc = sec["ipc"];
        if (ipc && ipc.IsMap()) {
            checkUnknownFields(ipc, kSecIpcKeys, "sec.ipc");
            if (ipc["socket_path"]) {
                checkPath("sec.ipc.socket_path", ipc["socket_path"].as<std::string>());
            }
        }

        YAML::Node tls = sec["tls"];
        if (tls && tls.IsMap()) {
            checkUnknownFields(tls, kSecTlsKeys, "sec.tls");

            YAML::Node dev_peer = tls["dev_peer_service"];
            if (dev_peer) {
                if (isProduction()) {
                    error("profile.production_no_dev_peer", "sec.tls.dev_peer_service",
                          "production profile forbids sec.tls.dev_peer_service");
                }
                // dev_peer_service 是服务名而非文件路径，不做路径净化
            }

            YAML::Node profiles = tls["profiles"];
            if (profiles && profiles.IsMap()) {
                for (const auto& prof_kv : profiles) {
                    const std::string name = prof_kv.first.as<std::string>();
                    YAML::Node prof = prof_kv.second;
                    if (!prof.IsMap()) continue;
                    const std::string base = "sec.tls.profiles." + name;
                    checkUnknownFields(prof, kTlsProfileKeys, base);
                    if (prof["credential_id"]) {
                        // credential_id 是非秘密引用，仅校验非空
                        const std::string cid = prof["credential_id"].as<std::string>();
                        if (cid.empty()) {
                            warn("schema.required", base + ".credential_id",
                                 "credential_id should be non-empty");
                        }
                    }
                }
            }
        }
    }

    void checkCloud() {
        YAML::Node cloud = root_["cloud"];
        if (!cloud) return;
        if (!cloud.IsMap()) return;
        checkUnknownFields(cloud, kCloudKeys, "cloud");

        if (cloud["endpoint"]) {
            // endpoint 是非秘密 URL，不做文件路径净化
        }
        checkIntField(cloud, "cloud.timeout_ms", 1, 600000);
        checkIntField(cloud, "cloud.retry_count", 0, 100);
        checkIntField(cloud, "cloud.retry_delay_ms", 0, 600000);
    }

    void checkStorage() {
        YAML::Node storage = root_["storage"];
        if (!storage) return;
        if (!storage.IsMap()) return;
        checkUnknownFields(storage, kStorageKeys, "storage");

        checkPath("storage.state_file",
                  storage["state_file"] ? storage["state_file"].as<std::string>() : "");
        checkPath("storage.ca_cert",
                  storage["ca_cert"] ? storage["ca_cert"].as<std::string>() : "");
        checkPath("storage.cert_store",
                  storage["cert_store"] ? storage["cert_store"].as<std::string>() : "");
    }

    void checkEnvironment() {
        YAML::Node env = root_["environment"];
        if (!env) return;
        if (!env.IsMap()) return;
        checkUnknownFields(env, kEnvironmentKeys, "environment");

        YAML::Node prod = env["is_production"];
        if (prod) {
            if (!prod.IsScalar()) {
                error("schema.type", "environment.is_production",
                      "must be a boolean");
            }
        }
    }

    // 路径净化（无副作用，仅字符串检查）
    void checkPath(const std::string& field_path, const std::string& value) {
        if (value.empty()) return;  // 空表示使用默认，OK

        // .. 越界（两个 profile 都禁止）
        if (value.find("..") != std::string::npos) {
            error("path.no_traversal", field_path,
                  "path must not contain '..'");
            return;
        }

        // 个人目录（两个 profile 都禁止）
        if (value.find("~") != std::string::npos) {
            error("path.no_personal_dir", field_path,
                  "path must not reference personal/home directory");
            return;
        }

        if (isProduction()) {
            // production 要求绝对路径（或空）
            if (value[0] != '/') {
                error("path.production_absolute", field_path,
                      "production profile requires absolute path");
                return;
            }
            // build tree 启发式检测
            const std::string lower = toLower(value);
            if (lower.find("/build/") != std::string::npos ||
                lower.find("/cmake-build") != std::string::npos ||
                lower.find("/build-") != std::string::npos) {
                warn("path.no_build_tree", field_path,
                     "path references build tree (review before release)");
            }
        }
        // test profile 允许相对路径（如 ./data）
    }

    void checkIntField(const YAML::Node& parent, const std::string& field_path,
                       int min_val, int max_val) {
        YAML::Node n = parent[field_path.substr(field_path.find_last_of('.') + 1)];
        if (!n) return;
        if (!n.IsScalar()) {
            error("schema.type", field_path, "must be an integer");
            return;
        }
        try {
            int v = n.as<int>();
            if (v < min_val || v > max_val) {
                warn("schema.range", field_path,
                     "value out of recommended range");
            }
        } catch (const YAML::BadConversion&) {
            error("schema.type", field_path, "must be an integer");
        }
    }

    void checkUnknownFields(const YAML::Node& node, const std::set<std::string>& known,
                            const std::string& prefix) {
        if (!node.IsMap()) return;
        for (const auto& kv : node) {
            const std::string key = kv.first.as<std::string>();
            if (known.find(key) == known.end()) {
                warn("schema.unknown_field", prefix + "." + key,
                     "unknown field (not in schema)");
            }
        }
    }

    // 递归扫描秘密字段名（production error, test warn）
    void checkSecretFieldsRecursive(const YAML::Node& node,
                                    const std::string& path) {
        if (!node.IsMap()) return;
        for (const auto& kv : node) {
            const std::string key = kv.first.as<std::string>();
            const std::string child_path = path.empty() ? key : path + "." + key;
            const std::string lower_key = toLower(key);

            if (kForbiddenSecretFields.count(lower_key)) {
                if (isProduction()) {
                    error("profile.production_no_secret", child_path,
                          "production profile forbids secret-bearing field");
                } else {
                    warn("profile.test_no_secret", child_path,
                         "test profile: secret-bearing field should not be in config");
                }
            }
            checkSecretFieldsRecursive(kv.second, child_path);
        }
    }

    static std::string joinSet(const std::set<std::string>& s) {
        std::string result;
        for (const auto& v : s) {
            if (!result.empty()) result += ", ";
            result += v;
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// 用法
// ---------------------------------------------------------------------------
void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --check-config <path> --profile production|test\n"
              << "\nOptions:\n"
              << "  --check-config <path>   SEC config YAML file to validate\n"
              << "  --profile <name>        production | test\n"
              << "  --help                   Show this help\n"
              << "\nExit codes:\n"
              << "  0  pass (warnings allowed)\n"
              << "  1  validation failed (errors found)\n"
              << "  2  usage / parse error\n";
}

} // namespace

int main(int argc, char* argv[]) {
    std::string config_path;
    std::string profile_str;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return EXIT_PASS;
        } else if (arg == "--check-config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--profile" && i + 1 < argc) {
            profile_str = argv[++i];
        } else {
            std::cerr << "ERROR: unknown or incomplete argument: " << arg << "\n";
            printUsage(argv[0]);
            return EXIT_USAGE_ERROR;
        }
    }

    if (config_path.empty()) {
        std::cerr << "ERROR: --check-config is required\n";
        printUsage(argv[0]);
        return EXIT_USAGE_ERROR;
    }
    if (profile_str.empty()) {
        std::cerr << "ERROR: --profile is required\n";
        printUsage(argv[0]);
        return EXIT_USAGE_ERROR;
    }

    Profile profile;
    if (profile_str == "production") {
        profile = Profile::Production;
    } else if (profile_str == "test") {
        profile = Profile::Test;
    } else {
        std::cerr << "ERROR: --profile must be 'production' or 'test'\n";
        return EXIT_USAGE_ERROR;
    }

    ConfigChecker checker(config_path, profile);
    bool ok = checker.run();

    // 解析错误（文件不存在/不可解析）映射为 EXIT_USAGE_ERROR
    if (!ok && checker.findings().empty()) {
        // run() 已在 stderr 报告原因
        return EXIT_USAGE_ERROR;
    }

    checker.printReport();
    return ok ? EXIT_PASS : EXIT_VALIDATION_FAIL;
}

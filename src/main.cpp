#include <atomic>
#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include "sec_service.h"
#include "ipc_prov_service.h"
#include "config.h"
#include "store.h"
#include "sec_log_adapter.h"
#include "log_types.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

using namespace tbox::sec;

// 重定向 stdout/stderr 到日志系统
void redirect_stdio_to_log() {
    // 保存原始的 cout/cerr 缓冲区
    static std::streambuf* orig_cout = std::cout.rdbuf();
    static std::streambuf* orig_cerr = std::cerr.rdbuf();

    // 创建自定义缓冲区，将输出重定向到日志
    class LogBuf : public std::streambuf {
    public:
        LogBuf(std::streambuf* orig, bool is_err) : orig_(orig), is_err_(is_err) {}
    protected:
        int overflow(int c) override {
            if (c == '\n') {
                flush_line();
            } else {
                line_ += static_cast<char>(c);
            }
            return c;
        }
        int sync() override {
            flush_line();
            return 0;
        }
    private:
        void flush_line() {
            if (!line_.empty()) {
                if (is_err_) {
                    SecLogAdapter::ipc().error("sec.external.stderr", line_, {
                        {"source", tbox::fw::log::FieldValue::makeString(is_err_ ? "stderr" : "stdout")}
                    });
                } else {
                    SecLogAdapter::ipc().info("sec.external.stdout", line_, {
                        {"source", tbox::fw::log::FieldValue::makeString(is_err_ ? "stderr" : "stdout")}
                    });
                }
                line_.clear();
            }
        }
        std::streambuf* orig_;
        bool is_err_;
        std::string line_;
    };

    static LogBuf cout_log_buf(orig_cout, false);
    static LogBuf cerr_log_buf(orig_cerr, true);

    std::cout.rdbuf(&cout_log_buf);
    std::cerr.rdbuf(&cerr_log_buf);
}

std::shared_ptr<SecService> g_sec_service;
std::atomic<bool> g_running{true};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cerr << "\n[signal] received signal " << signal << ", requesting shutdown" << std::endl;
        g_running = false;
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    std::cout << "TBOX Security Service Starting..." << std::endl;

    // framework-log 初始化
    {
        tbox::fw::log::LogConfig logConfig;
        logConfig.level = tbox::fw::log::LogLevel::kInfo;
        logConfig.console_config.enabled = true;
        logConfig.format = "standard";

        // 从 common.log 读取配置
        auto& config_manager_init = hwyz::config::ConfigManager::instance();
        // 注意：这里需要先加载配置才能读取日志配置
        // 实际配置读取会在后面的配置加载完成后进行

        auto logResult = SecLogAdapter::init("sec", logConfig);
        if (logResult.error != tbox::fw::log::LogError::kOk) {
            // 严格模式失败，非严格模式继续（降级到 console + INFO）
            std::cerr << "[SEC] framework-log 初始化降级: " << logResult.error_message << std::endl;
            spdlog::warn("framework-log 初始化降级: {}", logResult.error_message);
        } else {
            // 覆盖 spdlog 默认 logger 为 "sec"
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_level(spdlog::level::debug);
            auto sec_logger = std::make_shared<spdlog::logger>("sec", console_sink);
            sec_logger->set_level(spdlog::level::debug);
            spdlog::set_default_logger(sec_logger);
        }
    }

    // 重定向 stdout/stderr 以捕获外部库输出
    redirect_stdio_to_log();

    // Logger 初始化成功事件
    SecLogAdapter::service().info(
        "sec.service.log_initialized",
        "SEC 日志系统初始化成功",
        {
            {"service", tbox::fw::log::FieldValue::makeString("sec")},
            {"sink_mode", tbox::fw::log::FieldValue::makeString("console")}
        }
    );

    std::string config_root = "/etc/tbox";
    
    // 多层配置查找：当前目录 -> config目录 -> 上级config目录 -> 系统目录
    if (argc > 1) {
        // 命令行参数优先
        config_root = argv[1];
    } else {
        // 检查当前目录是否有 common.yaml
        if (access("common.yaml", F_OK) == 0) {
            config_root = ".";
        }
        // 检查 config 目录
        else if (access("config/common.yaml", F_OK) == 0) {
            config_root = "config";
        }
        // 检查上级 config 目录（用于在 build 目录中运行）
        else if (access("../config/common.yaml", F_OK) == 0) {
            config_root = "../config";
        }
        // 否则使用默认系统目录 /etc/tbox
        else {
            config_root = "/etc/tbox";
        }
    }
    
    std::cout << "Using config root: " << config_root << std::endl;

    auto& config_manager = hwyz::config::ConfigManager::instance();
    auto config_result = config_manager.load("sec", config_root);
    if (config_result != hwyz::config::ConfigError::kOk) {
        std::cerr << "Failed to load configuration from: " << config_root << std::endl;
        std::cerr << "Error code: " << static_cast<uint32_t>(config_result) << std::endl;
        return 1;
    }

    auto config_snapshot = config_manager.getSnapshot();

    SecServiceConfig sec_config;
    sec_config.config_snapshot = config_snapshot;

    // Read IPC configuration from common.ipc.* and sec.ipc.*
    sec_config.ipc_config.max_frame_bytes = static_cast<uint32_t>(
        config_snapshot->getInt("common.ipc.max_frame_bytes", 10485760));
    sec_config.ipc_config.receive_timeout_ms = static_cast<uint32_t>(
        config_snapshot->getInt("common.ipc.receive_timeout_ms", 60000));
    sec_config.ipc_config.connect_timeout_ms = static_cast<uint32_t>(
        config_snapshot->getInt("common.ipc.connect_timeout_ms", 3000));
    sec_config.ipc_config.listen_backlog =
        config_snapshot->getInt("common.ipc.listen_backlog", 5);
    sec_config.ipc_config.reconnect.initial_backoff_ms = static_cast<uint32_t>(
        config_snapshot->getInt("common.ipc.reconnect.initial_backoff_ms", 100));
    sec_config.ipc_config.reconnect.max_backoff_ms = static_cast<uint32_t>(
        config_snapshot->getInt("common.ipc.reconnect.max_backoff_ms", 5000));
    sec_config.ipc_config.reconnect.multiplier =
        config_snapshot->getDouble("common.ipc.reconnect.multiplier", 2.0);
    sec_config.ipc_socket_path =
        config_snapshot->getString("sec.ipc.socket_path", "/tmp/tbox-sec.sock");

    std::string prov_socket_path = config_snapshot->getString("prov.socket_path", "/tmp/tbox-prov.sock");
    auto prov_service = std::make_shared<IpcProvService>(prov_socket_path);

    ErrorCode prov_result = prov_service->initialize();
    if (prov_result != ErrorCode::SUCCESS) {
        std::cerr << "Failed to connect to PROV service: "
                  << error_code_to_string(prov_result) << std::endl;
        std::cerr << "Please ensure PROV service is running at " << prov_socket_path << std::endl;
        return 1;
    }

    try {
        // Store root 必须与 HSM 侧一致（HsmFactory 使用 common.store.root），
        // 否则 TLS 材料/CA 证书会从错误的默认目录(/var/lib/tbox)读取而落空。
        std::string store_root = config_snapshot->getString("common.store.root", "/var/lib/tbox");
        auto store = hwyz::store::Store::open("sec", store_root);
        g_sec_service = std::make_shared<SecService>(sec_config, nullptr, prov_service, std::move(store));
        ErrorCode result = g_sec_service->initialize();

        if (result != ErrorCode::SUCCESS) {
            std::cerr << "Failed to initialize SEC service: "
                      << error_code_to_string(result) << std::endl;
            return 1;
        }

        std::cout << "TBOX Security Service initialized successfully" << std::endl;
        std::cout << g_sec_service->get_device_info() << std::endl;

        if (!g_sec_service->start_ipc_server()) {
            std::cerr << "Failed to start IPC server" << std::endl;
            return 1;
        }

        std::cout << "SEC service is ready to accept IPC connections" << std::endl;

        while (g_running) {
            sleep(1);
        }

        std::cout << "TBOX Security Service shutting down" << std::endl;
        g_sec_service->stop_ipc_server();

    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize SEC service: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

#pragma once

#include "log.h"
#include "log_types.h"
#include <string>

namespace tbox::sec {

class SecLogAdapter {
public:
    // 初始化日志系统（在 main.cpp 中调用一次）
    static tbox::fw::log::InitResult init(
        const std::string& service,
        const tbox::fw::log::LogConfig& config
    );

    // 获取各模块的 Logger 实例（CR-011 §4.1：service/provisioning/certificate/seed_key/tls_credential/ipc）
    static tbox::fw::log::Logger service();
    static tbox::fw::log::Logger provisioning();
    static tbox::fw::log::Logger certificate();
    static tbox::fw::log::Logger seed_key();
    static tbox::fw::log::Logger tls_credential();
    static tbox::fw::log::Logger ipc();

private:
    static bool s_initialized;
};

} // namespace tbox::sec

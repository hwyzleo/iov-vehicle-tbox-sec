#include "sec_log_adapter.h"

namespace tbox::sec {

bool SecLogAdapter::s_initialized = false;

tbox::fw::log::InitResult SecLogAdapter::init(
    const std::string& service,
    const tbox::fw::log::LogConfig& config
) {
    auto result = tbox::fw::log::Logger::init(service, config);
    if (result.error == tbox::fw::log::LogError::kOk) {
        s_initialized = true;
    }
    return result;
}

tbox::fw::log::Logger SecLogAdapter::service() {
    return tbox::fw::log::Logger::get("service");
}

tbox::fw::log::Logger SecLogAdapter::provisioning() {
    return tbox::fw::log::Logger::get("provisioning");
}

tbox::fw::log::Logger SecLogAdapter::certificate() {
    return tbox::fw::log::Logger::get("certificate");
}

tbox::fw::log::Logger SecLogAdapter::seed_key() {
    return tbox::fw::log::Logger::get("seed_key");
}

tbox::fw::log::Logger SecLogAdapter::tls_credential() {
    return tbox::fw::log::Logger::get("tls_credential");
}

tbox::fw::log::Logger SecLogAdapter::ipc() {
    return tbox::fw::log::Logger::get("ipc");
}

} // namespace tbox::sec

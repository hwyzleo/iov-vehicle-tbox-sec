#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "sec_log_adapter.h"
#include "ipc_protocol.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <chrono>

namespace tbox {
namespace sec {

namespace {

// FW-0305: JSON/base64 serialization failed
constexpr int32_t FW_SERIALIZATION_FAILED = 305;
// FW-0306: unknown method or request handler failed
constexpr int32_t FW_HANDLER_FAILED = 306;

std::string make_json_response(int32_t status, const nlohmann::json& payload) {
    nlohmann::json j = payload;
    j["status"] = status;
    return j.dump();
}

/// base64 编码 vector<uint8_t> -> string
std::string b64_encode(const std::vector<uint8_t>& data) {
    return ::hwyz::Utils::base64_encode(
        std::string(reinterpret_cast<const char*>(data.data()), data.size()));
}

/// base64 解码 string -> vector<uint8_t>
std::vector<uint8_t> b64_decode(const std::string& encoded) {
    std::string decoded = ::hwyz::Utils::base64_decode(encoded);
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

} // anonymous namespace

SecIpcDispatcher::SecIpcDispatcher(SecService* service)
    : service_(service) {
}

std::string SecIpcDispatcher::dispatch(uint32_t method_id,
                                       std::string_view params_json,
                                       int client_fd) {
    (void)client_fd;  // 当前无订阅需求，预留

    auto start = std::chrono::steady_clock::now();

    // IPC 日志只记录 method_id 和 payload_bytes，不记录原始 JSON
    SecLogAdapter::ipc().debug(
        "sec.ipc.dispatch",
        "Dispatching request",
        {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int>(method_id))),
         tbox::fw::log::Field("payload_bytes", tbox::fw::log::FieldValue::makeInt(static_cast<int>(params_json.size())))}
    );

    std::pair<int32_t, std::string> result{FW_HANDLER_FAILED, "{}"};

    try {
        switch (static_cast<ipc::MethodId>(method_id)) {
            case ipc::MethodId::INITIALIZE:
                result = handle_initialize();
                break;
            case ipc::MethodId::GENERATE_KEY_PAIR:
                result = handle_generate_key_pair();
                break;
            case ipc::MethodId::EXPORT_PRIVATE_KEY:
                result = handle_export_private_key();
                break;
            case ipc::MethodId::GET_CSR:
                result = handle_get_csr();
                break;
            case ipc::MethodId::SUBMIT_CSR:
                result = handle_submit_csr();
                break;
            case ipc::MethodId::INJECT_CERTIFICATE:
                result = handle_inject_certificate(params_json);
                break;
            case ipc::MethodId::APPLY_CERTIFICATE:
                result = handle_apply_certificate();
                break;
            case ipc::MethodId::SET_CA_CERTIFICATE:
                result = handle_set_ca_certificate(params_json);
                break;
            case ipc::MethodId::GET_SEED:
                result = handle_get_seed(params_json);
                break;
            case ipc::MethodId::VERIFY_KEY:
                result = handle_verify_key(params_json);
                break;
            case ipc::MethodId::GET_STATUS:
                result = handle_get_status();
                break;
            case ipc::MethodId::GET_DEVICE_INFO:
                result = handle_get_device_info();
                break;
            case ipc::MethodId::RESET_STATUS:
                result = handle_reset_status();
                break;
            default:
                SecLogAdapter::ipc().warn(
                    "sec.ipc.unknown_method",
                    "Unknown method ID",
                    {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int>(method_id)))}
                );
                result = {FW_HANDLER_FAILED, nlohmann::json({{"error", "Unknown method"}}).dump()};
                break;
        }
    } catch (const nlohmann::json::exception& e) {
        SecLogAdapter::ipc().error(
            "sec.ipc.json_error",
            "JSON serialization error in dispatch",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int>(method_id))),
             tbox::fw::log::Field("what", tbox::fw::log::FieldValue::makeString(e.what()))}
        );
        result = {FW_SERIALIZATION_FAILED, nlohmann::json({{"error", "JSON error"}}).dump()};
    } catch (const std::exception& e) {
        SecLogAdapter::ipc().error(
            "sec.ipc.dispatch_exception",
            "Exception in dispatch",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int>(method_id))),
             tbox::fw::log::Field("what", tbox::fw::log::FieldValue::makeString(e.what()))}
        );
        result = {FW_HANDLER_FAILED, nlohmann::json({{"error", "Internal error"}}).dump()};
    } catch (...) {
        SecLogAdapter::ipc().error(
            "sec.ipc.dispatch_exception",
            "Unknown exception in dispatch",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int>(method_id)))}
        );
        result = {FW_HANDLER_FAILED, nlohmann::json({{"error", "Unknown exception"}}).dump()};
    }

    auto end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // IPC 日志只记录 method_id、status、duration，不记录响应内容
    SecLogAdapter::ipc().debug(
        "sec.ipc.dispatched",
        "Request dispatched",
        {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int>(method_id))),
         tbox::fw::log::Field("status", tbox::fw::log::FieldValue::makeInt(result.first)),
         tbox::fw::log::Field("duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms))}
    );

    // 构建最终 JSON：payload + status 字段
    try {
        auto payload = nlohmann::json::parse(result.second);
        return make_json_response(result.first, payload);
    } catch (...) {
        return make_json_response(result.first, nlohmann::json({{"error", "Invalid response"}}));
    }
}

// ============================================================
// Method handlers
// ============================================================

std::pair<int32_t, std::string> SecIpcDispatcher::handle_initialize() {
    auto result = service_->initialize();
    nlohmann::json j;
    j["success"] = (result == ErrorCode::SUCCESS);
    return {static_cast<int32_t>(result), j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_generate_key_pair() {
    auto result = service_->generate_key_pair();
    nlohmann::json j;
    j["success"] = (result == ErrorCode::SUCCESS);
    return {static_cast<int32_t>(result), j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_export_private_key() {
    std::vector<uint8_t> priv_key;
    auto result = service_->export_private_key(priv_key);
    nlohmann::json j;
    if (result == ErrorCode::SUCCESS) {
        j["private_key"] = b64_encode(priv_key);
    } else {
        j["success"] = false;
    }
    return {static_cast<int32_t>(result), j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_csr() {
    std::vector<uint8_t> csr_der;
    auto result = service_->get_csr(csr_der);
    nlohmann::json j;
    if (result == ErrorCode::SUCCESS) {
        j["csr"] = b64_encode(csr_der);
    } else {
        j["success"] = false;
    }
    return {static_cast<int32_t>(result), j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_submit_csr() {
    auto result = service_->submit_csr();
    nlohmann::json j;
    j["success"] = (result == ErrorCode::SUCCESS);
    return {static_cast<int32_t>(result), j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_inject_certificate(std::string_view params) {
    try {
        auto j = nlohmann::json::parse(params);
        std::string cert_b64 = j.value("cert", "");
        if (cert_b64.empty()) {
            nlohmann::json resp;
            resp["success"] = false;
            resp["error"] = "Missing cert parameter";
            return {static_cast<int32_t>(ErrorCode::INVALID_PARAMETER), resp.dump()};
        }
        std::vector<uint8_t> cert_der = b64_decode(cert_b64);
        auto result = service_->inject_certificate(cert_der);
        nlohmann::json resp;
        resp["success"] = (result == ErrorCode::SUCCESS);
        return {static_cast<int32_t>(result), resp.dump()};
    } catch (const nlohmann::json::exception&) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "Invalid JSON";
        return {FW_SERIALIZATION_FAILED, resp.dump()};
    }
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_apply_certificate() {
    auto result = service_->apply_certificate();
    nlohmann::json j;
    j["success"] = (result == ErrorCode::SUCCESS);
    return {static_cast<int32_t>(result), j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_set_ca_certificate(std::string_view params) {
    try {
        auto j = nlohmann::json::parse(params);
        std::string ca_cert_b64 = j.value("cert", "");
        if (ca_cert_b64.empty()) {
            nlohmann::json resp;
            resp["success"] = false;
            resp["error"] = "Missing cert parameter";
            return {static_cast<int32_t>(ErrorCode::INVALID_PARAMETER), resp.dump()};
        }
        std::vector<uint8_t> ca_cert_der = b64_decode(ca_cert_b64);
        auto result = service_->set_ca_certificate(ca_cert_der);
        nlohmann::json resp;
        resp["success"] = (result == ErrorCode::SUCCESS);
        return {static_cast<int32_t>(result), resp.dump()};
    } catch (const nlohmann::json::exception&) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "Invalid JSON";
        return {FW_SERIALIZATION_FAILED, resp.dump()};
    }
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_seed(std::string_view params) {
    try {
        auto j = nlohmann::json::parse(params);
        uint8_t level = static_cast<uint8_t>(j.value("level", 0));
        std::vector<uint8_t> seed;
        auto result = service_->get_seed(level, seed);
        nlohmann::json resp;
        if (result == ErrorCode::SUCCESS) {
            resp["seed"] = b64_encode(seed);
        } else {
            resp["success"] = false;
        }
        return {static_cast<int32_t>(result), resp.dump()};
    } catch (const nlohmann::json::exception&) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "Invalid JSON";
        return {FW_SERIALIZATION_FAILED, resp.dump()};
    }
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_verify_key(std::string_view params) {
    try {
        auto j = nlohmann::json::parse(params);
        uint8_t level = static_cast<uint8_t>(j.value("level", 0));
        std::string key_b64 = j.value("key", "");
        if (key_b64.empty()) {
            nlohmann::json resp;
            resp["success"] = false;
            resp["error"] = "Missing key parameter";
            return {static_cast<int32_t>(ErrorCode::INVALID_PARAMETER), resp.dump()};
        }
        std::vector<uint8_t> key = b64_decode(key_b64);
        auto result = service_->verify_key(level, key);
        nlohmann::json resp;
        resp["success"] = (result == ErrorCode::SUCCESS);
        return {static_cast<int32_t>(result), resp.dump()};
    } catch (const nlohmann::json::exception&) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "Invalid JSON";
        return {FW_SERIALIZATION_FAILED, resp.dump()};
    }
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_status() {
    auto status = service_->get_provision_status();
    nlohmann::json j;
    j["vin"] = status.vin;
    j["ecu_uid"] = status.ecu_uid;
    j["state"] = provision_state_to_string(status.state);
    j["last_error"] = status.last_error;
    j["retry_count"] = status.retry_count;
    return {0, j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_device_info() {
    std::string info = service_->get_device_info();
    nlohmann::json j;
    j["device_info"] = info;
    return {0, j.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_reset_status() {
    auto result = service_->reset_provision_status();
    nlohmann::json j;
    j["success"] = (result == ErrorCode::SUCCESS);
    return {static_cast<int32_t>(result), j.dump()};
}

} // namespace sec
} // namespace tbox

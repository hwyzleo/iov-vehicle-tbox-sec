#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "sec_log_adapter.h"
#include "ipc_protocol.h"
#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "business_key_provisioning.h"
#include "tbox/sec/types.h"
#include "tbox/sec/business_key.h"
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

SecIpcDispatcher::~SecIpcDispatcher() = default;

void SecIpcDispatcher::setTlsCredentialProvider(TlsCredentialProvider* provider) {
    tls_provider_ = provider;
}

void SecIpcDispatcher::setBusinessKeyService(BusinessKeyProvisioningService* service) {
    business_key_service_ = service;
}

void SecIpcDispatcher::setPeerCredentialResolver(std::shared_ptr<PeerCredentialResolver> resolver) {
    peer_resolver_ = std::move(resolver);
}

void SecIpcDispatcher::setAddSubscriptionCallback(std::function<bool(int, uint32_t)> cb) {
    add_subscription_fn_ = std::move(cb);
}

PeerIdentity SecIpcDispatcher::resolvePeer(int client_fd) {
    if (peer_resolver_) {
        return peer_resolver_->resolve(client_fd);
    }
    // 无解析器时 fail-closed
    PeerIdentity identity;
    identity.valid = false;
    return identity;
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
            // TBOX-SEC-DSN-CR-016 §4.3: SET_CA_CERTIFICATE 写入口已移除。
            // MethodId 数值保留（wire/ABI 兼容）但不路由：旧调用落到 default
            // 返回未知方法并失败，不产生任何写入，不改变材料/版本/READY 状态。
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
            case ipc::MethodId::GET_TLS_CREDENTIAL:
                result = handle_get_tls_credential(params_json, client_fd);
                break;
            case ipc::MethodId::GET_TLS_CREDENTIAL_STATE:
                result = handle_get_tls_credential_state(params_json);
                break;
            case ipc::MethodId::SIGN_TLS:
                result = handle_sign_tls(params_json, client_fd);
                break;
            case ipc::MethodId::SUBSCRIBE_TLS_CREDENTIAL_CHANGED:
                result = handle_subscribe_tls_credential_changed(params_json, client_fd);
                break;
            case ipc::MethodId::GET_BUSINESS_KEY_STATUS:
                result = handle_get_business_key_status(params_json, client_fd);
                break;
            case ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS:
                result = handle_import_wrapped_business_keys(params_json, client_fd);
                break;
            case ipc::MethodId::GET_BUSINESS_KEY_IMPORT_RESULT:
                result = handle_get_business_key_import_result(params_json, client_fd);
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
    // 车辆绑定/个性化状态（PROV 权威来源），与上面的证书下发 state 区分。
    j["prov_state"] = device_provision_state_to_string(service_->get_device_binding_state());
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

// ============================================================
// TLS Credential Provider handlers (TBOX-SEC-DSN-CR-010)
// ============================================================

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_tls_credential(
        std::string_view params, int client_fd) {
    if (!tls_provider_) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "TLS provider not configured";
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    std::string profile = ipc::kTlsProfileMqtt;
    try {
        auto j = nlohmann::json::parse(params);
        profile = j.value("profile", ipc::kTlsProfileMqtt);
    } catch (...) {
        // 缺省 mqtt
    }

    PeerIdentity caller = resolvePeer(client_fd);
    if (!tls_provider_->isAuthorized(profile, caller)) {
        SecLogAdapter::ipc().warn(
            "sec.ipc.acl_denied",
            "TLS getTlsCredential ACL 拒绝",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(
                static_cast<int>(ipc::MethodId::GET_TLS_CREDENTIAL))),
             tbox::fw::log::Field("profile", tbox::fw::log::FieldValue::makeString(profile)),
             tbox::fw::log::Field("peer_valid", tbox::fw::log::FieldValue::makeInt(caller.valid))}
        );
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::ACL_DENIED), resp.dump()};
    }

    TlsCredentialBundle bundle;
    // 自愈：材料未就绪时按需解析 VIN/ECU_UID 并重载（避免启动时 PROV 未就绪导致永久 NOT_READY）
    if (service_) {
        service_->ensure_tls_material_ready(profile);
    }
    auto rc = tls_provider_->getTlsCredential(profile, caller, bundle);
    nlohmann::json resp;
    if (rc == ErrorCode::SUCCESS) {
        resp["credential_id"] = bundle.credential_id;
        resp["version"] = bundle.version;
        resp["root_ca_bundle"] = b64_encode(bundle.root_ca_bundle_der);
        resp["client_cert_chain"] = b64_encode(bundle.client_cert_chain_der);
        resp["private_key_ref"] = b64_encode(bundle.private_key_ref.data);
        resp["key_algorithm"] = key_algorithm_to_string(bundle.key_algorithm);
        resp["not_before"] = bundle.not_before;
        resp["not_after"] = bundle.not_after;
        resp["credential_status"] = tls_credential_status_to_string(bundle.status);
    } else {
        resp["success"] = false;
    }
    return {static_cast<int32_t>(rc), resp.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_tls_credential_state(
        std::string_view params) {
    if (!tls_provider_) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    std::string profile = ipc::kTlsProfileMqtt;
    try {
        auto j = nlohmann::json::parse(params);
        profile = j.value("profile", ipc::kTlsProfileMqtt);
    } catch (...) {
        // 缺省 mqtt
    }

    TlsCredentialState state;
    // 自愈：材料未就绪时按需解析 VIN/ECU_UID 并重载
    if (service_) {
        service_->ensure_tls_material_ready(profile);
    }
    auto rc = tls_provider_->getTlsCredentialState(profile, state);
    nlohmann::json resp;
    if (rc == ErrorCode::SUCCESS) {
        resp["credential_id"] = state.credential_id;
        resp["version"] = state.version;
        resp["credential_status"] = tls_credential_status_to_string(state.status);
        resp["reason_code"] = state.reason_code;
    } else {
        resp["success"] = false;
    }
    return {static_cast<int32_t>(rc), resp.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_sign_tls(
        std::string_view params, int client_fd) {
    if (!tls_provider_) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    TlsSignRequest req;
    std::string alg_str;
    try {
        auto j = nlohmann::json::parse(params);
        req.private_key_ref.data = b64_decode(j.value("private_key_ref", ""));
        alg_str = j.value("algorithm", "");
        req.algorithm = string_to_signature_algorithm(alg_str);
        req.digest = b64_decode(j.value("digest", ""));
        req.context = b64_decode(j.value("context", ""));
        req.request_id = j.value("request_id", "");
    } catch (const nlohmann::json::exception&) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "Invalid JSON";
        return {FW_SERIALIZATION_FAILED, resp.dump()};
    }

    PeerIdentity caller = resolvePeer(client_fd);
    std::vector<uint8_t> signature;
    auto rc = tls_provider_->signTls(req, caller, signature);
    nlohmann::json resp;
    if (rc == ErrorCode::SUCCESS) {
        resp["signature"] = b64_encode(signature);
    } else {
        resp["success"] = false;
    }
    // 安全清零临时签名缓冲
    std::fill(signature.begin(), signature.end(), 0);
    return {static_cast<int32_t>(rc), resp.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_subscribe_tls_credential_changed(
        std::string_view params, int client_fd) {
    if (!tls_provider_) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    std::string profile = ipc::kTlsProfileMqtt;
    try {
        auto j = nlohmann::json::parse(params);
        profile = j.value("profile", ipc::kTlsProfileMqtt);
    } catch (...) {
        // 缺省 mqtt
    }

    PeerIdentity caller = resolvePeer(client_fd);
    if (!tls_provider_->isAuthorized(profile, caller)) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::ACL_DENIED), resp.dump()};
    }

    if (!add_subscription_fn_ ||
        !add_subscription_fn_(client_fd, static_cast<uint32_t>(ipc::EventId::TLS_CREDENTIAL_CHANGED))) {
        nlohmann::json resp;
        resp["success"] = false;
        resp["error"] = "Subscription failed";
        return {static_cast<int32_t>(ErrorCode::INTERNAL_ERROR), resp.dump()};
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["event_type"] = static_cast<uint32_t>(ipc::EventId::TLS_CREDENTIAL_CHANGED);
    return {0, resp.dump()};
}

// ============================================================
// V2C 业务密钥 handlers (TBOX-SEC-DSN-CR-019)
// ============================================================

namespace {

nlohmann::json business_key_status_to_json(const BusinessKeyStatus& s) {
    nlohmann::json j;
    j["business_domain"] = s.business_domain;
    j["purpose"] = s.purpose;
    j["business_key_version"] = s.business_key_version;
    j["state"] = business_key_state_to_string(s.state);
    j["key_id_digest"] = s.key_id_digest;
    j["algorithm"] = s.algorithm;
    j["valid_from_ms"] = s.valid_from_ms;
    j["valid_to_ms"] = s.valid_to_ms;
    // TBOX-SEC-DSN-CR-020 §7/US-020：非敏感 ACK 绑定字段
    j["envelope_format"] = key_envelope_format_to_string(s.envelope_format);
    if (!s.envelope_digest.empty()) {
        j["envelope_digest"] = b64_encode(s.envelope_digest);
    }
    if (s.key_check_value_present) {
        j["key_check_value"] = b64_encode(std::vector<uint8_t>(s.key_check_value.begin(),
                                                               s.key_check_value.end()));
    }
    return j;
}

nlohmann::json import_result_to_json(const ImportResult& r) {
    nlohmann::json j;
    j["request_id"] = r.request_id;
    j["business_domain"] = r.business_domain;
    j["state"] = business_key_import_state_to_string(r.state);
    nlohmann::json items = nlohmann::json::array();
    for (const auto& s : r.items) items.push_back(business_key_status_to_json(s));
    j["items"] = items;
    j["committed_at_ms"] = r.committed_at_ms;
    j["provider_version_digest"] = r.provider_version_digest;
    if (!r.import_proof.empty()) {
        j["import_proof"] = b64_encode(std::vector<uint8_t>(
            r.import_proof.data(), r.import_proof.data() + r.import_proof.size()));
    }
    j["proof_algorithm"] = r.proof_algorithm;
    return j;
}

} // namespace

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_business_key_status(
        std::string_view params, int client_fd) {
    if (!business_key_service_) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    PeerIdentity caller = resolvePeer(client_fd);
    if (!caller.valid || caller.service_name != business_key_peer_service_) {
        SecLogAdapter::ipc().warn(
            "sec.ipc.acl_denied",
            "业务密钥状态查询 ACL 拒绝",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(
                 static_cast<int>(ipc::MethodId::GET_BUSINESS_KEY_STATUS))),
             tbox::fw::log::Field("peer_valid", tbox::fw::log::FieldValue::makeInt(caller.valid))});
        return {static_cast<int32_t>(ErrorCode::ACL_DENIED), nlohmann::json({
                    {"success", false}}).dump()};
    }

    std::string domain;
    std::vector<std::string> purposes;
    try {
        auto j = nlohmann::json::parse(params);
        domain = j.value("business_domain", std::string(kBusinessDomainV2c));
        if (j.contains("purposes") && j["purposes"].is_array()) {
            for (auto& p : j["purposes"]) purposes.push_back(p.get<std::string>());
        }
    } catch (const nlohmann::json::exception&) {
        return {FW_SERIALIZATION_FAILED, nlohmann::json({{"success", false}}).dump()};
    }
    if (purposes.empty()) {
        purposes = {kBusinessPurposeUplinkAead, kBusinessPurposeDownlinkAead};
    }

    BusinessKeyStatusSet set;
    ErrorCode rc = business_key_service_->getStatus(domain, purposes, set);
    nlohmann::json resp;
    if (rc == ErrorCode::SUCCESS) {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& s : set.items) items.push_back(business_key_status_to_json(s));
        resp["items"] = items;
    } else {
        resp["success"] = false;
    }
    return {static_cast<int32_t>(rc), resp.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_import_wrapped_business_keys(
        std::string_view params, int client_fd) {
    if (!business_key_service_) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    PeerIdentity caller = resolvePeer(client_fd);
    if (!caller.valid || caller.service_name != business_key_peer_service_) {
        SecLogAdapter::ipc().warn(
            "sec.ipc.acl_denied",
            "业务密钥导入 ACL 拒绝",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(
                 static_cast<int>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS))),
             tbox::fw::log::Field("peer_valid", tbox::fw::log::FieldValue::makeInt(caller.valid))});
        return {static_cast<int32_t>(ErrorCode::ACL_DENIED), nlohmann::json({
                    {"success", false}}).dump()};
    }

    std::string request_id, domain;
    std::vector<WrappedKeyItem> items;
    try {
        auto j = nlohmann::json::parse(params);
        request_id = j.value("request_id", "");
        domain = j.value("business_domain", std::string(kBusinessDomainV2c));
        if (j.contains("items") && j["items"].is_array()) {
            for (auto& ji : j["items"]) {
                WrappedKeyItem item;
                item.purpose = ji.value("purpose", "");
                item.key_id = ji.value("key_id", "");
                item.business_key_version = ji.value("business_key_version", 0ULL);
                item.algorithm = ji.value("algorithm", "");
                auto wk = b64_decode(ji.value("wrapped_key", ""));
                item.wrapped_key.assign(wk.data(), wk.size());
                std::fill(wk.begin(), wk.end(), 0);
                auto prm = b64_decode(ji.value("parameters", ""));
                item.parameters.assign(prm.data(), prm.size());
                std::fill(prm.begin(), prm.end(), 0);
                item.valid_from_ms = ji.value("valid_from_ms", 0LL);
                item.valid_to_ms = ji.value("valid_to_ms", 0LL);
                item.wrapping_suite = ji.value("wrapping_suite", "");
                item.envelope_format =
                    string_to_key_envelope_format(ji.value("envelope_format", "UNSPECIFIED"));
                auto ed = b64_decode(ji.value("envelope_digest", ""));
                item.envelope_digest.assign(ed.begin(), ed.end());
                auto kcv = b64_decode(ji.value("key_check_value", ""));
                if (kcv.size() == 3) {
                    item.key_check_value = {kcv[0], kcv[1], kcv[2]};
                    item.key_check_value_present = true;
                }
                items.push_back(std::move(item));
            }
        }
    } catch (const nlohmann::json::exception&) {
        return {FW_SERIALIZATION_FAILED, nlohmann::json({{"success", false}}).dump()};
    }

    ImportResult result;
    ErrorCode rc = business_key_service_->import(request_id, domain, items, result);
    // 调用方 buffer 已移交，立即清零
    for (auto& it : items) {
        it.wrapped_key.clear();
        it.parameters.clear();
    }
    nlohmann::json resp = import_result_to_json(result);
    if (rc != ErrorCode::SUCCESS) resp["success"] = false;
    return {static_cast<int32_t>(rc), resp.dump()};
}

std::pair<int32_t, std::string> SecIpcDispatcher::handle_get_business_key_import_result(
        std::string_view params, int client_fd) {
    if (!business_key_service_) {
        nlohmann::json resp;
        resp["success"] = false;
        return {static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED), resp.dump()};
    }
    PeerIdentity caller = resolvePeer(client_fd);
    if (!caller.valid || caller.service_name != business_key_peer_service_) {
        return {static_cast<int32_t>(ErrorCode::ACL_DENIED), nlohmann::json({
                    {"success", false}}).dump()};
    }

    std::string request_id;
    try {
        auto j = nlohmann::json::parse(params);
        request_id = j.value("request_id", "");
    } catch (const nlohmann::json::exception&) {
        return {FW_SERIALIZATION_FAILED, nlohmann::json({{"success", false}}).dump()};
    }

    ImportResult result;
    ErrorCode rc = business_key_service_->getImportResult(request_id, result);
    nlohmann::json resp = import_result_to_json(result);
    if (rc != ErrorCode::SUCCESS) resp["success"] = false;
    return {static_cast<int32_t>(rc), resp.dump()};
}

} // namespace sec
} // namespace tbox

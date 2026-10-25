#include "tbox/sec/client.h"
#include "sec_retry_policy.h"
#include "ipc_protocol.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstring>

#include "ipc.h"
#include <memory>

namespace tbox {
namespace sec {

// ============================================================
// SecClient::Impl
// ============================================================
class SecClient::Impl {
public:
    explicit Impl(const std::string& socket_path)
        : socket_path_(socket_path),
          fw_client_(std::make_unique<::tbox::fw::ipc::Client>(socket_path_)) {
    }

    ~Impl() {
        disconnect();
    }

    bool connect() {
        return fw_client_->connect();
    }

    void disconnect() {
        fw_client_->disconnect();
    }

    bool is_connected() const {
        return fw_client_->is_connected();
    }

    /// Send request and receive response
    /// @return (ok, biz_status_code, response_json)
    std::tuple<bool, int32_t, std::string>
    send_request(uint32_t method_id, const std::string& params_json) {
        // SecRetryPolicy: decide whether to allow auto-retry
        bool retry_allowed = SecRetryPolicy::should_retry(method_id);

        std::pair<int32_t, std::string> result;
        if (retry_allowed) {
            result = fw_client_->call(method_id, params_json);
        } else {
            // callOnce: no auto-retry, transport failure = unknown outcome
            result = fw_client_->callOnce(method_id, params_json);
        }

        auto [fw_status, response_json] = result;

        if (fw_status < 0) {
            // Client transport error
            // For non-retryable methods: unknown outcome (server may have executed)
            return {false, 0, ""};
        }

        if (fw_status > 0) {
            // Server transport/handler error (FW-03xx)
            return {false, 0, ""};
        }

        // fw_status == 0: transport success, extract business status from JSON
        int32_t biz_status = 0;
        try {
            auto j = nlohmann::json::parse(response_json);
            biz_status = j.value("status", 0);
        } catch (...) {
            // JSON parse failure, keep biz_status = 0
        }
        return {true, biz_status, response_json};
    }

    /// base64 encode for framework mode (uses framework Utils)
    std::string b64_encode(const std::vector<uint8_t>& data) {
        return ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(data.data()), data.size()));
    }

    /// base64 decode for framework mode
    std::vector<uint8_t> b64_decode(const std::string& encoded) {
        std::string decoded = ::hwyz::Utils::base64_decode(encoded);
        return std::vector<uint8_t>(decoded.begin(), decoded.end());
    }

    /// 订阅包装（framework Client::subscribe 使用独立连接）
    ::tbox::fw::ipc::Subscription subscribe(uint32_t method_id,
                                             uint32_t event_type,
                                             ::tbox::fw::ipc::EventCallback cb) {
        return fw_client_->subscribe(method_id, event_type, std::move(cb));
    }

private:
    std::string socket_path_;
    std::unique_ptr<::tbox::fw::ipc::Client> fw_client_;
};

// ============================================================
// SecClient facade
// ============================================================

SecClient::SecClient(const std::string& socket_path)
    : impl_(std::make_unique<Impl>(socket_path)) {
}

SecClient::~SecClient() = default;

bool SecClient::connect() {
    return impl_->connect();
}

void SecClient::disconnect() {
    impl_->disconnect();
}

bool SecClient::is_connected() const {
    return impl_->is_connected();
}

ErrorCode SecClient::initialize() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::INITIALIZE), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::generate_key_pair() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GENERATE_KEY_PAIR), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::export_private_key(std::vector<uint8_t>& private_key) {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::EXPORT_PRIVATE_KEY), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;

    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string priv_b64 = j.value("private_key", "");
            private_key = impl_->b64_decode(priv_b64);
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::get_csr(std::vector<uint8_t>& csr_der) {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_CSR), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;

    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string csr_b64 = j.value("csr", "");
            csr_der = impl_->b64_decode(csr_b64);
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::submit_csr() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::SUBMIT_CSR), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::inject_certificate(const std::vector<uint8_t>& cert_der) {
    nlohmann::json params;
    params["cert"] = impl_->b64_encode(cert_der);
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::apply_certificate() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::APPLY_CERTIFICATE), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::get_seed(uint8_t level, std::vector<uint8_t>& seed) {
    nlohmann::json params;
    params["level"] = level;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_SEED), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;

    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string seed_b64 = j.value("seed", "");
            seed = impl_->b64_decode(seed_b64);
            // Security: clear temporary sensitive buffer after use
            // (seed_b64 is local, will be destructed)
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::verify_key(uint8_t level, const std::vector<uint8_t>& key) {
    nlohmann::json params;
    params["level"] = level;
    params["key"] = impl_->b64_encode(key);
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

SecProvisionStatus SecClient::get_provision_status() {
    SecProvisionStatus status;
    auto [ok, biz_status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_STATUS), "{}");
    if (!ok) return status;

    try {
        auto j = nlohmann::json::parse(response_json);
        status.vin = j.value("vin", "");
        status.ecu_uid = j.value("ecu_uid", "");
        status.state = j.value("state", "NONE");
        status.last_error = j.value("last_error", "");
        status.retry_count = j.value("retry_count", 0);
    } catch (const std::exception&) {
        // Return default status
    }
    return status;
}

std::string SecClient::get_device_info() {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_DEVICE_INFO), "{}");
    if (!ok) return "";

    try {
        auto j = nlohmann::json::parse(response_json);
        return j.value("device_info", "");
    } catch (const std::exception&) {
        return "";
    }
}

ErrorCode SecClient::reset_provision_status() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::RESET_STATUS), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

// ============================================================
// MQTT TLS Credential Provider（TBOX-SEC-DSN-CR-010）
// ============================================================

ErrorCode SecClient::get_tls_credential(const std::string& profile,
                                        TlsCredentialBundle& bundle) {
    nlohmann::json params;
    params["profile"] = profile;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    if (status != 0) return static_cast<ErrorCode>(status);

    try {
        auto j = nlohmann::json::parse(response_json);
        bundle.credential_id = j.value("credential_id", "");
        bundle.version = j.value("version", 0ULL);
        bundle.root_ca_bundle_der = impl_->b64_decode(j.value("root_ca_bundle", ""));
        bundle.client_cert_chain_der = impl_->b64_decode(j.value("client_cert_chain", ""));
        bundle.private_key_ref.data = impl_->b64_decode(j.value("private_key_ref", ""));
        bundle.key_algorithm = string_to_key_algorithm(j.value("key_algorithm", ""));
        bundle.not_before = j.value("not_before", 0LL);
        bundle.not_after = j.value("not_after", 0LL);
        bundle.status = string_to_tls_credential_status(j.value("credential_status", "NOT_READY"));
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::INTERNAL_ERROR;
    }
}

ErrorCode SecClient::get_tls_credential_state(const std::string& profile,
                                              TlsCredentialState& state) {
    nlohmann::json params;
    params["profile"] = profile;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL_STATE), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    if (status != 0) return static_cast<ErrorCode>(status);

    try {
        auto j = nlohmann::json::parse(response_json);
        state.credential_id = j.value("credential_id", "");
        state.version = j.value("version", 0ULL);
        state.status = string_to_tls_credential_status(j.value("credential_status", "NOT_READY"));
        state.reason_code = j.value("reason_code", 0);
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::INTERNAL_ERROR;
    }
}

ErrorCode SecClient::sign_tls(const TlsSignRequest& request,
                              std::vector<uint8_t>& signature) {
    nlohmann::json params;
    params["private_key_ref"] = impl_->b64_encode(request.private_key_ref.data);
    params["algorithm"] = signature_algorithm_to_string(request.algorithm);
    params["digest"] = impl_->b64_encode(request.digest);
    if (!request.context.empty()) {
        params["context"] = impl_->b64_encode(request.context);
    }
    params["request_id"] = request.request_id;

    // SIGN_TLS 禁止自动重放：send_request 内部根据 retry policy 使用 callOnce
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::SIGN_TLS), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    if (status != 0) return static_cast<ErrorCode>(status);

    try {
        auto j = nlohmann::json::parse(response_json);
        signature = impl_->b64_decode(j.value("signature", ""));
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::INTERNAL_ERROR;
    }
}

// 订阅句柄实现：持有 framework Subscription 以维持独立连接生命周期
struct TlsCredentialSubscription::Impl {
    bool active = false;
    std::function<void(const TlsCredentialChangedEvent&)> callback;
    ::tbox::fw::ipc::Subscription fw_sub;
};

TlsCredentialSubscription::TlsCredentialSubscription(std::shared_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
TlsCredentialSubscription::~TlsCredentialSubscription() { cancel(); }
TlsCredentialSubscription::TlsCredentialSubscription(TlsCredentialSubscription&&) noexcept = default;
TlsCredentialSubscription& TlsCredentialSubscription::operator=(TlsCredentialSubscription&&) noexcept = default;
void TlsCredentialSubscription::cancel() {
    if (impl_) {
        impl_->active = false;
        impl_->fw_sub.cancel();
        impl_.reset();
    }
}
bool TlsCredentialSubscription::isActive() const {
    return impl_ && impl_->active;
}

TlsCredentialSubscription SecClient::subscribe_tls_credential_changed(
        const std::string& profile,
        std::function<void(const TlsCredentialChangedEvent&)> callback) {
    auto sub_impl = std::make_shared<TlsCredentialSubscription::Impl>();
    sub_impl->active = true;
    sub_impl->callback = std::move(callback);
    (void)profile;  // framework subscribe 不支持传 params，server 缺省 mqtt

    // 订阅使用独立 framework-ipc 连接（SUBSCRIBE 握手后进入 event-only）
    // profile 由 server 端缺省为 mqtt（framework subscribe 不支持传 params）
    sub_impl->fw_sub = impl_->subscribe(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TLS_CREDENTIAL_CHANGED),
        static_cast<uint32_t>(ipc::EventId::TLS_CREDENTIAL_CHANGED),
        [sub_impl](uint32_t event_type, std::string_view payload_json) {
            (void)event_type;
            if (!sub_impl->active || !sub_impl->callback) return;
            try {
                auto j = nlohmann::json::parse(payload_json);
                TlsCredentialChangedEvent ev;
                ev.profile = j.value("profile", "");
                ev.credential_id = j.value("credential_id", "");
                ev.version = j.value("version", 0ULL);
                ev.status = string_to_tls_credential_status(j.value("status", "NOT_READY"));
                ev.reason_code = j.value("reason_code", 0);
                sub_impl->callback(ev);
            } catch (const std::exception&) {
                // 忽略畸形事件
            }
        });

    return TlsCredentialSubscription(sub_impl);
}

// ============================================================
// V2C 业务密钥开通（TBOX-SEC-DSN-CR-019）
// ============================================================

namespace {

void business_key_status_from_json(
    const nlohmann::json& j, BusinessKeyStatus& s,
    const std::function<std::vector<uint8_t>(const std::string&)>& dec) {
    s.business_domain = j.value("business_domain", "");
    s.purpose = j.value("purpose", "");
    s.business_key_version = j.value("business_key_version", 0ULL);
    s.state = string_to_business_key_state(j.value("state", "UNKNOWN"));
    s.key_id = j.value("key_id", "");
    s.key_id_digest = j.value("key_id_digest", "");
    s.algorithm = j.value("algorithm", "");
    s.valid_from_ms = j.value("valid_from_ms", 0LL);
    s.valid_to_ms = j.value("valid_to_ms", 0LL);
    s.envelope_format = string_to_key_envelope_format(j.value("envelope_format", "UNSPECIFIED"));
    if (j.contains("envelope_digest")) {
        s.envelope_digest = dec(j.value("envelope_digest", ""));
    }
    if (j.contains("key_check_value")) {
        auto kcv = dec(j.value("key_check_value", ""));
        if (kcv.size() == 3) {
            s.key_check_value = {kcv[0], kcv[1], kcv[2]};
            s.key_check_value_present = true;
        }
    }
    if (j.contains("import_proof")) {
        s.import_proof = dec(j.value("import_proof", ""));
    }
    s.proof_algorithm = j.value("proof_algorithm", "");
    if (j.contains("recipient_certificate_digest")) {
        s.recipient_certificate_digest = dec(j.value("recipient_certificate_digest", ""));
    }
}

void import_result_from_json(const nlohmann::json& j, ImportResult& out,
                             const std::function<std::vector<uint8_t>(const std::string&)>& dec) {
    out.request_id = j.value("request_id", "");
    out.business_domain = j.value("business_domain", "");
    // TBOX-SEC-DSN-CR-021 §4：数值(state_code) + 稳定字符串(state) additive 编码。
    //   - 已知且一致 → 采用；未知数值/字符串、数值/字符串冲突、缺失 state → UNKNOWN
    //     （禁止默认零值）；
    //   - 旧 SEC 响应无 state_code → 仅按稳定字符串映射，不得从错误文本/空字段/
    //     版本推断 NOT_FOUND。
    out.state = BusinessKeyImportState::UNKNOWN;
    const bool has_code =
        j.contains("state_code") && j["state_code"].is_number_unsigned();
    const bool has_str = j.contains("state") && j["state"].is_string();
    if (!has_code) {
        if (has_str) {
            out.state =
                string_to_business_key_import_state(j["state"].get<std::string>());
        }
    } else {
        const BusinessKeyImportState code_state =
            import_state_from_code(j["state_code"].get<uint32_t>());
        if (!has_str) {
            out.state = BusinessKeyImportState::UNKNOWN;  // 缺失 state → UNKNOWN
        } else {
            const BusinessKeyImportState str_state =
                string_to_business_key_import_state(j["state"].get<std::string>());
            out.state = (code_state == str_state) ? code_state
                                                  : BusinessKeyImportState::UNKNOWN;
        }
    }
    out.items.clear();
    if (j.contains("items") && j["items"].is_array()) {
        for (const auto& ji : j["items"]) {
            BusinessKeyStatus s;
            business_key_status_from_json(ji, s, dec);
            out.items.push_back(std::move(s));
        }
    }
    out.committed_at_ms = j.value("committed_at_ms", 0LL);
    out.provider_version_digest = j.value("provider_version_digest", "");
    if (j.contains("import_proof")) {
        auto proof = dec(j.value("import_proof", ""));
        out.import_proof.assign(proof.data(), proof.size());
        std::fill(proof.begin(), proof.end(), 0);
    }
    out.proof_algorithm = j.value("proof_algorithm", "");
    if (j.contains("binding_certificate_digest")) {
        out.binding_certificate_digest = dec(j.value("binding_certificate_digest", ""));
    }
}

} // namespace

ErrorCode SecClient::get_business_key_status(const std::string& business_domain,
                                             const std::vector<std::string>& purposes,
                                             BusinessKeyStatusSet& out) {
    nlohmann::json params;
    params["business_domain"] = business_domain;
    params["purposes"] = purposes;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_STATUS), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    out.items.clear();
    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            if (j.contains("items") && j["items"].is_array()) {
                for (const auto& ji : j["items"]) {
                    BusinessKeyStatus s;
                    business_key_status_from_json(ji, s,
                        [this](const std::string& v) { return impl_->b64_decode(v); });
                    out.items.push_back(std::move(s));
                }
            }
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::import_wrapped_business_keys(const std::string& request_id,
                                                  const std::string& business_domain,
                                                  const std::vector<WrappedKeyItem>& items,
                                                  ImportResult& out) {
    nlohmann::json params;
    params["request_id"] = request_id;
    params["business_domain"] = business_domain;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& item : items) {
        nlohmann::json e;
        e["purpose"] = item.purpose;
        e["key_id"] = item.key_id;
        e["business_key_version"] = item.business_key_version;
        e["algorithm"] = item.algorithm;
        e["wrapped_key"] = impl_->b64_encode(std::vector<uint8_t>(
            item.wrapped_key.data(), item.wrapped_key.data() + item.wrapped_key.size()));
        e["parameters"] = impl_->b64_encode(std::vector<uint8_t>(
            item.parameters.data(), item.parameters.data() + item.parameters.size()));
        e["valid_from_ms"] = item.valid_from_ms;
        e["valid_to_ms"] = item.valid_to_ms;
        e["wrapping_suite"] = item.wrapping_suite;
        e["envelope_format"] = key_envelope_format_to_string(item.envelope_format);
        if (!item.envelope_digest.empty()) {
            e["envelope_digest"] = impl_->b64_encode(item.envelope_digest);
        }
        if (item.key_check_value_present) {
            e["key_check_value"] = impl_->b64_encode(std::vector<uint8_t>(
                item.key_check_value.begin(), item.key_check_value.end()));
        }
        arr.push_back(e);
    }
    params["items"] = arr;

    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::IMPORT_WRAPPED_BUSINESS_KEYS), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    out = ImportResult{};
    out.request_id = request_id;
    if (status == 0 || status == static_cast<int32_t>(ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN) ||
        status == static_cast<int32_t>(ErrorCode::BUSINESS_KEY_OUTCOME_UNKNOWN)) {
        try {
            auto j = nlohmann::json::parse(response_json);
            import_result_from_json(j, out, [&](const std::string& s) {
                return impl_->b64_decode(s);
            });
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    } else if (!response_json.empty()) {
        // 确定性拒绝（BUSINESS_KEY_UNSUPPORTED/NOT_READY 等）时 SEC IPC 同样返回
        // 权威 result JSON（含 state=FAILED）；解析后调用方才能正确分类，避免被
        // 误判为“结果未知可重试”导致无限重发（现场：VMD key_algorithm 不符）。
        // 非 result 响应（ACL/参数错误仅 {"success":false}）保持默认 UNKNOWN。
        try {
            auto j = nlohmann::json::parse(response_json);
            if (j.contains("state")) {
                import_result_from_json(j, out, [&](const std::string& s) {
                    return impl_->b64_decode(s);
                });
            }
        } catch (const std::exception&) {
            // 解析失败：保持 UNKNOWN（fail-closed 由调用方分类）。
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::get_business_key_import_result(const std::string& request_id,
                                                    ImportResult& out) {
    nlohmann::json params;
    params["request_id"] = request_id;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_BUSINESS_KEY_IMPORT_RESULT), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    out = ImportResult{};
    out.request_id = request_id;
    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            import_result_from_json(j, out, [&](const std::string& s) {
                return impl_->b64_decode(s);
            });
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    } else if (!response_json.empty()) {
        // 同 import_wrapped_business_keys：确定性错误响应同样携带权威 result，
        // 尽力解析出 state（失败保持 UNKNOWN，fail-closed 由调用方分类）。
        try {
            auto j = nlohmann::json::parse(response_json);
            if (j.contains("state")) {
                import_result_from_json(j, out, [&](const std::string& s) {
                    return impl_->b64_decode(s);
                });
            }
        } catch (const std::exception&) {
            // 解析失败：保持 UNKNOWN。
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::get_v2c_key_provisioning_capability(
        V2cKeyProvisioningCapability& out) {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_V2C_KEY_PROVISIONING_CAPABILITY), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    out = V2cKeyProvisioningCapability{};
    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            out.capability_contract_version =
                j.value("capability_contract_version", 0u);
            // TBOX-SEC-DSN-CR-020 §11 修订：版本不匹配（旧服务 v1 或未知版本）
            // fail-closed —— 仅保留收到的版本号，其余字段全为默认 false，
            // 使 all()==false（新 Keyprov 不可用），禁止把旧结构解释为 ECDH-ES READY。
            if (out.capability_contract_version !=
                V2cKeyProvisioningCapability::kContractVersion) {
                return ErrorCode::BUSINESS_KEY_NOT_READY;
            }
            out.envelope_v1_import_ready = j.value("envelope_v1_import_ready", false);
            out.atomic_dual_purpose_commit_ready =
                j.value("atomic_dual_purpose_commit_ready", false);
            out.import_proof_sign_ecdsa_p256_v1_ready =
                j.value("import_proof_sign_ecdsa_p256_v1_ready", false);
            out.secure_journal_replay_ready =
                j.value("secure_journal_replay_ready", false);
            out.identity_key_template_sign_derive =
                j.value("identity_key_template_sign_derive", false);
            out.csr_key_usage_request_matched =
                j.value("csr_key_usage_request_matched", false);
            out.certificate_profile_matched =
                j.value("certificate_profile_matched", false);
            out.certificate_chain_and_key_match =
                j.value("certificate_chain_and_key_match", false);
            out.certificate_critical_extensions_allowed =
                j.value("certificate_critical_extensions_allowed", false);
            out.leaf_certificate_digest_bound =
                j.value("leaf_certificate_digest_bound", false);
            out.proto_release_matched = j.value("proto_release_matched", false);
            out.envelope_format_v1 = j.value("envelope_format_v1", false);
            out.p256_ecdh = j.value("p256_ecdh", false);
            out.hkdf_sha256 = j.value("hkdf_sha256", false);
            out.aes256_gcm_decrypt_to_slot =
                j.value("aes256_gcm_decrypt_to_slot", false);
            out.atomic_dual_slot_commit = j.value("atomic_dual_slot_commit", false);
            out.active_certificate_key_agreement =
                j.value("active_certificate_key_agreement", false);
            out.active_certificate_digital_signature =
                j.value("active_certificate_digital_signature", false);
            out.active_private_key_can_derive =
                j.value("active_private_key_can_derive", false);
            out.active_private_key_can_sign =
                j.value("active_private_key_can_sign", false);
            out.ecdsa_p256_sha256_p1363 = j.value("ecdsa_p256_sha256_p1363", false);
            out.secure_journal_ready = j.value("secure_journal_ready", false);
            out.trusted_time_ready = j.value("trusted_time_ready", false);
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

} // namespace sec
} // namespace tbox

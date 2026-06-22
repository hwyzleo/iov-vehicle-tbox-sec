#include "diag_service_interface.h"
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>

namespace tbox {
namespace sec {

class DiagServiceAdapter : public DiagServiceInterface {
public:
    DiagServiceAdapter();
    ~DiagServiceAdapter() override;

    ErrorCode initialize() override;

    ErrorCode send_request(DiagRequestType request_type,
                          const std::vector<uint8_t>& request_data,
                          DiagResponseCallback callback) override;

    ErrorCode send_request_sync(DiagRequestType request_type,
                               const std::vector<uint8_t>& request_data,
                               DiagResponse& response) override;

    bool is_connected() const override;

    std::string get_service_status() const override;

private:
    bool initialized_;
    bool connected_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<DiagResponse> response_queue_;

    DiagResponse process_request_internal(DiagRequestType request_type,
                                         const std::vector<uint8_t>& request_data);
};

DiagServiceAdapter::DiagServiceAdapter()
    : initialized_(false), connected_(false) {}

DiagServiceAdapter::~DiagServiceAdapter() = default;

ErrorCode DiagServiceAdapter::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);

    initialized_ = true;
    connected_ = true;

    return ErrorCode::SUCCESS;
}

ErrorCode DiagServiceAdapter::send_request(DiagRequestType request_type,
                                          const std::vector<uint8_t>& request_data,
                                          DiagResponseCallback callback) {
    if (!initialized_ || !connected_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    std::thread([this, request_type, request_data, callback]() {
        DiagResponse response = process_request_internal(request_type, request_data);
        if (callback) {
            callback(response);
        }
    }).detach();

    return ErrorCode::SUCCESS;
}

ErrorCode DiagServiceAdapter::send_request_sync(DiagRequestType request_type,
                                               const std::vector<uint8_t>& request_data,
                                               DiagResponse& response) {
    if (!initialized_ || !connected_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    response = process_request_internal(request_type, request_data);
    return ErrorCode::SUCCESS;
}

bool DiagServiceAdapter::is_connected() const {
    return connected_;
}

std::string DiagServiceAdapter::get_service_status() const {
    if (!initialized_) {
        return "Not initialized";
    }
    if (!connected_) {
        return "Disconnected";
    }
    return "Connected";
}

DiagResponse DiagServiceAdapter::process_request_internal(DiagRequestType request_type,
                                                         const std::vector<uint8_t>& request_data) {
    DiagResponse response;

    switch (request_type) {
        case DiagRequestType::GENERATE_KEY_PAIR:
            response.error_code = ErrorCode::SUCCESS;
            response.data = {0x01};
            break;

        case DiagRequestType::READ_CSR:
            response.error_code = ErrorCode::SUCCESS;
            response.data = {0x30, 0x82, 0x01, 0x00};
            break;

        case DiagRequestType::INJECT_CERTIFICATE:
            response.error_code = ErrorCode::SUCCESS;
            response.data = {0x01};
            break;

        case DiagRequestType::READ_PROVISION_STATE:
            response.error_code = ErrorCode::SUCCESS;
            response.data = {0x00};
            break;

        default:
            response.error_code = ErrorCode::INVALID_PARAMETER;
            response.error_message = "Unknown request type";
            break;
    }

    return response;
}

} // namespace sec
} // namespace tbox

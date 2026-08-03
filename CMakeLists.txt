# TBox SEC - TBOX 安全服务
#
# TBOX-SEC-DSN-CR-012: 接入 TBOX-BUILD 统一 Orin aarch64 构建。
#   - 不设置 CMAKE_C_COMPILER / CMAKE_CXX_COMPILER / CMAKE_SYSROOT（由 BUILD
#     toolchain/preset 注入；正式 Orin 入口归属 tbox-build/ci/build-in-docker.sh）
#   - framework / PROV 通过已安装 package 消费（find_package + targets），
#     禁止 add_subdirectory、源码/私有头文件、build-tree library 或绝对库路径
#   - GNUInstallDirs + 两个显式 install component: sec-sdk / sec-runtime
#   - 仅 HOST 开发构建在本项目执行；本文件不维护交叉编译入口

cmake_minimum_required(VERSION 3.16)
project(tbox_sec VERSION 0.1.0 LANGUAGES C CXX)

# --- C/C++ 标准（toolchain/preset 可能已设置；不覆盖 Orin preset） ---
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()
if(NOT CMAKE_C_STANDARD)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ===========================================================================
# 依赖：framework SDK + PROV client SDK + OpenSSL + nlohmann_json + CURL
# ===========================================================================

# --- Framework SDK (config/store/log/ipc/application) ---
# 本地开发：framework 仓库 scripts/tbox-env.sh 设置 TBoxFramework_DIR / CMAKE_PREFIX_PATH
# BUILD 交叉编译：orin-aarch64 toolchain 从 TBOX_SDK_STAGING 设置 CMAKE_PREFIX_PATH
# 幂等保护：兄弟项目以 add_subdirectory 引入时跳过重复 find_package
if(NOT TARGET TBoxFramework::config)
    find_package(TboxFramework CONFIG REQUIRED)
endif()

# --- PROV client SDK（已安装 package；只通过 tbox::prov_client 消费） ---
find_package(TboxProvClient CONFIG REQUIRED)

# --- OpenSSL（sysroot 或显式 TARGET 依赖；TboxFrameworkConfig 亦已 find_dependency） ---
find_package(OpenSSL REQUIRED)

# --- nlohmann_json（SEC 直接使用；BUILD: TBOX_DEP_STAGING；本地: conan） ---
find_package(nlohmann_json REQUIRED)

# --- CURL（SEC 直接 TARGET 依赖：cloud_client 证书注入/CSR 提交） ---
# 静态链接(lock.yaml linkage: static)：curl 的 CURLConfig.cmake 会经 CURL::libcurl
# 传递 OpenSSL/ZLIB;若 find_package 回退到 module-mode FindCURL 则不会传播 zlib,
# 故显式 find ZLIB 并链接,保证静态 curl 的 -lz 符号可解析。
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)

# --- GTest（仅 HOST 单元测试；BUILD 目标构建不提供） ---
find_package(GTest QUIET)

# ===========================================================================
# Daemon library (TboxSecLib) — 内部库，不安装
# ===========================================================================
set(LIB_SOURCES
    src/sec_service.cpp
    src/key_engine.cpp
    src/hsm_interface.cpp
    src/soft_file_hsm.cpp
    src/secure_storage.cpp
    src/csr_builder.cpp
    src/cert_validator.cpp
    src/cloud_client.cpp
    src/error_codes.cpp
    src/diag_service_adapter.cpp
    src/service_dispatcher.cpp
    src/sec_log_adapter.cpp
    src/sec_ipc_dispatcher.cpp
    src/sec_retry_policy.cpp
    src/tls_credential_provider.cpp
    src/peer_credential.cpp
    src/ipc_prov_service.cpp
    src/sec_application.cpp
)

add_library(TboxSecLib STATIC ${LIB_SOURCES})
target_include_directories(TboxSecLib PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_options(TboxSecLib PRIVATE -Wall -g)

# TBoxFramework:: 组件 targets 携带 include 路径与传递依赖，无需手动 INCLUDE_DIRS。
# tbox::prov_client 同样只携带其公开 facade 头文件。
target_link_libraries(TboxSecLib
    PUBLIC
        TBoxFramework::config
        TBoxFramework::store
        TBoxFramework::log
        TBoxFramework::ipc
        TBoxFramework::application
        tbox::prov_client
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
        ZLIB::ZLIB
)

# ===========================================================================
# Client SDK library (tbox_sec_client / tbox::sec_client)
# ===========================================================================
set(CLIENT_SOURCES
    src/sec_client.cpp
    src/sec_retry_policy.cpp
    src/error_codes.cpp
)

add_library(tbox_sec_client STATIC ${CLIENT_SOURCES})
add_library(tbox::sec_client ALIAS tbox_sec_client)
set_target_properties(tbox_sec_client PROPERTIES EXPORT_NAME sec_client)
# 供下游服务将静态 SDK 链入自身 .so 时使用
set_target_properties(tbox_sec_client PROPERTIES POSITION_INDEPENDENT_CODE ON)

# PUBLIC: only business facade/DTO headers (no framework IPC leakage to callers)
target_include_directories(tbox_sec_client
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# PRIVATE: framework-ipc (传输细节不泄漏给调用方) + framework-application
# (sec_client 内部使用 hwyz::Utils::base64_*，符号随静态库归档) + nlohmann_json
target_link_libraries(tbox_sec_client
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE
        TBoxFramework::ipc
        TBoxFramework::application
)

# ===========================================================================
# Main executable (daemon)
# ===========================================================================
# TBOX-SEC-DSN-CR-011 §9.1: 迁移期构建期二选一；同一二进制只能含一套入口/信号/
# Logger/IPC/HSM 生命周期。验收后删除 OFF 路径与开关（CR-011 阶段 3）。
option(SEC_USE_FRAMEWORK_APPLICATION "Use hwyz::Application lifecycle" ON)
if(SEC_USE_FRAMEWORK_APPLICATION)
    add_executable(tbox_sec src/main.cpp)
else()
    add_executable(tbox_sec src/main_legacy.cpp)
endif()
target_link_libraries(tbox_sec PRIVATE TboxSecLib)

# ===========================================================================
# Install rules — 两个显式 component (CR-012 §9 / BD7)
#
#   sec-sdk     -> staging: sdk      (公开头文件 / client 静态库 / CMake package)
#   sec-runtime -> staging: rootfs   (daemon / systemd unit / 非秘密默认配置)
# ===========================================================================

# --- sec-runtime: daemon binary ---
install(TARGETS tbox_sec
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT sec-runtime
)

# --- sec-runtime: systemd unit ---
install(FILES packaging/systemd/tbox-sec.service
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
    COMPONENT sec-runtime
)

# --- sec-runtime: 默认非秘密配置模板（生产 fail-closed，不含测试材料） ---
install(FILES config/sec.default.yaml
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/tbox/conf.d
    RENAME sec.yaml
    COMPONENT sec-runtime
)

# --- sec-sdk: public headers ---
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/tbox/sec/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tbox/sec
    COMPONENT sec-sdk
    FILES_MATCHING PATTERN "*.h"
)

# --- sec-sdk: client static library + export ---
install(TARGETS tbox_sec_client
    EXPORT TboxSecClientTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT sec-sdk
)

install(EXPORT TboxSecClientTargets
    FILE TboxSecClientTargets.cmake
    NAMESPACE tbox::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxSecClient
    COMPONENT sec-sdk
)

# --- sec-sdk: CMake package config (relocatable) ---
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TboxSecClientConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TboxSecClientConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxSecClient
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/TboxSecClientConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TboxSecClientConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/TboxSecClientConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxSecClient
    COMPONENT sec-sdk
)

# ===========================================================================
# Tests (HOST only; BUILD 目标构建仅构建 declared targets，不编译测试)
# ===========================================================================
if(GTest_FOUND)
    enable_testing()

    set(TEST_SOURCES
        tests/test_key_engine.cpp
        tests/test_csr_builder.cpp
        tests/test_cert_validator.cpp
        tests/test_sec_service.cpp
        tests/test_sec_service_with_diag.cpp
        tests/test_hsm_interface.cpp
        tests/test_diag_service_interface.cpp
        tests/test_seed_key.cpp
        tests/test_service_dispatcher.cpp
        tests/test_soft_file_hsm.cpp
        tests/test_key_provisioning_mode.cpp
        tests/test_subject_dn.cpp
        tests/test_show_csr.cpp
        tests/test_config_snapshot.cpp
        tests/test_framework_integration.cpp
        tests/test_device_identity.cpp
        tests/test_sec_log_adapter.cpp
        tests/test_sec_log_events.cpp
        tests/test_sec_log_context.cpp
        tests/test_sec_log_redaction.cpp
        tests/test_sec_log_fault.cpp
        tests/test_sec_log_security.cpp
        tests/test_sec_retry_policy.cpp
        tests/test_sec_ipc_dispatcher.cpp
        tests/test_tls_credential_provider.cpp
        tests/test_tls_ipc_handlers.cpp
        tests/test_tls_integration.cpp
        tests/test_sec_application.cpp
    )
    add_executable(TboxSecTests ${TEST_SOURCES})
    target_link_libraries(TboxSecTests PRIVATE TboxSecLib tbox_sec_client GTest::GTest GTest::gmock GTest::Main)
    add_test(NAME TboxSecTests COMMAND TboxSecTests)
endif()

# ===========================================================================
# CLI tool for testing (IPC client；不安装，仅 HOST 开发/验证用)
# ===========================================================================
add_executable(sec_cli src/sec_cli.cpp)
target_link_libraries(sec_cli PRIVATE tbox_sec_client OpenSSL::Crypto)

cmake_minimum_required(VERSION 3.10)
project(TboxSecService)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_definitions("-Wall -lpthread -g")

include(GNUInstallDirs)

# ============================================================
# Build options
# ============================================================

# Platform-specific library directories
if (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    if (APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/arm64-apple-darwin)
    elseif (UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/aarch64-linux-gnu)
    endif ()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    if (APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-apple-darwin)
    elseif (UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-linux-gnu)
    endif ()
endif ()

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# fmt (required by spdlog)
find_package(fmt REQUIRED)

# YAML-CPP
find_package(yaml-cpp REQUIRED)
include_directories(${YAML_CPP_INCLUDE_DIRS})
add_definitions(-DUSE_YAML_CPP)

# Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# nlohmann_json
find_package(nlohmann_json REQUIRED)

# CURL
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})

# Framework (hwyz) - config, store, log, ipc
set(FRAMEWORK_DIR ${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-framework)
if(EXISTS ${FRAMEWORK_DIR}/include)
    set(FRAMEWORK_INCLUDE_DIR ${FRAMEWORK_DIR}/include)
    message(STATUS "Found framework include at: ${FRAMEWORK_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "Framework not found at: ${FRAMEWORK_DIR}")
endif()

# Find framework library
find_library(FRAMEWORK_LIB tbox-framework PATHS ${FRAMEWORK_DIR}/build NO_DEFAULT_PATH)
if(NOT FRAMEWORK_LIB)
    message(FATAL_ERROR "Framework library not found in ${FRAMEWORK_DIR}/build")
endif()

# PROV project - for IPC client (ProvClient)
set(PROV_DIR ${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-prov)
if(EXISTS ${PROV_DIR}/include)
    set(PROV_INCLUDE_DIR ${PROV_DIR}/include)
    message(STATUS "Found PROV include at: ${PROV_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "PROV project not found at: ${PROV_DIR}")
endif()

# Find PROV client library
find_library(PROV_CLIENT_LIB tbox_prov_client PATHS ${PROV_DIR}/build NO_DEFAULT_PATH)
if(NOT PROV_CLIENT_LIB)
    message(FATAL_ERROR "ProvClient library not found in ${PROV_DIR}/build")
endif()

# Find PROV daemon library (for ProvLogAdapter symbols used by prov_client)
find_library(PROV_DAEMON_LIB TboxProvLib PATHS ${PROV_DIR}/build NO_DEFAULT_PATH)

# ============================================================
# Daemon library (TboxSecLib)
# ============================================================
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
)

list(APPEND LIB_SOURCES
    src/sec_ipc_dispatcher.cpp
    src/sec_retry_policy.cpp
)

add_library(TboxSecLib STATIC ${LIB_SOURCES})
target_include_directories(TboxSecLib PUBLIC ${PROJECT_SOURCE_DIR}/include ${FRAMEWORK_INCLUDE_DIR})
target_link_libraries(TboxSecLib PUBLIC OpenSSL::SSL OpenSSL::Crypto yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json CURL::libcurl)

# ============================================================
# Client SDK library (tbox_sec_client / tbox::sec_client)
# ============================================================
set(CLIENT_SOURCES
    src/sec_client.cpp
    src/sec_retry_policy.cpp
    src/error_codes.cpp
)

add_library(tbox_sec_client STATIC ${CLIENT_SOURCES})
add_library(tbox::sec_client ALIAS tbox_sec_client)

# PUBLIC: only business facade/DTO headers
target_include_directories(tbox_sec_client
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# PRIVATE: framework-ipc link and internal headers
target_link_libraries(tbox_sec_client
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE ${FRAMEWORK_LIB}
)
target_include_directories(tbox_sec_client PRIVATE ${FRAMEWORK_INCLUDE_DIR})

# Install public SDK headers
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/tbox/sec/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tbox/sec
    FILES_MATCHING PATTERN "*.h"
)

# Install client library
install(TARGETS tbox_sec_client
    EXPORT TboxSecClientTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Export CMake config
install(EXPORT TboxSecClientTargets
    FILE TboxSecClientTargets.cmake
    NAMESPACE tbox::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxSecClient
)

# CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TboxSecClientConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TboxSecClientConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxSecClient
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TboxSecClientConfig.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxSecClient
)

# ============================================================
# Main executable
# ============================================================
add_executable(tbox_sec src/main.cpp src/ipc_prov_service.cpp)
target_include_directories(tbox_sec PRIVATE ${PROV_INCLUDE_DIR})
target_link_libraries(tbox_sec PRIVATE TboxSecLib ${FRAMEWORK_LIB} ${PROV_CLIENT_LIB} ${PROV_DAEMON_LIB} fmt::fmt)

# ============================================================
# Tests
# ============================================================
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
)
add_executable(TboxSecTests ${TEST_SOURCES})
target_link_libraries(TboxSecTests PRIVATE TboxSecLib tbox_sec_client ${FRAMEWORK_LIB} GTest::GTest GTest::gmock GTest::Main)
add_test(NAME TboxSecTests COMMAND TboxSecTests)

# Example program
add_executable(GenerateKeysAndCsr examples/generate_keys_and_csr.cpp)
target_link_libraries(GenerateKeysAndCsr PRIVATE TboxSecLib ${FRAMEWORK_LIB})

# CLI tool for testing (IPC client)
add_executable(sec_cli src/sec_cli.cpp)
target_link_libraries(sec_cli PRIVATE tbox_sec_client OpenSSL::Crypto)

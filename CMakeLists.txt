cmake_minimum_required(VERSION 3.10)
project(TboxSecService)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_definitions("-Wall -lpthread -g")

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

# Library source files (without main.cpp)
set(LIB_SOURCES
    src/sec_service.cpp
    src/key_engine.cpp
    src/hsm_interface.cpp
    src/soft_file_hsm.cpp
    src/secure_storage.cpp
    src/csr_builder.cpp
    src/cert_validator.cpp
    src/cloud_client.cpp
    src/provision_state.cpp
    src/error_codes.cpp
    src/diag_service_adapter.cpp
    src/service_dispatcher.cpp
)

# Static library for other modules to link against
add_library(TboxSecLib STATIC ${LIB_SOURCES})
target_include_directories(TboxSecLib PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(TboxSecLib PUBLIC OpenSSL::SSL OpenSSL::Crypto yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json CURL::libcurl)

# Main executable
add_executable(TboxSecService src/main.cpp)
target_link_libraries(TboxSecService PRIVATE TboxSecLib)

# Tests
enable_testing()
add_executable(TboxSecTests
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
)
target_link_libraries(TboxSecTests PRIVATE TboxSecLib GTest::GTest GTest::Main)
add_test(NAME TboxSecTests COMMAND TboxSecTests)

# Example program
add_executable(GenerateKeysAndCsr examples/generate_keys_and_csr.cpp)
target_link_libraries(GenerateKeysAndCsr PRIVATE TboxSecLib)

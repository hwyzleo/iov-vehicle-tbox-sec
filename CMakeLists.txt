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

# Framework (hwyz) - config and store
set(FRAMEWORK_DIR ${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-framework)
if(EXISTS ${FRAMEWORK_DIR}/include)
    set(FRAMEWORK_INCLUDE_DIR ${FRAMEWORK_DIR}/include)
    message(STATUS "Found framework include at: ${FRAMEWORK_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "Framework not found at: ${FRAMEWORK_DIR}")
endif()

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
    src/error_codes.cpp
    src/diag_service_adapter.cpp
    src/service_dispatcher.cpp
)

# Static library for other modules to link against
add_library(TboxSecLib STATIC ${LIB_SOURCES})
target_include_directories(TboxSecLib PUBLIC ${PROJECT_SOURCE_DIR}/include ${FRAMEWORK_INCLUDE_DIR})
target_link_libraries(TboxSecLib PUBLIC OpenSSL::SSL OpenSSL::Crypto yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json CURL::libcurl)

# Main executable
add_executable(TboxSecService src/main.cpp)

# Find framework library properly
find_library(FRAMEWORK_LIB hwyz PATHS ${FRAMEWORK_DIR}/build NO_DEFAULT_PATH)
if(NOT FRAMEWORK_LIB)
    message(FATAL_ERROR "Framework library not found in ${FRAMEWORK_DIR}/build")
endif()
target_link_libraries(TboxSecService PRIVATE TboxSecLib ${FRAMEWORK_LIB})

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
    tests/test_subject_dn.cpp
    tests/test_show_csr.cpp
    tests/test_config_snapshot.cpp
)
target_link_libraries(TboxSecTests PRIVATE TboxSecLib GTest::GTest GTest::Main)
add_test(NAME TboxSecTests COMMAND TboxSecTests)

# Example program
add_executable(GenerateKeysAndCsr examples/generate_keys_and_csr.cpp)
target_link_libraries(GenerateKeysAndCsr PRIVATE TboxSecLib)

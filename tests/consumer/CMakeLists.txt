# TBOX-SEC-DSN-CR-012 §13.1/TBOX-FW-DSN-CR-010 §11.2: 独立 installed-package consumer。
#
# 验证安装后的 TboxSecClient package（而非 build tree / 源码）可被外部消费方
# find_package + 链接，且 tbox::sec_client 公开接口不泄漏 framework IPC 细节。
#
# 用法（HOST 开发验证）：
#   cmake -S tests/consumer -B build-consumer \
#       -DCMAKE_PREFIX_PATH=<sec-sdk install prefix>
#   cmake --build build-consumer
cmake_minimum_required(VERSION 3.16)
project(tbox_sec_consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(TboxSecClient CONFIG REQUIRED)

add_executable(sec_consumer main.cpp)
target_link_libraries(sec_consumer PRIVATE tbox::sec_client)

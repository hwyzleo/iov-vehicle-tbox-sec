#!/bin/bash

# TBOX SEC Service Build Script

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查依赖
check_dependencies() {
    print_info "Checking dependencies..."
    
    # 检查CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake is not installed"
        exit 1
    fi
    
    # 检查Conan（可选）
    if ! command -v conan &> /dev/null; then
        print_warn "Conan is not installed, will use system dependencies"
        USE_CONAN=false
    else
        USE_CONAN=true
    fi
    
    print_info "All dependencies are available"
}

# 安装依赖
install_dependencies() {
    print_info "Installing dependencies..."
    
    # 创建构建目录
    mkdir -p build
    cd build
    
    # 安装依赖
    if [ "$USE_CONAN" = true ]; then
        print_info "Using Conan for dependencies..."
        conan install .. --output-folder=. --build=missing
        CMAKE_PRESET="conan-release"
    else
        print_info "Using system dependencies..."
        CMAKE_PRESET=""
    fi
    
    cd ..
}

# 构建项目
build_project() {
    local build_type=${1:-Debug}
    print_info "Building project (${build_type})..."
    
    cd build
    
    # 配置CMake
    if [ "$USE_CONAN" = true ] && [ -n "$CMAKE_PRESET" ]; then
        cmake .. --preset $CMAKE_PRESET
    else
        cmake .. -DCMAKE_BUILD_TYPE=$build_type
    fi
    
    # 构建
    cmake --build . --config $build_type
    
    cd ..
}

# 运行测试
run_tests() {
    print_info "Running tests..."
    
    cd build
    
    # 运行测试
    ctest --output-on-failure
    
    cd ..
}

# 清理构建
clean_build() {
    print_info "Cleaning build directory..."
    
    rm -rf build/*
}

# 显示帮助
show_help() {
    echo "TBOX SEC Service Build Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  build     Build the project (Debug)"
    echo "  release   Build the project (Release)"
    echo "  test      Build and run tests"
    echo "  clean     Clean build directory"
    echo "  install   Install dependencies only"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build      # Build in Debug mode"
    echo "  $0 release    # Build in Release mode"
    echo "  $0 test       # Build and run tests"
    echo "  $0 clean      # Clean build directory"
}

# 主函数
main() {
    # 检查依赖
    check_dependencies
    
    case "${1:-build}" in
        build)
            install_dependencies
            build_project Debug
            ;;
        release)
            install_dependencies
            build_project Release
            ;;
        test)
            install_dependencies
            build_project Debug
            run_tests
            ;;
        clean)
            clean_build
            ;;
        install)
            install_dependencies
            ;;
        help)
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    
    print_info "Build completed successfully"
}

# 执行主函数
main "$@"

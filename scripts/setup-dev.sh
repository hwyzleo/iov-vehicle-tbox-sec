#!/bin/bash
# Setup development environment on macOS (HOST-only)
#
# TBOX-SEC-DSN-CR-012: SEC 不维护交叉编译 toolchain/sysroot/容器入口；
# Orin 交叉构建由 TBOX-BUILD 仓库统一管理。本脚本只准备 HOST 开发依赖。
set -e

echo "=== Setting up TBOX Sec Development Environment ==="

# Install dependencies via Homebrew
echo "Installing dependencies..."
brew install cmake openssl yaml-cpp curl nlohmann-json googletest

# Install Conan (optional)
read -p "Install Conan package manager? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip3 install conan
fi

# Make scripts executable
chmod +x scripts/*.sh tests/smoke/*.sh

echo ""
echo "=== Setup Complete ==="
echo "HOST 开发构建：./scripts/build.sh"
echo "Orin 正式构建入口归属 TBOX-BUILD：tbox-build/ci/build-in-docker.sh"

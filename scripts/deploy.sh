#!/bin/bash
# TBOX Security Service Deployment Script
# Usage: ./scripts/deploy.sh [target_ip] [target_user]

set -e

TARGET_IP=${1:-"192.168.1.100"}
TARGET_USER=${2:-"root"}
TARGET_DIR="/opt/tbox-sec"
BUILD_DIR="build-aarch64"
BINARY="TboxSecService"

echo "=== TBOX Security Service Deployment ==="
echo "Target: ${TARGET_USER}@${TARGET_IP}:${TARGET_DIR}"

# Step 1: Cross compile
echo ""
echo "Step 1: Cross compiling for aarch64..."
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

# Use Conan for dependency management if available
if command -v conan &> /dev/null; then
    conan install .. --profile:host profiles/aarch64-linux-gnu --output-folder=. --build=missing
fi

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=../toolchain-aarch64-linux-gnu.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local

make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
cd ..

echo "Build successful: ${BUILD_DIR}/${BINARY}"

# Step 2: Deploy to target
echo ""
echo "Step 2: Deploying to target..."

# Create target directory
ssh ${TARGET_USER}@${TARGET_IP} "mkdir -p ${TARGET_DIR}/{config,lib}"

# Copy binary
scp ${BUILD_DIR}/${BINARY} ${TARGET_USER}@${TARGET_IP}:${TARGET_DIR}/

# Copy config
scp config/config.yaml ${TARGET_USER}@${TARGET_IP}:${TARGET_DIR}/config/

# Copy shared libraries (if needed)
if [ -d "${BUILD_DIR}/lib" ]; then
    scp -r ${BUILD_DIR}/lib/* ${TARGET_USER}@${TARGET_IP}:${TARGET_DIR}/lib/
fi

# Step 3: Install service
echo ""
echo "Step 3: Installing systemd service..."
scp scripts/tbox-sec.service ${TARGET_USER}@${TARGET_IP}:/etc/systemd/system/
ssh ${TARGET_USER}@${TARGET_IP} "systemctl daemon-reload && systemctl enable tbox-sec"

echo ""
echo "=== Deployment Complete ==="
echo "To start: ssh ${TARGET_USER}@${TARGET_IP} 'systemctl start tbox-sec'"
echo "To check: ssh ${TARGET_USER}@${TARGET_IP} 'systemctl status tbox-sec'"

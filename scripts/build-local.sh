#!/bin/bash
# Local build script for development and testing
set -e

BUILD_DIR="build"
CMAKE_PRESET=${1:-"default"}

echo "=== TBOX Security Service Local Build ==="

# Create build directory
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

# Configure
echo "Configuring..."
if [ "$CMAKE_PRESET" = "conan" ]; then
    # Use Conan for dependencies
    conan install .. --output-folder=. --build=missing
    cmake .. --preset conan-release
else
    # Use system dependencies
    cmake .. -DCMAKE_BUILD_TYPE=Debug
fi

# Build
echo "Building..."
make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc)

# Run tests if requested
if [ "$2" = "--test" ]; then
    echo "Running tests..."
    ctest --output-on-failure
fi

echo ""
echo "=== Build Complete ==="
echo "Binary: ${BUILD_DIR}/TboxSecService"
echo "Tests:  ${BUILD_DIR}/TboxSecTests"

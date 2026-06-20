#!/bin/bash
# Setup development environment on macOS
set -e

echo "=== Setting up TBOX Sec Development Environment ==="

# Install dependencies via Homebrew
echo "Installing dependencies..."
brew install cmake openssl yaml-cpp curl nlohmann-json googletest

# Install cross-compilation tools (optional)
read -p "Install cross-compilation tools for aarch64? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing cross-compilation tools..."
    brew install aarch64-elf-gcc
fi

# Install Conan (optional)
read -p "Install Conan package manager? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip3 install conan
fi

# Make scripts executable
chmod +x scripts/*.sh

echo ""
echo "=== Setup Complete ==="
echo "To build: ./scripts/build-local.sh"
echo "To test:  ./scripts/build-local.sh default --test"

# TBOX Security Service

TBOX (Telematics Box) Security Service for production line security identity initialization.

## Overview

This service handles the complete security identity initialization flow for TBOX devices during production:

1. **Key Pair Generation**: Generate ECDSA P-256 key pair in secure element (HSM)
2. **CSR Creation**: Build PKCS#10 Certificate Signing Request with device identifiers
3. **Certificate Application**: Submit CSR to PKI via cloud API (OAPI)
4. **Certificate Injection**: Validate and install certificate on device

## Features

- Private keys never leave secure element (HSM/SE)
- UDS diagnostic interface (ISO 14229)
- Cloud communication via OAPI (10805)
- Provision state management
- Error handling and retry logic
- Configurable via YAML

## Building

### Prerequisites

- C++17 compiler
- CMake 3.10+
- OpenSSL 1.1+
- yaml-cpp
- libcurl
- nlohmann-json
- Google Test (for tests)

### Quick Start (macOS)

```bash
# Setup development environment
./scripts/setup-dev.sh

# Build and test
./scripts/build-local.sh default --test
```

### Build Commands

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
ctest  # Run tests
```

### Cross Compilation (for TBOX ARM Linux)

```bash
# Option 1: Using Docker (recommended)
docker build -f Dockerfile.cross -t tbox-sec-builder .
docker run --rm -v $(pwd)/output:/output tbox-sec-builder

# Option 2: Using toolchain
mkdir build-aarch64 && cd build-aarch64
cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-aarch64-linux-gnu.cmake
make -j$(nproc)
```

## Deployment

See `docs/deployment.md` for detailed deployment instructions.

### Quick Deploy

```bash
# Deploy to TBOX
./scripts/deploy.sh 192.168.1.100 root

# Start service
ssh root@192.168.1.100 "systemctl start tbox-sec"

# Check status
ssh root@192.168.1.100 "systemctl status tbox-sec"
```

## Configuration

Edit `config/config.yaml` to configure:

- Device identifiers (VIN, ECU UID)
- HSM/Secure Element settings
- Cloud API endpoints
- UDS parameters
- Certificate settings

## Usage

### Production Line Flow

1. Security workstation establishes UDS session
2. Perform security access (0x29)
3. Trigger key pair generation (RoutineControl)
4. Read CSR (ReadDataByIdentifier)
5. Submit CSR to PKI via MES/OAPI
6. Inject certificate (WriteDataByIdentifier)
7. Verify certificate installation

### Diagnostic Commands

See `docs/diagnostic.md` for detailed diagnostic procedures.

## API Documentation

See `docs/api.md` for complete API documentation.

## Architecture

```
+---------------+     +---------------+     +---------------+
|   UDS         |     |   SEC         |     |   Cloud       |
|  Handler      |---->|  Service      |---->|   Client      |
+---------------+     +---------------+     +---------------+
                           |
                           v
                    +---------------+
                    |   Key         |
                    |  Engine       |
                    +---------------+
                           |
                           v
                    +---------------+
                    |   HSM         |
                    | Interface     |
                    +---------------+
```

## License

[License information]

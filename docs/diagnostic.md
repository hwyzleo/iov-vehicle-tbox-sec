# TBOX Security Diagnostic Procedures

## Overview

This document describes diagnostic procedures for the TBOX Security Service. With the implementation of TBOX-SEC-DSN-CR-002, the SEC module now consumes DIAG service interfaces rather than directly handling UDS protocol.

## DIAG Service Architecture

The SEC service now uses `DiagServiceInterface` to interact with diagnostic services. This change:
- Separates SEC logic from UDS protocol handling
- Enables easier testing with mock DIAG services
- Provides a standard interface for diagnostic operations

### DiagRequestType

| Type | Description |
|------|-------------|
| `GENERATE_KEY_PAIR` | Generate device key pair |
| `READ_CSR` | Read Certificate Signing Request |
| `SUBMIT_CSR` | Submit CSR to PKI |
| `INJECT_CERTIFICATE` | Inject certificate into device |
| `READ_PROVISION_STATE` | Read current provision state |
| `GET_SEED` | Generate 16-byte random seed for SecurityAccess |
| `VERIFY_KEY` | Verify key using AES-128 algorithm |

## Prerequisites

- UDS diagnostic tool with security access capability
- Valid security certificates
- Access to production line network

## Diagnostic Sessions

### Default Session (0x01)
- Basic diagnostic operations
- No security access required

### Extended Session (0x03)
- Advanced diagnostic operations
- Security access required for sensitive operations

## Security Access

### Level 0x29
Required for:
- Key pair generation
- CSR reading
- Certificate injection
- Provision state reading

### Procedure
1. Request seed: `29 29`
2. Receive seed from device
3. Calculate key using security algorithm
4. Send key: `29 2A [key]`
5. Receive positive response: `69 2A 01`

## Diagnostic Operations

### Read Provision State
**Request:** `22 F1 00`
**Response:** `62 F1 00 [state]`

**States:**
- `00`: NONE
- `01`: KEY_GENERATED
- `02`: CSR_BUILT
- `03`: CSR_SUBMITTED
- `04`: CERT_INSTALLED
- `05`: FAILED

### Generate Key Pair
**Request:** `31 01 FF 00`
**Response:** `71 01 FF 00 01` (success) or `7F 31 72` (failure)

### Read CSR
**Request:** `22 F1 01`
**Response:** `62 F1 01 [CSR data]`

### Inject Certificate
**Request:** `2E F1 02 [certificate data]`
**Response:** `6E F1 02` (success) or `7F 2E 72` (failure)

## SecurityAccess Seed-Key (0x27)

### Overview
The SEC service provides `getSeed` and `verifyKey` interfaces for UDS 0x27 SecurityAccess. The DIAG service handles the protocol interaction and lockout state machine, while SEC provides the cryptographic implementation.

### getSeed Interface
**Request:** `DiagRequestType::GET_SEED` with level parameter
**Response:** 16-byte random seed

**Parameters:**
- `level`: UDS security level (odd value, e.g., 0x27 for security level 27)

**Returns:**
- `ErrorCode::SUCCESS`: Seed generated successfully
- `ErrorCode::SEED_GENERATION_FAILED`: Failed to generate seed
- `ErrorCode::UDS_SECURITY_DENIED`: In lockout period
- `ErrorCode::INVALID_PARAMETER`: Invalid security level (must be odd)

### verifyKey Interface
**Request:** `DiagRequestType::VERIFY_KEY` with level and key
**Response:** Boolean result (success/failure)

**Parameters:**
- `level`: UDS security level (even value, must be requestSeed level + 1, e.g., 0x28)
- `key`: 16-byte key to verify

**Returns:**
- `ErrorCode::SUCCESS`: Key verification successful
- `ErrorCode::KEY_VERIFICATION_FAILED`: Key verification failed
- `ErrorCode::UDS_SECURITY_DENIED`: In lockout period
- `ErrorCode::INVALID_PARAMETER`: Invalid security level (must be even and match requestSeed level + 1)

### Algorithm Details
- **Algorithm**: AES-128
- **Seed Size**: 16 bytes (128-bit)
- **Key Size**: 16 bytes (128-bit)
- **Key Computation**: Key = AES-128(seed, shared_secret)
- **Shared Secret**: Stored securely in HSM/secure element

### Security Features
- **UDS Compliance**: Follows ISO 14229 SecurityAccess level conventions
  - requestSeed uses odd security levels (0x01, 0x03, ..., 0x27, etc.)
  - sendKey uses even security levels (0x02, 0x04, ..., 0x28, etc.)
  - sendKey level must equal requestSeed level + 1
- **Seed Expiry**: Seeds expire after 30 seconds
- **Single Use**: Seeds are invalidated after successful verification
- **Lockout**: 3 consecutive failures trigger 10-second lockout
- **Constant-Time Comparison**: Prevents timing attacks
- **Secure Memory**: Seed material cleared after use

### Integration with DIAG

The DIAG `ServiceDispatcher` handles UDS SecurityAccess (0x27) protocol:

```cpp
// ServiceDispatcher passes RAW UDS level to SEC - NO level decrement
ErrorCode ServiceDispatcher::handle_security_access(uint8_t sub_function, ...) {
    bool is_request_seed = (sub_function & 0x01) != 0;
    uint8_t raw_level = sub_function;  // 0x27 or 0x28
    
    if (is_request_seed) {
        return sec_service_->get_seed(raw_level, seed);  // Pass 0x27
    } else {
        return sec_service_->verify_key(raw_level, key);  // Pass 0x28, NOT 0x27
    }
}
```

The DIAG service maintains:
- 0x27 protocol interaction state
- Failed attempt counter
- Lockout state machine (3 failures → 10s lockout)
- NRC mapping (SEC-1008 → NRC 0x35)

## Error Handling

### Negative Response Codes
- `0x11`: Service not supported
- `0x12`: Sub-function not supported
- `0x22`: Conditions not correct
- `0x31`: Request out of range
- `0x33`: Security access denied
- `0x35`: Invalid key
- `0x36`: Exceeded number of attempts
- `0x37`: Required time delay not expired
- `0x72`: General programming failure

### SEC Error Codes
- `SEC-1007`: Seed generation failure
- `SEC-1008`: Key verification failure (maps to NRC 0x35)

## Troubleshooting

### Key Generation Failed
1. Check HSM connection
2. Verify security access
3. Check device storage

### CSR Build Failed
1. Verify key pair exists
2. Check device identifiers
3. Validate configuration

### Certificate Injection Failed
1. Verify certificate format
2. Check key match
3. Validate certificate chain

### PKI Communication Failed
1. Check network connectivity
2. Verify OAPI endpoint
3. Check timeout settings

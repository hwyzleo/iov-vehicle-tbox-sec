# TBOX Security Diagnostic Procedures

## Overview

This document describes diagnostic procedures for the TBOX Security Service.

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

## Error Handling

### Negative Response Codes
- `0x11`: Service not supported
- `0x12`: Sub-function not supported
- `0x22`: Conditions not correct
- `0x31`: Request out of range
- `0x33`: Security access denied
- `0x35`: Invalid key
- `0x72`: General programming failure

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

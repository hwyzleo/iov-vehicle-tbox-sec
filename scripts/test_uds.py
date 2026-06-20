#!/usr/bin/env python3
"""
UDS Simulator - Direct API Test
Test UDS Handler without network connection
"""

import sys
import os

# Add build directory to path for C++ library
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'build'))

def print_header(title):
    """Print formatted header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_response(response):
    """Print UDS response"""
    if response.get('success'):
        print(f"✓ Success")
        if 'data' in response:
            print(f"  Data: {response['data'].hex()}")
    else:
        print(f"✗ Failed: {response.get('error', 'Unknown error')}")

def test_with_cpp_binary():
    """Test using the compiled C++ binary"""
    import subprocess
    
    print_header("Testing with C++ Binary")
    
    # Check if binary exists
    binary_path = os.path.join(os.path.dirname(__file__), '..', 'build', 'TboxSecService')
    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}")
        print("Please build first: ./scripts/build-local.sh")
        return False
        
    print(f"Binary found: {binary_path}")
    
    # Run with test config
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.yaml')
    
    print("\nStarting TBOX Security Service...")
    print("Press Ctrl+C to stop")
    print("\nNote: This will fail with STORAGE_READ_FAILED (expected for first run)")
    
    try:
        subprocess.run([binary_path, config_path], timeout=5)
    except subprocess.TimeoutExpired:
        print("\n✓ Service started successfully (timeout after 5s)")
    except KeyboardInterrupt:
        print("\n✓ Service stopped by user")
    except Exception as e:
        print(f"\n✗ Service failed: {e}")
        return False
        
    return True

def test_with_unit_tests():
    """Test using unit tests"""
    import subprocess
    
    print_header("Running Unit Tests")
    
    # Check if test binary exists
    test_binary = os.path.join(os.path.dirname(__file__), '..', 'build', 'TboxSecTests')
    if not os.path.exists(test_binary):
        print(f"Test binary not found: {test_binary}")
        print("Please build first: ./scripts/build-local.sh")
        return False
        
    print(f"Running: {test_binary}")
    
    # Run UDS handler tests
    try:
        result = subprocess.run(
            [test_binary, '--gtest_filter=UdsHandlerTest.*'],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"Tests failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"Test execution failed: {e}")
        return False
        
    return True

def show_uds_commands():
    """Show UDS command reference"""
    print_header("UDS Command Reference")
    
    commands = """
Diagnostic Session Control (0x10):
  Request:  10 <session_type>
  Response: 50 <session_type>
  Sessions: 01=Default, 02=Programming, 03=Extended

Security Access (0x29):
  Request Seed:  29 29
  Response Seed: 69 29 <seed>
  Send Key:      29 2A <key>
  Response Key:  69 2A 01

Read Data By Identifier (0x22):
  Provision State: 22 F1 00
  CSR:             22 F1 01
  Response:        62 <DID> <data>

Write Data By Identifier (0x2E):
  Certificate: 2E F1 02 <cert_data>
  Response:    6E F1 02

Routine Control (0x31):
  Generate Key Pair: 31 01 FF 00
  Response:          71 01 FF 00 01

Negative Response:
  7F <service> <NRC>
  NRC Codes:
    11 - Service not supported
    12 - Sub-function not supported
    22 - Conditions not correct
    31 - Request out of range
    33 - Security access denied
    35 - Invalid key
    72 - General programming failure
"""
    print(commands)

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='TBOX UDS Test Tool')
    parser.add_argument('--binary', action='store_true', help='Test with C++ binary')
    parser.add_argument('--unit-test', action='store_true', help='Run unit tests')
    parser.add_argument('--commands', action='store_true', help='Show UDS commands')
    
    args = parser.parse_args()
    
    if args.binary:
        test_with_cpp_binary()
    elif args.unit_test:
        test_with_unit_tests()
    elif args.commands:
        show_uds_commands()
    else:
        # Show menu
        print_header("TBOX UDS Test Tool")
        print("\nOptions:")
        print("  1. Run unit tests")
        print("  2. Test with C++ binary")
        print("  3. Show UDS commands")
        print("  q. Quit")
        
        while True:
            choice = input("\n> ").strip()
            
            if choice == 'q':
                break
            elif choice == '1':
                test_with_unit_tests()
            elif choice == '2':
                test_with_cpp_binary()
            elif choice == '3':
                show_uds_commands()
            else:
                print("Unknown choice")

if __name__ == '__main__':
    main()

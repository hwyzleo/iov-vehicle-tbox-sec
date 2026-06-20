#!/usr/bin/env python3
"""
UDS Diagnostic Simulator for TBOX Security Service
Simulates a diagnostic workstation sending UDS requests
"""

import socket
import struct
import sys
import time

class UdsSimulator:
    """Simulate UDS diagnostic requests"""
    
    # UDS Service IDs
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    SECURITY_ACCESS = 0x29
    READ_DATA_BY_IDENTIFIER = 0x22
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    ROUTINE_CONTROL = 0x31
    
    # Negative Response Codes
    NRC_SERVICE_NOT_SUPPORTED = 0x11
    NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
    NRC_CONDITIONS_NOT_CORRECT = 0x22
    NRC_REQUEST_OUT_OF_RANGE = 0x31
    NRC_SECURITY_ACCESS_DENIED = 0x33
    NRC_INVALID_KEY = 0x35
    NRC_GENERAL_PROGRAMMING_FAILURE = 0x72
    
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.sock = None
        self.security_access_granted = False
        
    def connect(self):
        """Connect to TBOX UDS server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
            
    def disconnect(self):
        """Disconnect from server"""
        if self.sock:
            self.sock.close()
            self.sock = None
            
    def send_request(self, service_id, sub_function=0, data=None, did=0, rid=0):
        """Send UDS request and receive response"""
        if not self.sock:
            print("Not connected")
            return None
            
        # Build request packet (simplified)
        # In real UDS, this would be CAN/DoIP framing
        request = struct.pack('BB', service_id, sub_function)
        if did:
            request += struct.pack('>H', did)
        if rid:
            request += struct.pack('>H', rid)
        if data:
            request += bytes(data)
            
        print(f"\n>>> Sending: {request.hex()}")
        print(f"    Service: 0x{service_id:02X}, SubFunc: 0x{sub_function:02X}")
        if did:
            print(f"    DID: 0x{did:04X}")
        if rid:
            print(f"    RID: 0x{rid:04X}")
            
        self.sock.send(request)
        
        # Receive response
        response = self.sock.recv(1024)
        if response:
            print(f"<<< Response: {response.hex()}")
            return self.parse_response(response)
        return None
        
    def parse_response(self, response):
        """Parse UDS response"""
        if len(response) < 2:
            return {'success': False, 'error': 'Invalid response'}
            
        # Check for negative response
        if response[0] == 0x7F:
            nrc = response[2]
            error_msg = {
                self.NRC_SERVICE_NOT_SUPPORTED: "Service not supported",
                self.NRC_SUBFUNCTION_NOT_SUPPORTED: "Sub-function not supported",
                self.NRC_CONDITIONS_NOT_CORRECT: "Conditions not correct",
                self.NRC_REQUEST_OUT_OF_RANGE: "Request out of range",
                self.NRC_SECURITY_ACCESS_DENIED: "Security access denied",
                self.NRC_INVALID_KEY: "Invalid key",
                self.NRC_GENERAL_PROGRAMMING_FAILURE: "General programming failure"
            }.get(nrc, f"Unknown NRC: 0x{nrc:02X}")
            
            return {
                'success': False,
                'nrc': nrc,
                'error': error_msg
            }
        else:
            return {
                'success': True,
                'data': response[1:]
            }
            
    # UDS Service Implementations
    
    def diagnostic_session_control(self, session_type=0x01):
        """
        Switch diagnostic session
        0x01: Default session
        0x02: Programming session
        0x03: Extended session
        """
        print(f"\n=== Diagnostic Session Control (0x{session_type:02X}) ===")
        return self.send_request(self.DIAGNOSTIC_SESSION_CONTROL, session_type)
        
    def security_access_request_seed(self):
        """Request seed for security access"""
        print("\n=== Security Access: Request Seed ===")
        return self.send_request(self.SECURITY_ACCESS, 0x29)
        
    def security_access_send_key(self, key):
        """Send key for security access"""
        print(f"\n=== Security Access: Send Key ===")
        result = self.send_request(self.SECURITY_ACCESS, 0x2A, data=key)
        if result and result['success']:
            self.security_access_granted = True
            print("✓ Security access granted!")
        return result
        
    def read_provision_state(self):
        """Read provision state (DID 0xF100)"""
        print("\n=== Read Provision State ===")
        result = self.send_request(self.READ_DATA_BY_IDENTIFIER, did=0xF100)
        if result and result['success']:
            state_map = {
                0: "NONE",
                1: "KEY_GENERATED",
                2: "CSR_BUILT",
                3: "CSR_SUBMITTED",
                4: "CERT_INSTALLED",
                5: "FAILED"
            }
            state = result['data'][0] if result['data'] else 0
            print(f"State: {state_map.get(state, 'UNKNOWN')} ({state})")
        return result
        
    def read_csr(self):
        """Read CSR (DID 0xF101)"""
        print("\n=== Read CSR ===")
        return self.send_request(self.READ_DATA_BY_IDENTIFIER, did=0xF101)
        
    def write_certificate(self, cert_data):
        """Write certificate (DID 0xF102)"""
        print(f"\n=== Write Certificate ({len(cert_data)} bytes) ===")
        return self.send_request(self.WRITE_DATA_BY_IDENTIFIER, did=0xF102, data=cert_data)
        
    def generate_key_pair(self):
        """Generate key pair (RID 0xFF00)"""
        print("\n=== Generate Key Pair ===")
        return self.send_request(self.ROUTINE_CONTROL, rid=0xFF00)
        
    # High-level workflows
    
    def run_full_workflow(self):
        """Run complete security initialization workflow"""
        print("\n" + "="*60)
        print("TBOX Security Initialization Workflow")
        print("="*60)
        
        # Step 1: Switch to extended session
        print("\n[Step 1] Switch to extended session")
        result = self.diagnostic_session_control(0x03)
        if not result or not result['success']:
            print("✗ Failed to switch session")
            return False
            
        # Step 2: Security access
        print("\n[Step 2] Security access")
        result = self.security_access_request_seed()
        if not result or not result['success']:
            print("✗ Failed to request seed")
            return False
            
        # In real implementation, calculate key from seed
        # For simulation, use dummy key
        dummy_key = [0x01, 0x02, 0x03, 0x04]
        result = self.security_access_send_key(dummy_key)
        if not result or not result['success']:
            print("✗ Security access failed")
            return False
            
        # Step 3: Read current state
        print("\n[Step 3] Read current provision state")
        self.read_provision_state()
        
        # Step 4: Generate key pair
        print("\n[Step 4] Generate key pair")
        result = self.generate_key_pair()
        if not result or not result['success']:
            print("✗ Failed to generate key pair")
            return False
            
        # Step 5: Read CSR
        print("\n[Step 5] Read CSR")
        result = self.read_csr()
        if result and result['success']:
            print(f"CSR length: {len(result['data'])} bytes")
            # In real workflow, send CSR to MES -> OAPI -> PKI
            
        # Step 6: Read state again
        print("\n[Step 6] Read provision state after key generation")
        self.read_provision_state()
        
        print("\n" + "="*60)
        print("Workflow completed!")
        print("="*60)
        return True
        
    def interactive_mode(self):
        """Interactive diagnostic mode"""
        print("\n" + "="*60)
        print("TBOX UDS Simulator - Interactive Mode")
        print("="*60)
        print("\nCommands:")
        print("  1 - Diagnostic Session Control")
        print("  2 - Security Access (Request Seed)")
        print("  3 - Security Access (Send Key)")
        print("  4 - Read Provision State")
        print("  5 - Read CSR")
        print("  6 - Generate Key Pair")
        print("  7 - Write Certificate")
        print("  8 - Run Full Workflow")
        print("  q - Quit")
        
        while True:
            cmd = input("\n> ").strip()
            
            if cmd == 'q':
                break
            elif cmd == '1':
                session = input("Session type (01/02/03): ").strip()
                self.diagnostic_session_control(int(session, 16))
            elif cmd == '2':
                self.security_access_request_seed()
            elif cmd == '3':
                key_hex = input("Key (hex, e.g., 01020304): ").strip()
                key = bytes.fromhex(key_hex)
                self.security_access_send_key(key)
            elif cmd == '4':
                self.read_provision_state()
            elif cmd == '5':
                self.read_csr()
            elif cmd == '6':
                self.generate_key_pair()
            elif cmd == '7':
                cert_hex = input("Certificate (hex): ").strip()
                cert = bytes.fromhex(cert_hex)
                self.write_certificate(cert)
            elif cmd == '8':
                self.run_full_workflow()
            else:
                print("Unknown command")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='TBOX UDS Simulator')
    parser.add_argument('--host', default='localhost', help='TBOX host address')
    parser.add_argument('--port', type=int, default=5000, help='TBOX UDS port')
    parser.add_argument('--workflow', action='store_true', help='Run full workflow')
    
    args = parser.parse_args()
    
    simulator = UdsSimulator(args.host, args.port)
    
    if not simulator.connect():
        sys.exit(1)
        
    try:
        if args.workflow:
            simulator.run_full_workflow()
        else:
            simulator.interactive_mode()
    finally:
        simulator.disconnect()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
OCSP Check Demo Script

This script demonstrates how to run an OCSP check and extract signer information.
It provides example usage and can be used with sample certificates.
"""

import os
import sys
import subprocess
from datetime import datetime

def check_openssl_available():
    """Check if OpenSSL is available"""
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[OK] OpenSSL available: {result.stdout.strip()}")
            return True
        else:
            print("[ERROR] OpenSSL not available")
            return False
    except FileNotFoundError:
        print("[ERROR] OpenSSL not found in PATH")
        return False

def create_sample_certificates():
    """Create sample certificates for testing"""
    print("\n[INFO] Creating sample certificates for testing...")
    
    try:
        # Create a simple CA certificate
        ca_key_cmd = ["openssl", "genrsa", "-out", "sample_ca.key", "2048"]
        subprocess.run(ca_key_cmd, check=True)
        
        ca_cert_cmd = [
            "openssl", "req", "-new", "-x509", "-key", "sample_ca.key",
            "-out", "sample_ca.pem", "-days", "365",
            "-subj", "/C=US/ST=CA/L=San Francisco/O=Test CA/CN=Test CA"
        ]
        subprocess.run(ca_cert_cmd, check=True)
        
        # Create a sample certificate
        cert_key_cmd = ["openssl", "genrsa", "-out", "sample_cert.key", "2048"]
        subprocess.run(cert_key_cmd, check=True)
        
        cert_req_cmd = [
            "openssl", "req", "-new", "-key", "sample_cert.key",
            "-out", "sample_cert.csr",
            "-subj", "/C=US/ST=CA/L=San Francisco/O=Test Org/CN=test.example.com"
        ]
        subprocess.run(cert_req_cmd, check=True)
        
        cert_sign_cmd = [
            "openssl", "x509", "-req", "-in", "sample_cert.csr",
            "-CA", "sample_ca.pem", "-CAkey", "sample_ca.key",
            "-out", "sample_cert.pem", "-days", "365",
            "-CAcreateserial"
        ]
        subprocess.run(cert_sign_cmd, check=True)
        
        print("[OK] Sample certificates created successfully")
        print("   - sample_ca.pem (CA certificate)")
        print("   - sample_cert.pem (Sample certificate)")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error creating sample certificates: {e}")
        return False

def run_ocsp_check_demo():
    """Run OCSP check demo"""
    print("\n[INFO] Running OCSP check demo...")
    
    # Check if sample certificates exist
    if not os.path.exists("sample_cert.pem") or not os.path.exists("sample_ca.pem"):
        print("[ERROR] Sample certificates not found. Creating them...")
        if not create_sample_certificates():
            print("[ERROR] Failed to create sample certificates")
            return False
    
    # Use a public OCSP URL for testing (Google's OCSP responder)
    ocsp_url = "http://ocsp.pki.goog/gts1o1core"
    
    print(f"\n[INFO] Running OCSP check with:")
    print(f"   Certificate: sample_cert.pem")
    print(f"   Issuer: sample_ca.pem")
    print(f"   OCSP URL: {ocsp_url}")
    
    try:
        # Run OCSP check
        ocsp_cmd = [
            "openssl", "ocsp",
            "-issuer", "sample_ca.pem",
            "-cert", "sample_cert.pem",
            "-url", ocsp_url,
            "-resp_text",
            "-verify_other", "sample_ca.pem"
        ]
        
        print(f"\n[CMD] {' '.join(ocsp_cmd)}")
        result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
        
        print("\n[OCSP RESPONSE]")
        print("=" * 50)
        print(result.stdout)
        
        if result.stderr:
            print("\n[OCSP STDERR]")
            print("=" * 50)
            print(result.stderr)
        
        # Extract signer information
        print("\n[EXTRACTED SIGNER INFORMATION]")
        print("=" * 50)
        
        import re
        
        # Extract Responder ID
        responder_match = re.search(r'Responder ID:\s*(.+)', result.stdout)
        if responder_match:
            print(f"Responder ID: {responder_match.group(1).strip()}")
        
        # Extract Signature Algorithm
        sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', result.stdout)
        if sig_algo_match:
            print(f"Signature Algorithm: {sig_algo_match.group(1).strip()}")
        
        # Check signature verification
        if "Response verify OK" in result.stdout or "Response verify OK" in result.stderr:
            print("Signature Verification: [OK] PASSED")
        else:
            print("Signature Verification: [ERROR] FAILED")
        
        # Extract certificate status
        status_match = re.search(r'Cert Status:\s*(\w+)', result.stdout)
        if status_match:
            print(f"Certificate Status: {status_match.group(1).upper()}")
        
        # Extract timestamps
        this_update_match = re.search(r'This Update:\s*(.+)', result.stdout)
        if this_update_match:
            print(f"This Update: {this_update_match.group(1).strip()}")
        
        next_update_match = re.search(r'Next Update:\s*(.+)', result.stdout)
        if next_update_match:
            print(f"Next Update: {next_update_match.group(1).strip()}")
        
        return True
        
    except subprocess.TimeoutExpired:
        print("[ERROR] OCSP request timed out")
        return False
    except Exception as e:
        print(f"[ERROR] Error running OCSP check: {e}")
        return False

def main():
    """Main function"""
    print("OCSP Check and Signer Extraction Demo")
    print("=" * 50)
    
    # Check OpenSSL availability
    if not check_openssl_available():
        print("\n[ERROR] OpenSSL is required but not available.")
        print("Please install OpenSSL and ensure it's in your PATH.")
        sys.exit(1)
    
    # Run the demo
    success = run_ocsp_check_demo()
    
    if success:
        print("\n[OK] OCSP check demo completed successfully!")
        print("\n[INFO] You can now use the following scripts:")
        print("   1. ocsp_signer_extractor.py - Standalone signer extraction")
        print("   2. ocsp_check_example.py - Using existing OCSP framework")
        print("   3. app.py - Full GUI application")
    else:
        print("\n[ERROR] OCSP check demo failed")
        sys.exit(1)

if __name__ == "__main__":
    main()

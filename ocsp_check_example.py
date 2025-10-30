#!/usr/bin/env python3
"""
OCSP Check and Signer Extraction Example

This script demonstrates how to use the existing OCSP testing framework
to run an OCSP check and extract signer information from the response.
"""

import sys
import os
import subprocess
import json
from datetime import datetime

# Add the ocsp_tester module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ocsp_tester'))

from ocsp_tester.monitor import OCSPMonitor

def run_ocsp_check_with_signer_extraction(cert_path: str, issuer_path: str, ocsp_url: str):
    """
    Run OCSP check using the existing framework and extract signer information
    
    Args:
        cert_path: Path to the certificate being checked
        issuer_path: Path to the issuing CA certificate
        ocsp_url: OCSP server URL
        
    Returns:
        Dict containing OCSP results and extracted signer information
    """
    
    print("OCSP Check and Signer Extraction")
    print("=" * 50)
    print(f"Certificate: {cert_path}")
    print(f"Issuer: {issuer_path}")
    print(f"OCSP URL: {ocsp_url}")
    print("=" * 50)
    
    # Create OCSP monitor instance
    monitor = OCSPMonitor()
    
    # Run OCSP check
    print("\n[INFO] Running OCSP check...")
    results = monitor.run_ocsp_check(cert_path, issuer_path, ocsp_url)
    
    # Extract signer information from the raw output
    signer_info = extract_signer_from_ocsp_output(results)
    
    # Compile final results
    final_results = {
        "timestamp": datetime.now().isoformat(),
        "certificate_path": cert_path,
        "issuer_path": issuer_path,
        "ocsp_url": ocsp_url,
        "ocsp_results": results,
        "extracted_signer_information": signer_info
    }
    
    return final_results

def extract_signer_from_ocsp_output(ocsp_results: dict) -> dict:
    """
    Extract signer information from OCSP results
    
    Args:
        ocsp_results: Results from OCSPMonitor.run_ocsp_check()
        
    Returns:
        Dict containing extracted signer information
    """
    signer_info = {
        "responder_id": None,
        "signature_algorithm": None,
        "signature_verified": False,
        "signer_certificate_details": None,
        "extraction_method": "from_ocsp_results"
    }
    
    try:
        # Get raw stdout if available
        raw_stdout = ocsp_results.get("raw_stdout", "")
        raw_stderr = ocsp_results.get("raw_stderr", "")
        
        if raw_stdout:
            import re
            
            # Extract Responder ID
            responder_match = re.search(r'Responder ID:\s*(.+)', raw_stdout)
            if responder_match:
                signer_info["responder_id"] = responder_match.group(1).strip()
            
            # Extract Signature Algorithm
            sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', raw_stdout)
            if sig_algo_match:
                signer_info["signature_algorithm"] = sig_algo_match.group(1).strip()
            
            # Check signature verification status
            if "Response verify OK" in raw_stdout or "Response verify OK" in raw_stderr:
                signer_info["signature_verified"] = True
            
            # Extract certificate details if present
            cert_match = re.search(r'Certificate:\s*\n(.*?)(?=\n\s*\n|\n\s*Signature)', raw_stdout, re.DOTALL)
            if cert_match:
                cert_text = cert_match.group(1)
                
                # Extract subject
                subject_match = re.search(r'Subject:\s*(.+)', cert_text)
                if subject_match:
                    signer_info["signer_certificate_details"] = {
                        "subject": subject_match.group(1).strip()
                    }
                
                # Extract issuer
                issuer_match = re.search(r'Issuer:\s*(.+)', cert_text)
                if issuer_match and signer_info["signer_certificate_details"]:
                    signer_info["signer_certificate_details"]["issuer"] = issuer_match.group(1).strip()
                
                # Extract serial number
                serial_match = re.search(r'Serial Number:\s*(.+)', cert_text)
                if serial_match and signer_info["signer_certificate_details"]:
                    signer_info["signer_certificate_details"]["serial_number"] = serial_match.group(1).strip()
        
        print(f"\n[EXTRACTED SIGNER INFORMATION]")
        print(f"Responder ID: {signer_info['responder_id']}")
        print(f"Signature Algorithm: {signer_info['signature_algorithm']}")
        print(f"Signature Verified: {signer_info['signature_verified']}")
        if signer_info['signer_certificate_details']:
            print(f"Signer Subject: {signer_info['signer_certificate_details'].get('subject', 'N/A')}")
            print(f"Signer Issuer: {signer_info['signer_certificate_details'].get('issuer', 'N/A')}")
            print(f"Signer Serial: {signer_info['signer_certificate_details'].get('serial_number', 'N/A')}")
        
    except Exception as e:
        print(f"[ERROR] Error extracting signer information: {str(e)}")
        signer_info["extraction_error"] = str(e)
    
    return signer_info

def main():
    """Main function"""
    if len(sys.argv) < 4:
        print("Usage: python ocsp_check_example.py <cert_path> <issuer_path> <ocsp_url>")
        print("\nExample:")
        print("python ocsp_check_example.py certificate.pem issuer.pem http://ocsp.example.com")
        sys.exit(1)
    
    cert_path = sys.argv[1]
    issuer_path = sys.argv[2]
    ocsp_url = sys.argv[3]
    
    # Check if files exist
    if not os.path.exists(cert_path):
        print(f"[ERROR] Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not os.path.exists(issuer_path):
        print(f"[ERROR] Issuer file not found: {issuer_path}")
        sys.exit(1)
    
    try:
        # Run OCSP check and extract signer information
        results = run_ocsp_check_with_signer_extraction(cert_path, issuer_path, ocsp_url)
        
        # Save results to JSON file
        output_file = f"ocsp_check_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[INFO] Results saved to: {output_file}")
        
        # Print summary
        print("\n[SUMMARY]")
        print("=" * 50)
        ocsp_results = results.get("ocsp_results", {})
        signer_info = results.get("extracted_signer_information", {})
        
        if "error" in ocsp_results:
            print(f"❌ OCSP Check Error: {ocsp_results['error']}")
        else:
            print(f"✅ OCSP Check Completed")
            print(f"📋 Certificate Status: {ocsp_results.get('cert_status', 'UNKNOWN')}")
            print(f"🔐 Signature Verified: {signer_info.get('signature_verified', False)}")
            print(f"👤 Responder ID: {signer_info.get('responder_id', 'Not found')}")
            print(f"🔑 Signature Algorithm: {signer_info.get('signature_algorithm', 'Not found')}")
            
            if signer_info.get('signer_certificate_details'):
                details = signer_info['signer_certificate_details']
                print(f"📜 Signer Subject: {details.get('subject', 'N/A')}")
                print(f"🏢 Signer Issuer: {details.get('issuer', 'N/A')}")
                print(f"🔢 Signer Serial: {details.get('serial_number', 'N/A')}")
        
    except Exception as e:
        print(f"[ERROR] Exception occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()


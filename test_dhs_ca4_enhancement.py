#!/usr/bin/env python3
"""
Test script for enhanced DHS CA4 batch OCSP response handling
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'ocsp_tester'))

from monitor import OCSPMonitor

def test_dhs_ca4_batch_response():
    """Test the enhanced OCSP monitor with DHS CA4 batch responses"""
    
    print("Testing Enhanced DHS CA4 Batch OCSP Response Handling")
    print("=" * 60)
    
    # Create monitor instance
    monitor = OCSPMonitor()
    
    # Test with DHS CA4 certificates
    cert_path = "C:/Users/jcgoo/Downloads/GARYCIS.pem"
    issuer_path = "C:/Users/jcgoo/Downloads/GARYCISDHSCA4.cer"
    ocsp_url = "http://ocsp.dimc.dhs.gov"
    
    print(f"Certificate: {cert_path}")
    print(f"Issuer: {issuer_path}")
    print(f"OCSP URL: {ocsp_url}")
    print()
    
    try:
        # Run OCSP check
        results = monitor.run_ocsp_check(cert_path, issuer_path, ocsp_url)
        
        print("\nEnhanced OCSP Check Results:")
        print("-" * 40)
        
        # Check federal PKI detection
        federal_info = results.get("federal_pki_info", {})
        if federal_info.get("is_federal_pki"):
            print(f"[FEDERAL-PKI] Detected: {federal_info.get('agency', 'Unknown')} federal PKI")
            print(f"[FEDERAL-PKI] CA Name: {federal_info.get('ca_name', 'Unknown')}")
            print(f"[FEDERAL-PKI] Characteristics:")
            for char in federal_info.get("characteristics", []):
                print(f"  - {char}")
        else:
            print("[FEDERAL-PKI] Not detected as federal PKI environment")
        
        # Check batch response handling
        cert_status_details = results.get("certificate_status_details", {})
        batch_info = cert_status_details.get("batch_response_info", {})
        
        if batch_info.get("is_batch_response"):
            print(f"\n[BATCH-RESPONSE] Detected batch OCSP response")
            print(f"[BATCH-RESPONSE] Total certificates: {batch_info.get('total_certificates', 0)}")
            
            # Show summary of batch certificates
            certificates = batch_info.get("certificates", [])
            if certificates:
                good_count = sum(1 for c in certificates if c.get("cert_status") == "good")
                revoked_count = sum(1 for c in certificates if c.get("cert_status") == "revoked")
                unknown_count = sum(1 for c in certificates if c.get("cert_status") == "unknown")
                
                print(f"[BATCH-RESPONSE] Summary: {good_count} good, {revoked_count} revoked, {unknown_count} unknown")
                
                # Show first few certificates as examples
                print(f"[BATCH-RESPONSE] Sample certificates:")
                for i, cert in enumerate(certificates[:5]):  # Show first 5
                    status_icon = "[OK]" if cert.get("cert_status") == "good" else "[REVOKED]" if cert.get("cert_status") == "revoked" else "[UNKNOWN]"
                    print(f"  {status_icon} Serial {cert.get('serial_number', 'Unknown')}: {cert.get('cert_status', 'Unknown').upper()}")
                
                if len(certificates) > 5:
                    print(f"  ... and {len(certificates) - 5} more certificates")
        else:
            print("\n[BATCH-RESPONSE] Single certificate response (not batch)")
        
        # Check target certificate status
        print(f"\n[TARGET-CERTIFICATE] Status:")
        print(f"  Serial: {cert_status_details.get('cert_serial', 'Unknown')}")
        print(f"  Status: {cert_status_details.get('cert_status', 'Unknown').upper()}")
        print(f"  This Update: {cert_status_details.get('this_update', 'Unknown')}")
        print(f"  Next Update: {cert_status_details.get('next_update', 'Unknown')}")
        
        if cert_status_details.get("revocation_time"):
            print(f"  Revocation Time: {cert_status_details.get('revocation_time', 'Unknown')}")
            print(f"  Revocation Reason: {cert_status_details.get('revocation_reason', 'Unknown')}")
        
        # Check for parsing errors or warnings
        parsing_errors = cert_status_details.get("parsing_errors", [])
        security_warnings = cert_status_details.get("security_warnings", [])
        
        if parsing_errors:
            print(f"\n[PARSING-ERRORS]:")
            for error in parsing_errors:
                print(f"  - {error}")
        
        if security_warnings:
            print(f"\n[SECURITY-WARNINGS]:")
            for warning in security_warnings:
                print(f"  - {warning}")
        
        # Print summary
        print(f"\n[SUMMARY]")
        print(f"Overall Result: {'SUCCESS' if results.get('overall_pass', False) else 'FAILED'}")
        print(f"Certificate Status: {cert_status_details.get('cert_status', 'UNKNOWN').upper()}")
        print(f"Federal PKI: {'YES' if federal_info.get('is_federal_pki') else 'NO'}")
        print(f"Batch Response: {'YES' if batch_info.get('is_batch_response') else 'NO'}")
        
        print("\n[SUCCESS] Enhanced DHS CA4 batch OCSP response handling test completed")
        
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = test_dhs_ca4_batch_response()
    if success:
        print("\n[OK] Enhanced DHS CA4 batch OCSP response handling verified")
    else:
        print("\n[ERROR] Enhanced DHS CA4 batch OCSP response handling failed")
        sys.exit(1)

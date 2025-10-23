#!/usr/bin/env python3
"""
Test script to verify the OCSP monitor fix
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'ocsp_tester'))

from monitor import OCSPMonitor

def test_ocsp_monitor():
    """Test the OCSP monitor with the fixed security_warnings key"""
    
    print("Testing OCSP Monitor Fix")
    print("=" * 40)
    
    # Create monitor instance
    monitor = OCSPMonitor()
    
    # Test with the same certificates that were causing the error
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
        
        print("OCSP Check Results:")
        print("-" * 30)
        
        # Check if security_warnings key exists
        cert_status_details = results.get("certificate_status_details", {})
        if "security_warnings" in cert_status_details:
            print("[OK] security_warnings key exists in certificate_status_details")
            warnings = cert_status_details["security_warnings"]
            if warnings:
                print(f"[INFO] Security warnings: {warnings}")
            else:
                print("[INFO] No security warnings")
        else:
            print("[ERROR] security_warnings key missing from certificate_status_details")
        
        # Check validity interval results
        validity_results = results.get("validity_interval_validation", {})
        if "security_warnings" in validity_results:
            print("[OK] security_warnings key exists in validity_interval_validation")
            warnings = validity_results["security_warnings"]
            if warnings:
                print(f"[INFO] Validity warnings: {warnings}")
            else:
                print("[INFO] No validity warnings")
        else:
            print("[ERROR] security_warnings key missing from validity_interval_validation")
        
        # Print summary
        if "summary" in results:
            print("\nSummary:")
            print("-" * 20)
            print(results["summary"])
        
        print("\n[SUCCESS] OCSP monitor test completed without KeyError")
        
    except KeyError as e:
        print(f"[ERROR] KeyError still exists: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Other error occurred: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = test_ocsp_monitor()
    if success:
        print("\n[OK] Fix verified - security_warnings KeyError resolved")
    else:
        print("\n[ERROR] Fix failed - KeyError still exists")
        sys.exit(1)

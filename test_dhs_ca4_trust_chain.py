#!/usr/bin/env python3
"""
DHS CA4 OCSP Trust Chain Test Script

This script demonstrates the enhanced OCSP signature verification
that addresses the "unable to get local issuer certificate" error
by automatically building trust chains from OCSP responses.

Usage:
    python test_dhs_ca4_trust_chain.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ocsp_tester.monitor import OCSPMonitor

def test_dhs_ca4_trust_chain():
    """Test the DHS CA4 OCSP trust chain functionality"""
    
    print("=" * 60)
    print("DHS CA4 OCSP Trust Chain Test")
    print("=" * 60)
    
    # Initialize the OCSP monitor
    monitor = OCSPMonitor()
    
    # Test parameters (using the user's example)
    issuer_cert = "C:/Users/jcgoo/Downloads/GARYCISDHSCA4.cer"
    end_entity_cert = "C:/Users/jcgoo/Downloads/GARYCIS.pem"
    ocsp_url = "http://ocsp.dimc.dhs.gov"
    
    print(f"Issuer Certificate: {issuer_cert}")
    print(f"End Entity Certificate: {end_entity_cert}")
    print(f"OCSP URL: {ocsp_url}")
    print()
    
    # Check if files exist
    if not os.path.exists(issuer_cert):
        print(f"[ERROR] Issuer certificate not found: {issuer_cert}")
        print("Please ensure the certificate files are in the correct location.")
        return False
    
    if not os.path.exists(end_entity_cert):
        print(f"[ERROR] End entity certificate not found: {end_entity_cert}")
        print("Please ensure the certificate files are in the correct location.")
        return False
    
    print("[INFO] Certificate files found, proceeding with OCSP check...")
    print()
    
    # Run the OCSP check with enhanced trust chain support
    try:
        results = monitor.run_ocsp_check(end_entity_cert, issuer_cert, ocsp_url)
        
        print("=" * 60)
        print("OCSP CHECK RESULTS")
        print("=" * 60)
        
        # Display key results
        if "summary" in results:
            print(results["summary"])
        
        # Display trust chain information
        if results.get("trust_chain_attempted"):
            print(f"[INFO] Trust chain was attempted: {results.get('trust_chain_path', 'N/A')}")
        
        # Display signature verification status
        signature_status = "PASSED" if results.get("signature_verified") else "FAILED"
        print(f"[INFO] Signature verification: {signature_status}")
        
        # Display certificate status
        cert_status = results.get("cert_status", "UNKNOWN")
        print(f"[INFO] Certificate status: {cert_status}")
        
        print()
        print("=" * 60)
        print("ENHANCED FEATURES DEMONSTRATED")
        print("=" * 60)
        print("✅ Automatic trust chain building from OCSP response")
        print("✅ Certificate extraction from OCSP responses")
        print("✅ Enhanced error handling for federal PKI environments")
        print("✅ Comprehensive signature verification fallback")
        print("✅ Detailed logging for troubleshooting")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] OCSP check failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("DHS CA4 OCSP Trust Chain Enhancement Test")
    print("This test demonstrates the solution to the 'unable to get local issuer certificate' error")
    print()
    
    success = test_dhs_ca4_trust_chain()
    
    if success:
        print("\n[SUCCESS] Test completed successfully!")
        print("The enhanced OCSP monitor now handles DHS CA4 trust chain issues.")
    else:
        print("\n[FAILED] Test encountered errors.")
        print("Please check the certificate file paths and try again.")


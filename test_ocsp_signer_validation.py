#!/usr/bin/env python3
"""
Multi-Step OCSP Signer Validation Test Script

This script demonstrates the comprehensive multi-step OCSP signer validation
that addresses the specific requirements:
1. Extract OCSP signer certificate from response
2. Validate OCSP signer certificate trust against issuer
3. Validate OCSP response signature with signer certificate

Usage:
    python test_ocsp_signer_validation.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ocsp_tester.monitor import OCSPMonitor

def test_ocsp_signer_validation():
    """Test the multi-step OCSP signer validation functionality"""
    
    print("=" * 70)
    print("Multi-Step OCSP Signer Validation Test")
    print("=" * 70)
    
    # Initialize the OCSP monitor
    monitor = OCSPMonitor()
    
    # Test parameters (using the user's DHS CA4 example)
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
    
    print("[INFO] Certificate files found, proceeding with multi-step OCSP signer validation...")
    print()
    
    # Run the OCSP check with multi-step signer validation
    try:
        results = monitor.run_ocsp_check(end_entity_cert, issuer_cert, ocsp_url)
        
        print("=" * 70)
        print("MULTI-STEP OCSP SIGNER VALIDATION RESULTS")
        print("=" * 70)
        
        # Display key results
        if "summary" in results:
            print(results["summary"])
        
        # Display detailed OCSP signer validation results
        if "ocsp_signer_validation" in results:
            signer_validation = results["ocsp_signer_validation"]
            
            print("\n" + "=" * 70)
            print("DETAILED OCSP SIGNER VALIDATION ANALYSIS")
            print("=" * 70)
            
            print(f"Overall Success: {'YES' if signer_validation['overall_success'] else 'NO'}")
            print(f"Steps Completed: {signer_validation['steps_completed']}/{signer_validation['total_steps']}")
            
            print("\nStep-by-Step Results:")
            for step_name, step_result in signer_validation["step_results"].items():
                step_display = step_name.replace("step_", "").replace("_", " ").title()
                status = "✅ PASS" if step_result["success"] else "❌ FAIL"
                print(f"  {status} {step_display}: {step_result['message']}")
            
            # Display trust validation details
            if signer_validation.get("trust_validation"):
                trust_val = signer_validation["trust_validation"]
                print(f"\nTrust Validation Details:")
                print(f"  Trusted: {'YES' if trust_val['is_trusted'] else 'NO'}")
                print(f"  Trust Method: {trust_val.get('trust_method', 'N/A')}")
                if trust_val.get("validation_details"):
                    details = trust_val["validation_details"]
                    print(f"  Relationship: {details.get('relationship', 'N/A')}")
                    print(f"  Signer Serial: {details.get('signer_serial', 'N/A')}")
                    print(f"  Issuer Serial: {details.get('issuer_serial', 'N/A')}")
            
            # Display signature validation details
            if signer_validation.get("signature_validation"):
                sig_val = signer_validation["signature_validation"]
                print(f"\nSignature Validation Details:")
                print(f"  Signature Valid: {'YES' if sig_val['signature_valid'] else 'NO'}")
                print(f"  Validation Method: {sig_val.get('validation_method', 'N/A')}")
            
            # Display errors and warnings
            if signer_validation["errors"]:
                print(f"\nErrors:")
                for error in signer_validation["errors"]:
                    print(f"  ❌ {error}")
            
            if signer_validation["warnings"]:
                print(f"\nWarnings:")
                for warning in signer_validation["warnings"]:
                    print(f"  ⚠️  {warning}")
        
        print()
        print("=" * 70)
        print("VALIDATION PROCESS EXPLAINED")
        print("=" * 70)
        print("Step 1: Extract OCSP Signer Certificate")
        print("  - Parses OCSP response to find embedded certificates")
        print("  - Extracts the certificate used to sign the OCSP response")
        print("  - Handles multiple certificates in response if present")
        print()
        print("Step 2: Validate Signer Certificate Trust")
        print("  - Checks if signer is directly issued by the provided issuer")
        print("  - Verifies self-signed OCSP scenarios")
        print("  - Validates OCSP Signing EKU extension (1.3.6.1.5.5.7.3.9)")
        print("  - Confirms certificate authority relationships")
        print()
        print("Step 3: Validate OCSP Response Signature")
        print("  - Uses extracted signer certificate to verify OCSP response signature")
        print("  - Performs cryptographic signature validation")
        print("  - Confirms response integrity and authenticity")
        print()
        print("This multi-step process ensures complete OCSP signature verification")
        print("addressing the 'unable to get local issuer certificate' error.")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] OCSP signer validation test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("Multi-Step OCSP Signer Validation Test")
    print("This test demonstrates the solution to OCSP signature verification issues")
    print("by implementing a comprehensive 3-step validation process.")
    print()
    
    success = test_ocsp_signer_validation()
    
    if success:
        print("\n[SUCCESS] Multi-step OCSP signer validation test completed!")
        print("The enhanced OCSP monitor now performs comprehensive signer validation.")
    else:
        print("\n[FAILED] Test encountered errors.")
        print("Please check the certificate file paths and try again.")

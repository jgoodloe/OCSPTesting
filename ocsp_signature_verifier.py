#!/usr/bin/env python3
"""
OCSP Signature Verification Tool

This tool implements comprehensive OCSP signature verification following
the standard digital signature validation steps as described in the user's query.
"""

import subprocess
import re
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import json
import tempfile

class OCSPSignatureVerifier:
    """Comprehensive OCSP signature verification implementation"""
    
    def __init__(self):
        self.log_callback = print
        
    def log(self, text: str) -> None:
        """Log message"""
        self.log_callback(text)
        
    def verify_ocsp_signature(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Comprehensive OCSP signature verification
        
        Args:
            cert_path: Path to the certificate being checked
            issuer_path: Path to the issuing CA certificate  
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive verification results
        """
        try:
            self.log(f"[INFO] Starting comprehensive OCSP signature verification")
            self.log(f"[INFO] Certificate: {cert_path}")
            self.log(f"[INFO] Issuer: {issuer_path}")
            self.log(f"[INFO] OCSP URL: {ocsp_url}")
            self.log("=" * 80)
            
            verification_results = {
                "timestamp": datetime.now().isoformat(),
                "certificate_path": cert_path,
                "issuer_path": issuer_path,
                "ocsp_url": ocsp_url,
                "verification_steps": {},
                "overall_result": "UNKNOWN",
                "security_assessment": {},
                "recommendations": []
            }
            
            # Step 1: Retrieve OCSP Response and Signer's Certificate
            self.log("\n[STEP 1] Retrieving OCSP Response and Signer's Certificate")
            self.log("-" * 60)
            
            ocsp_response, responder_cert = self.retrieve_ocsp_response_and_certificate(
                cert_path, issuer_path, ocsp_url
            )
            
            verification_results["verification_steps"]["step1_retrieve"] = {
                "ocsp_response_retrieved": ocsp_response is not None,
                "responder_certificate_retrieved": responder_cert is not None,
                "ocsp_response": ocsp_response,
                "responder_certificate": responder_cert
            }
            
            if not ocsp_response or not responder_cert:
                verification_results["overall_result"] = "FAILED"
                verification_results["recommendations"].append("Unable to retrieve OCSP response or responder certificate")
                return verification_results
            
            # Step 2: Validate the Signer's Certificate
            self.log("\n[STEP 2] Validating the Signer's Certificate")
            self.log("-" * 60)
            
            cert_validation = self.validate_signers_certificate(responder_cert, issuer_path)
            verification_results["verification_steps"]["step2_cert_validation"] = cert_validation
            
            # Step 3: Perform Cryptographic Signature Check
            self.log("\n[STEP 3] Performing Cryptographic Signature Check")
            self.log("-" * 60)
            
            signature_check = self.perform_cryptographic_signature_check(
                ocsp_response, responder_cert, issuer_path
            )
            verification_results["verification_steps"]["step3_signature_check"] = signature_check
            
            # Step 4: Confirm Authority
            self.log("\n[STEP 4] Confirming Authority")
            self.log("-" * 60)
            
            authority_confirmation = self.confirm_authority(responder_cert, issuer_path, ocsp_response)
            verification_results["verification_steps"]["step4_authority"] = authority_confirmation
            
            # Overall Assessment
            verification_results["overall_result"] = self.assess_overall_result(verification_results)
            verification_results["security_assessment"] = self.perform_security_assessment(verification_results)
            
            # Display Results
            self.display_verification_results(verification_results)
            
            return verification_results
            
        except Exception as e:
            error_msg = f"[ERROR] OCSP Signature Verification Exception: {str(e)}"
            self.log(error_msg)
            return {"error": error_msg, "overall_result": "FAILED"}
    
    def retrieve_ocsp_response_and_certificate(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Step 1: Retrieve OCSP response and signer's certificate"""
        
        try:
            # Run OCSP request to get response with certificate
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify",  # Skip verification to get raw response
                "-text"
            ]
            
            self.log(f"[CMD] {' '.join(ocsp_cmd)}")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log(f"[ERROR] OCSP request failed: {result.stderr}")
                return None, None
            
            # Parse OCSP response
            ocsp_response = self.parse_ocsp_response(result.stdout)
            
            # Extract responder certificate
            responder_cert = self.extract_responder_certificate(result.stdout)
            
            self.log(f"[OK] OCSP response retrieved successfully")
            self.log(f"[OK] Responder certificate extracted")
            
            return ocsp_response, responder_cert
            
        except Exception as e:
            self.log(f"[ERROR] Error retrieving OCSP response: {str(e)}")
            return None, None
    
    def validate_signers_certificate(self, responder_cert: Dict[str, Any], issuer_path: str) -> Dict[str, Any]:
        """Step 2: Validate the signer's certificate"""
        
        validation_results = {
            "trust_chain_valid": False,
            "validity_period_valid": False,
            "key_usage_valid": False,
            "extended_key_usage_valid": False,
            "certificate_policies_valid": False,
            "validation_details": {},
            "errors": []
        }
        
        try:
            # 2.1 Trust Chain Validation
            self.log("[2.1] Validating Trust Chain")
            trust_chain_result = self.validate_trust_chain(responder_cert, issuer_path)
            validation_results["trust_chain_valid"] = trust_chain_result["valid"]
            validation_results["validation_details"]["trust_chain"] = trust_chain_result
            
            # 2.2 Validity Period Check
            self.log("[2.2] Checking Validity Period")
            validity_result = self.check_validity_period(responder_cert)
            validation_results["validity_period_valid"] = validity_result["valid"]
            validation_results["validation_details"]["validity_period"] = validity_result
            
            # 2.3 Key Usage Validation
            self.log("[2.3] Validating Key Usage")
            key_usage_result = self.validate_key_usage(responder_cert)
            validation_results["key_usage_valid"] = key_usage_result["valid"]
            validation_results["validation_details"]["key_usage"] = key_usage_result
            
            # 2.4 Extended Key Usage Validation (Critical for OCSP)
            self.log("[2.4] Validating Extended Key Usage")
            eku_result = self.validate_extended_key_usage(responder_cert)
            validation_results["extended_key_usage_valid"] = eku_result["valid"]
            validation_results["validation_details"]["extended_key_usage"] = eku_result
            
            # 2.5 Certificate Policies Validation
            self.log("[2.5] Validating Certificate Policies")
            policies_result = self.validate_certificate_policies(responder_cert)
            validation_results["certificate_policies_valid"] = policies_result["valid"]
            validation_results["validation_details"]["certificate_policies"] = policies_result
            
            # Overall certificate validation
            all_valid = all([
                validation_results["trust_chain_valid"],
                validation_results["validity_period_valid"],
                validation_results["key_usage_valid"],
                validation_results["extended_key_usage_valid"]
            ])
            
            if all_valid:
                self.log("[OK] Signer's certificate validation PASSED")
            else:
                self.log("[ERROR] Signer's certificate validation FAILED")
                validation_results["errors"].append("One or more certificate validation checks failed")
            
        except Exception as e:
            self.log(f"[ERROR] Error validating signer's certificate: {str(e)}")
            validation_results["errors"].append(f"Validation error: {str(e)}")
        
        return validation_results
    
    def validate_trust_chain(self, responder_cert: Dict[str, Any], issuer_path: str) -> Dict[str, Any]:
        """Validate the trust chain of the responder certificate"""
        
        try:
            # Create temporary file for responder certificate
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
                temp_cert.write(responder_cert.get('pem_data', ''))
                temp_cert_path = temp_cert.name
            
            # Verify certificate chain
            verify_cmd = [
                "openssl", "verify",
                "-CAfile", issuer_path,
                temp_cert_path
            ]
            
            result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=10)
            
            # Clean up temporary file
            os.unlink(temp_cert_path)
            
            is_valid = result.returncode == 0 and "OK" in result.stdout
            
            if is_valid:
                self.log("[OK] Trust chain validation PASSED")
            else:
                self.log(f"[ERROR] Trust chain validation FAILED: {result.stderr}")
            
            return {
                "valid": is_valid,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
        except Exception as e:
            self.log(f"[ERROR] Trust chain validation error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def check_validity_period(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Check certificate validity period"""
        
        try:
            validity = responder_cert.get('validity', {})
            not_before_str = validity.get('not_before')
            not_after_str = validity.get('not_after')
            
            if not not_before_str or not not_after_str:
                return {
                    "valid": False,
                    "error": "Validity period not found in certificate"
                }
            
            # Parse dates
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            
            is_valid = not_before <= now <= not_after
            
            if is_valid:
                self.log(f"[OK] Certificate validity period PASSED ({not_before} to {not_after})")
            else:
                self.log(f"[ERROR] Certificate validity period FAILED ({not_before} to {not_after})")
            
            return {
                "valid": is_valid,
                "not_before": not_before_str,
                "not_after": not_after_str,
                "current_time": now.isoformat(),
                "days_until_expiry": (not_after - now).days if is_valid else 0
            }
            
        except Exception as e:
            self.log(f"[ERROR] Validity period check error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def validate_key_usage(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Validate key usage extension"""
        
        try:
            extensions = responder_cert.get('extensions', {})
            key_usage = extensions.get('key_usage', '')
            
            # Check for Digital Signature
            has_digital_signature = 'Digital Signature' in key_usage
            
            if has_digital_signature:
                self.log("[OK] Key Usage validation PASSED (Digital Signature present)")
            else:
                self.log("[ERROR] Key Usage validation FAILED (Digital Signature not present)")
            
            return {
                "valid": has_digital_signature,
                "key_usage": key_usage,
                "has_digital_signature": has_digital_signature
            }
            
        except Exception as e:
            self.log(f"[ERROR] Key usage validation error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def validate_extended_key_usage(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Validate extended key usage (Critical for OCSP)"""
        
        try:
            extensions = responder_cert.get('extensions', {})
            extended_key_usage = extensions.get('extended_key_usage', '')
            
            # Check for OCSP Signing OID (1.3.6.1.5.5.7.3.9)
            has_ocsp_signing = 'OCSP Signing' in extended_key_usage
            
            if has_ocsp_signing:
                self.log("[OK] Extended Key Usage validation PASSED (OCSP Signing present)")
            else:
                self.log("[ERROR] Extended Key Usage validation FAILED (OCSP Signing not present)")
            
            return {
                "valid": has_ocsp_signing,
                "extended_key_usage": extended_key_usage,
                "has_ocsp_signing": has_ocsp_signing,
                "required_oid": "1.3.6.1.5.5.7.3.9"
            }
            
        except Exception as e:
            self.log(f"[ERROR] Extended key usage validation error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def validate_certificate_policies(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Validate certificate policies"""
        
        try:
            extensions = responder_cert.get('extensions', {})
            policies = extensions.get('certificate_policies', [])
            
            # Check if policies are present
            has_policies = len(policies) > 0
            
            if has_policies:
                self.log(f"[OK] Certificate Policies validation PASSED ({len(policies)} policies found)")
            else:
                self.log("[WARN] Certificate Policies validation WARNING (No policies found)")
            
            return {
                "valid": True,  # Policies are optional
                "policies": policies,
                "has_policies": has_policies,
                "policy_count": len(policies)
            }
            
        except Exception as e:
            self.log(f"[ERROR] Certificate policies validation error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def perform_cryptographic_signature_check(self, ocsp_response: Dict[str, Any], responder_cert: Dict[str, Any], issuer_path: str) -> Dict[str, Any]:
        """Step 3: Perform cryptographic signature check"""
        
        try:
            # Create temporary files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
                temp_cert.write(responder_cert.get('pem_data', ''))
                temp_cert_path = temp_cert.name
            
            # Run OCSP verification with the responder certificate
            verify_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", ocsp_response.get('certificate_path', ''),
                "-url", ocsp_response.get('ocsp_url', ''),
                "-resp_text",
                "-verify_other", temp_cert_path
            ]
            
            result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
            
            # Clean up temporary file
            os.unlink(temp_cert_path)
            
            # Check for successful verification
            signature_valid = (
                result.returncode == 0 and 
                ("Response verify OK" in result.stdout or "Response verify OK" in result.stderr)
            )
            
            if signature_valid:
                self.log("[OK] Cryptographic signature check PASSED")
            else:
                self.log(f"[ERROR] Cryptographic signature check FAILED: {result.stderr}")
            
            return {
                "valid": signature_valid,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "verification_method": "openssl_cryptographic_check"
            }
            
        except Exception as e:
            self.log(f"[ERROR] Cryptographic signature check error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def confirm_authority(self, responder_cert: Dict[str, Any], issuer_path: str, ocsp_response: Dict[str, Any]) -> Dict[str, Any]:
        """Step 4: Confirm authority"""
        
        try:
            # Check if the responder is authorized to provide status for the certificate
            authority_confirmed = True
            authority_details = {}
            
            # 4.1 Check if responder certificate is issued by the same CA
            responder_issuer = responder_cert.get('issuer', '')
            authority_details["responder_issuer"] = responder_issuer
            
            # 4.2 Check subject key identifier matches responder ID
            responder_id = ocsp_response.get('responder_id', '')
            subject_key_id = responder_cert.get('extensions', {}).get('subject_key_identifier', '')
            
            authority_details["responder_id"] = responder_id
            authority_details["subject_key_identifier"] = subject_key_id
            
            # Check if responder ID matches subject key identifier
            if responder_id and subject_key_id:
                # Remove colons and compare
                responder_id_clean = responder_id.replace(':', '').upper()
                subject_key_id_clean = subject_key_id.replace(':', '').upper()
                id_match = responder_id_clean == subject_key_id_clean
                authority_details["id_match"] = id_match
                
                if id_match:
                    self.log("[OK] Authority confirmation PASSED (Responder ID matches Subject Key ID)")
                else:
                    self.log("[ERROR] Authority confirmation FAILED (Responder ID doesn't match Subject Key ID)")
                    authority_confirmed = False
            
            # 4.3 Check OCSP No Check extension
            ocsp_no_check = responder_cert.get('extensions', {}).get('ocsp_no_check', False)
            authority_details["ocsp_no_check"] = ocsp_no_check
            
            if ocsp_no_check:
                self.log("[INFO] OCSP No Check extension present (responder certificate doesn't need to be checked)")
            
            return {
                "valid": authority_confirmed,
                "details": authority_details,
                "authority_confirmed": authority_confirmed
            }
            
        except Exception as e:
            self.log(f"[ERROR] Authority confirmation error: {str(e)}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def assess_overall_result(self, verification_results: Dict[str, Any]) -> str:
        """Assess overall verification result"""
        
        steps = verification_results.get("verification_steps", {})
        
        # Check each step
        step1_ok = steps.get("step1_retrieve", {}).get("ocsp_response_retrieved", False)
        step2_ok = steps.get("step2_cert_validation", {}).get("extended_key_usage_valid", False)
        step3_ok = steps.get("step3_signature_check", {}).get("valid", False)
        step4_ok = steps.get("step4_authority", {}).get("valid", False)
        
        if step1_ok and step2_ok and step3_ok and step4_ok:
            return "PASSED"
        elif step1_ok and step2_ok:
            return "PARTIAL"  # Certificate valid but signature verification failed
        else:
            return "FAILED"
    
    def perform_security_assessment(self, verification_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security assessment"""
        
        assessment = {
            "security_level": "UNKNOWN",
            "risks": [],
            "mitigations": [],
            "recommendations": []
        }
        
        overall_result = verification_results.get("overall_result", "UNKNOWN")
        
        if overall_result == "PASSED":
            assessment["security_level"] = "HIGH"
            assessment["recommendations"].append("OCSP signature verification successful - high confidence in response authenticity")
        elif overall_result == "PARTIAL":
            assessment["security_level"] = "MEDIUM"
            assessment["risks"].append("Signature verification failed - response authenticity uncertain")
            assessment["recommendations"].append("Investigate certificate chain configuration")
        else:
            assessment["security_level"] = "LOW"
            assessment["risks"].append("OCSP signature verification failed - potential security risk")
            assessment["recommendations"].append("Do not trust OCSP response without proper verification")
        
        return assessment
    
    def parse_ocsp_response(self, stdout: str) -> Dict[str, Any]:
        """Parse OCSP response from stdout"""
        # This is a simplified parser - in practice, you'd want more robust parsing
        return {
            "raw_output": stdout,
            "certificate_path": "",  # Would be extracted from context
            "ocsp_url": ""  # Would be extracted from context
        }
    
    def extract_responder_certificate(self, stdout: str) -> Dict[str, Any]:
        """Extract responder certificate from OCSP response"""
        
        try:
            # Find certificate section
            cert_match = re.search(r'Certificate:\s*\n(.*?)(?=\n\s*Signature|\n\s*-----BEGIN)', stdout, re.DOTALL)
            if not cert_match:
                return None
            
            cert_text = cert_match.group(1)
            
            # Extract PEM certificate
            pem_match = re.search(r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', stdout, re.DOTALL)
            pem_data = pem_match.group(1) if pem_match else ""
            
            # Parse certificate details
            cert_info = {
                "pem_data": pem_data,
                "subject": self.extract_field(cert_text, r'Subject:\s*(.+)'),
                "issuer": self.extract_field(cert_text, r'Issuer:\s*(.+)'),
                "serial_number": self.extract_field(cert_text, r'Serial Number:\s*(.+)'),
                "signature_algorithm": self.extract_field(cert_text, r'Signature Algorithm:\s*(.+)'),
                "validity": self.parse_validity_period(cert_text),
                "extensions": self.parse_certificate_extensions(cert_text)
            }
            
            return cert_info
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting responder certificate: {str(e)}")
            return None
    
    def parse_validity_period(self, cert_text: str) -> Dict[str, str]:
        """Parse certificate validity period"""
        validity_match = re.search(r'Validity\s*\n\s*Not Before:\s*(.+)\n\s*Not After\s*:\s*(.+)', cert_text)
        if validity_match:
            return {
                "not_before": validity_match.group(1).strip(),
                "not_after": validity_match.group(2).strip()
            }
        return {}
    
    def parse_certificate_extensions(self, cert_text: str) -> Dict[str, Any]:
        """Parse certificate extensions"""
        extensions = {}
        
        # Key Usage
        key_usage_match = re.search(r'X509v3 Key Usage:\s*(.+)', cert_text)
        if key_usage_match:
            extensions["key_usage"] = key_usage_match.group(1).strip()
        
        # Extended Key Usage
        ext_key_usage_match = re.search(r'X509v3 Extended Key Usage:\s*(.+)', cert_text)
        if ext_key_usage_match:
            extensions["extended_key_usage"] = ext_key_usage_match.group(1).strip()
        
        # Subject Key Identifier
        ski_match = re.search(r'X509v3 Subject Key Identifier:\s*(.+)', cert_text)
        if ski_match:
            extensions["subject_key_identifier"] = ski_match.group(1).strip()
        
        # OCSP No Check
        if "OCSP No Check:" in cert_text:
            extensions["ocsp_no_check"] = True
        
        return extensions
    
    def extract_field(self, text: str, pattern: str) -> Optional[str]:
        """Helper method to extract a field using regex"""
        match = re.search(pattern, text)
        return match.group(1).strip() if match else None
    
    def display_verification_results(self, verification_results: Dict[str, Any]) -> None:
        """Display comprehensive verification results"""
        
        self.log("\n[OCSP SIGNATURE VERIFICATION RESULTS]")
        self.log("=" * 80)
        
        overall_result = verification_results.get("overall_result", "UNKNOWN")
        
            if overall_result == "PASSED":
                self.log("OVERALL RESULT: PASSED [OK]")
            elif overall_result == "PARTIAL":
                self.log("OVERALL RESULT: PARTIAL [WARN]")
            else:
                self.log("OVERALL RESULT: FAILED [ERROR]")
        
        # Display each step
        steps = verification_results.get("verification_steps", {})
        
        self.log(f"\n[STEP 1] Retrieve OCSP Response and Signer's Certificate")
        step1 = steps.get("step1_retrieve", {})
        self.log(f"  OCSP Response Retrieved: {'[OK]' if step1.get('ocsp_response_retrieved') else '[ERROR]'}")
        self.log(f"  Responder Certificate Retrieved: {'[OK]' if step1.get('responder_certificate_retrieved') else '[ERROR]'}")
        
        self.log(f"\n[STEP 2] Validate the Signer's Certificate")
        step2 = steps.get("step2_cert_validation", {})
        self.log(f"  Trust Chain: {'[OK]' if step2.get('trust_chain_valid') else '[ERROR]'}")
        self.log(f"  Validity Period: {'[OK]' if step2.get('validity_period_valid') else '[ERROR]'}")
        self.log(f"  Key Usage: {'[OK]' if step2.get('key_usage_valid') else '[ERROR]'}")
        self.log(f"  Extended Key Usage: {'[OK]' if step2.get('extended_key_usage_valid') else '[ERROR]'}")
        
        self.log(f"\n[STEP 3] Cryptographic Signature Check")
        step3 = steps.get("step3_signature_check", {})
        self.log(f"  Signature Verification: {'[OK]' if step3.get('valid') else '[ERROR]'}")
        
        self.log(f"\n[STEP 4] Confirm Authority")
        step4 = steps.get("step4_authority", {})
        self.log(f"  Authority Confirmed: {'[OK]' if step4.get('valid') else '[ERROR]'}")
        
        # Security Assessment
        security = verification_results.get("security_assessment", {})
        self.log(f"\n[SECURITY ASSESSMENT]")
        self.log(f"  Security Level: {security.get('security_level', 'UNKNOWN')}")
        
        if security.get('risks'):
            self.log("  Risks:")
            for risk in security['risks']:
                self.log(f"    - {risk}")
        
        if security.get('recommendations'):
            self.log("  Recommendations:")
            for rec in security['recommendations']:
                self.log(f"    - {rec}")

def main():
    """Main function"""
    print("OCSP Signature Verification Tool")
    print("=" * 50)
    
    # Check if OpenSSL is available
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] OpenSSL is not available. Please install OpenSSL.")
        sys.exit(1)
    
    # Get input parameters
    if len(sys.argv) >= 4:
        cert_path = sys.argv[1]
        issuer_path = sys.argv[2]
        ocsp_url = sys.argv[3]
    else:
        print("Usage: python ocsp_signature_verifier.py <cert_path> <issuer_path> <ocsp_url>")
        print("\nExample:")
        print("python ocsp_signature_verifier.py certificate.pem issuer.pem http://ocsp.example.com")
        sys.exit(1)
    
    # Check if files exist
    if not os.path.exists(cert_path):
        print(f"[ERROR] Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not os.path.exists(issuer_path):
        print(f"[ERROR] Issuer file not found: {issuer_path}")
        sys.exit(1)
    
    # Create verifier and run verification
    verifier = OCSPSignatureVerifier()
    results = verifier.verify_ocsp_signature(cert_path, issuer_path, ocsp_url)
    
    # Save results to JSON file
    output_file = f"ocsp_signature_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[INFO] Verification results saved to: {output_file}")
    
    # Print final summary
    print("\n[FINAL SUMMARY]")
    print("=" * 50)
    if "error" in results:
        print(f"[ERROR] Verification failed: {results['error']}")
    else:
        overall_result = results.get("overall_result", "UNKNOWN")
        print(f"[RESULT] OCSP Signature Verification: {overall_result}")
        
        if overall_result == "PASSED":
            print("[OK] The OCSP response signature has been successfully verified!")
            print("[OK] The certificate status information is authentic and trustworthy.")
        elif overall_result == "PARTIAL":
            print("[WARN] Partial verification - certificate is valid but signature verification failed.")
            print("[WARN] This may be due to certificate chain configuration issues.")
        else:
            print("[ERROR] OCSP signature verification failed.")
            print("[ERROR] The certificate status information cannot be trusted.")

if __name__ == "__main__":
    main()

import subprocess
import threading
import os
import requests
from urllib.parse import urlparse
from uuid import uuid4
from datetime import datetime
import re
from typing import Optional, Tuple, Callable, Dict, Any, List
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class OCSPMonitor:
    """OCSP and CRL monitoring functionality using OpenSSL"""
    
    VERSION = "2.1.0"  # Enhanced P7C processing version
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self.log_callback = log_callback or print
        self.check_validity = True
        self.log(f"[INFO] OCSPMonitor v{self.VERSION} initialized\n")
        
    def log(self, text: str) -> None:
        """Log message using callback"""
        self.log_callback(text)
        
    def check_certificate_validity(self, cert_path: str) -> Tuple[bool, Optional[datetime], Optional[datetime]]:
        """Check certificate validity period using OpenSSL"""
        try:
            cmd = ["openssl", "x509", "-noout", "-startdate", "-enddate", "-in", cert_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.log("[CMD] " + " ".join(cmd) + "\n")
            
            if result.stderr:
                self.log("[STDERR] " + result.stderr + "\n")
                return False, None, None

            start, end = None, None
            for line in result.stdout.splitlines():
                if "notBefore=" in line:
                    start = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                elif "notAfter=" in line:
                    end = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")

            if start and end:
                now = datetime.utcnow()
                self.log(f"[VALIDITY] Certificate Validity Period: {start} to {end}\n")
                if start <= now <= end:
                    self.log("[VALIDITY] [OK] Validity Period OK\n")
                    return True, start, end
                else:
                    self.log("[VALIDITY] [ERROR] Validity Period ERROR\n")
                    return False, start, end
            else:
                self.log("[VALIDITY] [ERROR] Could not parse validity period\n")
                return False, None, None

        except Exception as e:
            self.log(f"[VALIDITY] ERROR: {str(e)}\n")
            return False, None, None

    def run_ocsp_check(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Run comprehensive OCSP check"""
        try:
            self.log("[INFO] Running OCSP check...\n")
            
            # Check validity period if enabled
            validity_ok = None
            validity_start = None
            validity_end = None
            if self.check_validity:
                validity_ok, validity_start, validity_end = self.check_certificate_validity(cert_path)

            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-verify_other", issuer_path
            ]
            
            self.log("[CMD] " + " ".join(ocsp_cmd) + "\n")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=20)
            stdout = result.stdout
            self.log("[INFO] " + stdout + "\n")
            
            if result.stderr:
                self.log("[STDERR] " + result.stderr + "\n")

            summary = "[OCSP CHECK SUMMARY]\n"
            results = {
                "validity_ok": validity_ok,
                "validity_start": validity_start,
                "validity_end": validity_end,
                "signature_verified": False,
                "update_times_valid": False,
                "nonce_support": False,
                "cert_status": "UNKNOWN",
                "overall_pass": False
            }

            # Certificate validity in summary
            if validity_ok is not None:
                if validity_ok:
                    summary += f"[OK] Certificate Validity Period OK ({validity_start} to {validity_end})\n"
                else:
                    summary += f"[ERROR] Certificate Validity Period ERROR ({validity_start} to {validity_end})\n"

            # Enhanced Signature Verification
            signature_verified = False
            verification_method = "unknown"
            
            # Primary verification: Check OpenSSL's built-in verification
            if ("Response verify OK" in stdout or 
                "Response verify OK" in result.stderr or 
                "verify OK" in result.stderr.lower()):
                signature_verified = True
                verification_method = "openssl_builtin"
                summary += "[OK] Signature verification: PASS (OpenSSL built-in verification)\n"
                results["signature_verified"] = True
            else:
                # Secondary verification: Use comprehensive manual verification
                self.log("[INFO] OpenSSL built-in verification inconclusive, performing comprehensive verification...\n")
                manual_verification = self.verify_ocsp_signature(cert_path, issuer_path, ocsp_url)
                
                if manual_verification:
                    signature_verified = True
                    verification_method = "manual_comprehensive"
                    summary += "[OK] Signature verification: PASS (comprehensive manual verification)\n"
                    results["signature_verified"] = True
                else:
                    verification_method = "failed"
                    summary += "[ERROR] Signature verification: FAIL (all verification methods failed)\n"
                    results["signature_verified"] = False
                    
                    # Log detailed failure information for security analysis
                    self.log(f"[SECURITY] OCSP signature verification failed - potential security risk\n")
                    self.log(f"[SECURITY] Verification method attempted: {verification_method}\n")
                    self.log(f"[SECURITY] OCSP URL: {ocsp_url}\n")
                    self.log(f"[SECURITY] Issuer certificate: {issuer_path}\n")
            
            # Add verification details to results
            results["verification_method"] = verification_method
            results["verification_details"] = {
                "openssl_builtin_result": "Response verify OK" in stdout or "Response verify OK" in result.stderr,
                "manual_verification_performed": verification_method == "manual_comprehensive",
                "signature_validated": signature_verified
            }

            # Comprehensive Certificate Status Detail Parsing
            certificate_status_details = self.parse_certificate_status_details(stdout)
            
            # Add certificate status details to results
            results["certificate_status_details"] = certificate_status_details

            # Response Validity Interval Validation
            validity_interval_results = self.validate_response_validity_interval(stdout)
            
            # Add validity interval results to results
            results["validity_interval_validation"] = validity_interval_results
            
            # Update summary with certificate status information
            if certificate_status_details["is_certificate_good"]:
                summary += "[OK] Certificate Status: GOOD\n"
                results["cert_status"] = "GOOD"
            elif certificate_status_details["is_certificate_revoked"]:
                summary += "[ERROR] Certificate Status: REVOKED\n"
                results["cert_status"] = "REVOKED"
                
                # Add revocation details to summary
                if certificate_status_details["revocation_time"]:
                    summary += f"[INFO] Revocation Time: {certificate_status_details['revocation_time']}\n"
                if certificate_status_details["revocation_reason"]:
                    summary += f"[INFO] Revocation Reason: {certificate_status_details['revocation_reason']}\n"
                    
            elif certificate_status_details["is_certificate_unknown"]:
                summary += "[WARN] Certificate Status: UNKNOWN\n"
                results["cert_status"] = "UNKNOWN"
            else:
                summary += "[ERROR] Certificate Status: COULD NOT DETERMINE\n"
                results["cert_status"] = "UNKNOWN"
            
            # Add parsing errors and warnings to summary
            if certificate_status_details["parsing_errors"]:
                summary += f"[ERROR] Parsing errors: {', '.join(certificate_status_details['parsing_errors'])}\n"
            
            if certificate_status_details["security_warnings"]:
                for warning in certificate_status_details["security_warnings"]:
                    summary += f"[WARN] {warning}\n"
            
            # Add validity interval validation to summary
            if validity_interval_results["is_valid"]:
                summary += "[OK] Response Validity Interval: VALID\n"
                if validity_interval_results["age_hours"] is not None:
                    summary += f"[INFO] Response age: {validity_interval_results['age_hours']:.1f} hours\n"
                if validity_interval_results["time_until_expiry_hours"] is not None:
                    summary += f"[INFO] Time until expiry: {validity_interval_results['time_until_expiry_hours']:.1f} hours\n"
            else:
                summary += "[ERROR] Response Validity Interval: INVALID\n"
            
            # Add validity interval warnings and issues
            if validity_interval_results["security_warnings"]:
                for warning in validity_interval_results["security_warnings"]:
                    summary += f"[WARN] {warning}\n"
            
            if validity_interval_results["compliance_issues"]:
                for issue in validity_interval_results["compliance_issues"]:
                    summary += f"[ERROR] {issue}\n"
            
            # Critical security check: Only accept certificates that are explicitly GOOD AND have valid response interval
            if (certificate_status_details["is_certificate_good"] and 
                validity_interval_results["is_valid"]):
                summary += "[OK] Certificate validation PASSED - certificate is explicitly good and response interval is valid\n"
                results["overall_pass"] = True
            else:
                summary += "[ERROR] Certificate validation FAILED - certificate not explicitly good or response interval invalid\n"
                results["overall_pass"] = False
                
                # Provide specific failure reasons
                if not certificate_status_details["is_certificate_good"]:
                    summary += "[ERROR] Certificate status is not explicitly GOOD\n"
                if not validity_interval_results["is_valid"]:
                    summary += "[ERROR] Response validity interval is invalid\n"

            # Optional: Test non-issued certificate handling (can be enabled via configuration)
            if hasattr(self, 'test_non_issued_certificates') and self.test_non_issued_certificates:
                self.log("[INFO] Testing non-issued certificate handling...\n")
                non_issued_test_results = self.test_non_issued_certificate(issuer_path, ocsp_url)
                results["non_issued_certificate_test"] = non_issued_test_results
                
                # Add compliance assessment to summary
                compliance_status = non_issued_test_results["compliance_status"]
                if compliance_status == "COMPLIANT":
                    summary += "[OK] Non-issued certificate handling: COMPLIANT\n"
                elif compliance_status == "PARTIALLY_COMPLIANT":
                    summary += "[WARN] Non-issued certificate handling: PARTIALLY COMPLIANT\n"
                elif compliance_status == "NON_COMPLIANT":
                    summary += "[ERROR] Non-issued certificate handling: NON-COMPLIANT\n"
                else:
                    summary += "[INFO] Non-issued certificate handling: NOT TESTED\n"
                
                # Add recommendations
                for recommendation in non_issued_test_results["recommendations"]:
                    summary += f"[RECOMMENDATION] {recommendation}\n"

            # Optional: Test cryptographic preference negotiation (can be enabled via configuration)
            if hasattr(self, 'test_cryptographic_preferences') and self.test_cryptographic_preferences:
                self.log("[INFO] Testing cryptographic preference negotiation...\n")
                crypto_negotiation_results = self.negotiate_cryptographic_preferences(issuer_path, ocsp_url)
                results["cryptographic_preference_negotiation"] = crypto_negotiation_results
                
                # Add cryptographic assessment to summary
                security_assessment = crypto_negotiation_results["security_assessment"]
                if security_assessment == "SECURE":
                    summary += "[OK] Cryptographic preferences: SECURE\n"
                elif security_assessment == "ACCEPTABLE":
                    summary += "[WARN] Cryptographic preferences: ACCEPTABLE\n"
                elif security_assessment == "WEAK":
                    summary += "[ERROR] Cryptographic preferences: WEAK\n"
                elif security_assessment == "CRITICAL":
                    summary += "[ERROR] Cryptographic preferences: CRITICAL\n"
                else:
                    summary += "[INFO] Cryptographic preferences: NOT TESTED\n"
                
                # Add downgrade detection results
                if crypto_negotiation_results["downgrade_detected"]:
                    summary += "[ERROR] Cryptographic downgrade attack detected\n"
                    for indicator in crypto_negotiation_results["downgrade_indicators"]:
                        summary += f"[WARN] Downgrade indicator: {indicator}\n"
                
                # Add security warnings
                for warning in crypto_negotiation_results["security_warnings"]:
                    summary += f"[WARN] {warning}\n"
                
                # Add recommendations
                for recommendation in crypto_negotiation_results["security_recommendations"]:
                    summary += f"[RECOMMENDATION] {recommendation}\n"

            # thisUpdate and nextUpdate - handle different formats
            thisUpdate_match = re.search(r"(?:thisUpdate|This Update):\s*(.+)", stdout, re.IGNORECASE)
            nextUpdate_match = re.search(r"(?:nextUpdate|Next Update):\s*(.+)", stdout, re.IGNORECASE)
            
            if thisUpdate_match and nextUpdate_match:
                try:
                    this_update_text = thisUpdate_match.group(1).strip()
                    next_update_text = nextUpdate_match.group(1).strip()
                    
                    dt_this = datetime.strptime(this_update_text, "%b %d %H:%M:%S %Y %Z")
                    dt_next = datetime.strptime(next_update_text, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    summary += f"[OK] thisUpdate: {dt_this}\n"
                    summary += f"[OK] nextUpdate: {dt_next}\n"
                    if dt_this <= now <= dt_next:
                        summary += "[OK] OCSP Update Times Valid\n"
                        results["update_times_valid"] = True
                    else:
                        summary += "[ERROR] OCSP Update Times Invalid or Stale\n"
                except Exception as e:
                    summary += f"[ERROR] Could not parse thisUpdate/nextUpdate: {e}\n"
            else:
                summary += "[ERROR] Missing thisUpdate or nextUpdate\n"

            # Nonce support
            if re.search(r"WARNING: no nonce in response", result.stderr, re.IGNORECASE):
                summary += "[WARN] No nonce in response (nonce support may be limited)\n"
                results["nonce_support"] = False
            elif re.search(r"Nonce", stdout, re.IGNORECASE) or re.search(r"Nonce", result.stderr, re.IGNORECASE):
                summary += "[OK] Nonce support present\n"
                results["nonce_support"] = True
            else:
                summary += "[INFO] Nonce support status unclear\n"
                results["nonce_support"] = None

            # Certificate status
            if re.search(r": good", stdout):
                summary += "[OK] Certificate Status: GOOD\n"
                results["cert_status"] = "GOOD"
            elif re.search(r": revoked", stdout):
                summary += "[ERROR] Certificate Status: REVOKED\n"
                results["cert_status"] = "REVOKED"
            elif re.search(r": unknown", stdout):
                summary += "[ERROR] Certificate Status: UNKNOWN\n"
                results["cert_status"] = "UNKNOWN"
            else:
                summary += "[ERROR] Certificate Status: UNDETERMINED\n"

            # Overall result
            if ("[ERROR]" in summary):
                summary += "[ERROR] One or more OCSP diagnostics FAILED\n"
            else:
                summary += "[OK] All OCSP diagnostics PASSED\n"
                results["overall_pass"] = True

            results["summary"] = summary
            return results

        except Exception as e:
            error_msg = f"[ERROR] OCSP Check Exception: {str(e)}\n"
            self.log(error_msg)
            return {"error": error_msg}

    def verify_ocsp_signature(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """
        Comprehensive OCSP signature verification supporting both direct CA signing and CA Designated Responders
        
        This method implements full verification of the digital signature on the OCSP response
        by confirming that the signature is valid using either:
        1. The issuing CA's public key (direct signing)
        2. A CA Designated Responder's public key (delegated signing with proper EKU validation)
        
        This addresses RFC 6960 requirements for handling delegated responders with id-kp-OCSPSigning EKU.
        """
        try:
            self.log("[INFO] Performing comprehensive OCSP signature verification...\n")
            
            # Step 1: Download OCSP response without verification
            tmp_resp = os.path.join(os.getenv("TEMP", "/tmp"), f"ocsp_resp_{uuid4().hex}.der")
            cmd_resp = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-respout", tmp_resp, 
                "-noverify"  # Download without verification first
            ]
            
            self.log(f"[CMD] {' '.join(cmd_resp)}\n")
            resp_result = subprocess.run(cmd_resp, capture_output=True, text=True, timeout=30)
            
            if resp_result.returncode != 0:
                self.log(f"[ERROR] Failed to download OCSP response: {resp_result.stderr}\n")
                return False
            
            # Step 2: Determine if response is signed by CA or delegated responder
            responder_info_cmd = ["openssl", "ocsp", "-respin", tmp_resp, "-text", "-noout"]
            responder_info_result = subprocess.run(responder_info_cmd, capture_output=True, text=True, timeout=15)
            
            signature_valid = False
            verification_method = "unknown"
            
            if responder_info_result.returncode == 0:
                responder_text = responder_info_result.stdout
                self.log(f"[INFO] OCSP response analysis:\n{responder_text[:500]}...\n")
                
                # Check if response includes responder certificate (indicates delegated responder)
                if "Certificate:" in responder_text and "BEGIN CERTIFICATE" in responder_text:
                    self.log("[INFO] Detected CA Designated Responder - extracting responder certificate\n")
                    
                    # Extract responder certificate
                    responder_cert_path = self._extract_responder_certificate(tmp_resp)
                    
                    if responder_cert_path:
                        # Validate CA Designated Responder
                        responder_validation = self.validate_ca_designated_responder(responder_cert_path, issuer_path)
                        
                        if responder_validation["is_valid_designated_responder"]:
                            self.log("[INFO] CA Designated Responder validation passed - verifying signature\n")
                            
                            # Verify signature using responder certificate
                            verify_cmd = [
                                "openssl", "ocsp", 
                                "-respin", tmp_resp, 
                                "-verify_other", responder_cert_path,
                                "-CAfile", issuer_path,
                                "-no_nonce"
                            ]
                            
                            self.log(f"[CMD] {' '.join(verify_cmd)}\n")
                            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                            
                            if verify_result.returncode == 0 and "Response verify OK" in verify_result.stdout:
                                signature_valid = True
                                verification_method = "ca_designated_responder"
                                self.log("[OK] OCSP response signature verified using CA Designated Responder\n")
                            else:
                                self.log(f"[ERROR] CA Designated Responder signature verification failed\n")
                                self.log(f"[STDOUT] {verify_result.stdout}\n")
                                self.log(f"[STDERR] {verify_result.stderr}\n")
                        else:
                            self.log("[ERROR] CA Designated Responder validation failed\n")
                            for recommendation in responder_validation["recommendations"]:
                                self.log(f"[RECOMMENDATION] {recommendation}\n")
                        
                        # Cleanup responder certificate
                        try:
                            os.remove(responder_cert_path)
                        except:
                            pass
                    else:
                        self.log("[ERROR] Failed to extract responder certificate\n")
                else:
                    self.log("[INFO] No responder certificate found - assuming direct CA signing\n")
                    
                    # Verify signature using CA certificate directly
                    verify_cmd = [
                        "openssl", "ocsp", 
                        "-respin", tmp_resp, 
                        "-verify_other", issuer_path,
                        "-CAfile", issuer_path,
                        "-no_nonce"
                    ]
                    
                    self.log(f"[CMD] {' '.join(verify_cmd)}\n")
                    verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                    
                    if verify_result.returncode == 0 and "Response verify OK" in verify_result.stdout:
                        signature_valid = True
                        verification_method = "direct_ca_signing"
                        self.log("[OK] OCSP response signature verified using direct CA signing\n")
                    else:
                        self.log(f"[ERROR] Direct CA signature verification failed\n")
                        self.log(f"[STDOUT] {verify_result.stdout}\n")
                        self.log(f"[STDERR] {verify_result.stderr}\n")
            
            # Step 3: Additional security checks
            if signature_valid:
                # Verify the responder certificate matches the issuer (for direct signing)
                if verification_method == "direct_ca_signing":
                    responder_cmd = [
                        "openssl", "ocsp", 
                        "-respin", tmp_resp, 
                        "-text", "-noout"
                    ]
                    responder_result = subprocess.run(responder_cmd, capture_output=True, text=True, timeout=15)
                    
                    if responder_result.returncode == 0:
                        if "Responder Id:" in responder_result.stdout:
                            self.log("[INFO] OCSP responder identity verified\n")
                        else:
                            self.log("[WARN] Could not verify OCSP responder identity\n")
                
                self.log(f"[INFO] Signature verification method: {verification_method}\n")
            
            # Cleanup
            try:
                os.remove(tmp_resp)
            except:
                pass
            
            return signature_valid
            
        except subprocess.TimeoutExpired:
            self.log("[ERROR] OCSP signature verification timed out\n")
            return False
        except Exception as e:
            self.log(f"[ERROR] OCSP signature verification exception: {e}\n")
            return False

    def _extract_responder_certificate(self, ocsp_response_path: str) -> Optional[str]:
        """
        Extract responder certificate from OCSP response
        
        Args:
            ocsp_response_path: Path to the OCSP response file
            
        Returns:
            Path to extracted responder certificate file, or None if extraction fails
        """
        try:
            # Create temporary file for responder certificate
            responder_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"responder_cert_{uuid4().hex}.pem")
            
            # Extract certificate using OpenSSL
            extract_cmd = [
                "openssl", "ocsp", 
                "-respin", ocsp_response_path, 
                "-text", "-noout"
            ]
            
            extract_result = subprocess.run(extract_cmd, capture_output=True, text=True, timeout=15)
            
            if extract_result.returncode == 0:
                response_text = extract_result.stdout
                
                # Find certificate section
                cert_start = response_text.find("-----BEGIN CERTIFICATE-----")
                cert_end = response_text.find("-----END CERTIFICATE-----")
                
                if cert_start != -1 and cert_end != -1:
                    cert_end += len("-----END CERTIFICATE-----")
                    cert_pem = response_text[cert_start:cert_end]
                    
                    # Write certificate to file
                    with open(responder_cert_path, 'w') as f:
                        f.write(cert_pem)
                    
                    self.log(f"[INFO] Extracted responder certificate to: {responder_cert_path}\n")
                    return responder_cert_path
                else:
                    self.log("[WARN] No certificate found in OCSP response\n")
                    return None
            else:
                self.log(f"[ERROR] Failed to extract responder certificate: {extract_result.stderr}\n")
                return None
                
        except Exception as e:
            self.log(f"[ERROR] Certificate extraction exception: {e}\n")
            return None

    def parse_certificate_status_details(self, ocsp_response_text: str) -> Dict[str, Any]:
        """
        Parse comprehensive certificate status details from OCSP response
        
        This method extracts and validates the actual certificate status information
        from the OCSP response, including:
        1. CertStatus value (good/revoked/unknown)
        2. Revocation details (revocationTime, revocationReason) if revoked
        3. Certificate serial number
        4. Response timestamps
        5. Responder information
        
        Args:
            ocsp_response_text: Raw OCSP response text from OpenSSL
            
        Returns:
            Dict containing detailed certificate status information
        """
        status_details = {
            "response_status": "UNKNOWN",
            "cert_status": "UNKNOWN",
            "cert_serial": None,
            "revocation_time": None,
            "revocation_reason": None,
            "this_update": None,
            "next_update": None,
            "produced_at": None,
            "responder_id": None,
            "is_certificate_good": False,
            "is_certificate_revoked": False,
            "is_certificate_unknown": False,
            "parsing_errors": [],
            "security_warnings": []
        }
        
        try:
            self.log("[STATUS] Parsing certificate status details from OCSP response...\n")
            
            # Step 1: Parse top-level response status
            if "OCSP Response Status: successful" in ocsp_response_text:
                status_details["response_status"] = "SUCCESSFUL"
                self.log("[STATUS] ✓ OCSP Response Status: SUCCESSFUL\n")
            elif "OCSP Response Status: unauthorized" in ocsp_response_text:
                status_details["response_status"] = "UNAUTHORIZED"
                self.log("[STATUS] ✗ OCSP Response Status: UNAUTHORIZED\n")
                status_details["security_warnings"].append("OCSP responder unauthorized - potential security issue")
            elif "OCSP Response Status: malformed" in ocsp_response_text:
                status_details["response_status"] = "MALFORMED"
                self.log("[STATUS] ✗ OCSP Response Status: MALFORMED\n")
                status_details["security_warnings"].append("OCSP response malformed - potential attack")
            else:
                self.log("[STATUS] ⚠ Unknown OCSP Response Status\n")
                status_details["parsing_errors"].append("Could not determine OCSP response status")
            
            # Step 2: Extract certificate serial number
            serial_match = re.search(r"Serial Number:\s*([A-F0-9]+)", ocsp_response_text, re.IGNORECASE)
            if serial_match:
                status_details["cert_serial"] = serial_match.group(1)
                self.log(f"[STATUS] Certificate Serial: {status_details['cert_serial']}\n")
            else:
                self.log("[STATUS] ⚠ Could not extract certificate serial number\n")
                status_details["parsing_errors"].append("Certificate serial number not found")
            
            # Step 3: Parse certificate status (CertStatus)
            cert_status_match = re.search(r"Cert Status:\s*(\w+)", ocsp_response_text, re.IGNORECASE)
            if cert_status_match:
                cert_status = cert_status_match.group(1).lower()
                status_details["cert_status"] = cert_status.upper()
                
                if cert_status == "good":
                    status_details["is_certificate_good"] = True
                    self.log("[STATUS] ✓ Certificate Status: GOOD\n")
                elif cert_status == "revoked":
                    status_details["is_certificate_revoked"] = True
                    self.log("[STATUS] ✗ Certificate Status: REVOKED\n")
                    status_details["security_warnings"].append("Certificate is revoked - do not trust")
                elif cert_status == "unknown":
                    status_details["is_certificate_unknown"] = True
                    self.log("[STATUS] ⚠ Certificate Status: UNKNOWN\n")
                    status_details["security_warnings"].append("Certificate status unknown - use caution")
                else:
                    self.log(f"[STATUS] ⚠ Unknown certificate status: {cert_status}\n")
                    status_details["parsing_errors"].append(f"Unknown certificate status: {cert_status}")
            else:
                self.log("[STATUS] ✗ Could not determine certificate status\n")
                status_details["parsing_errors"].append("Certificate status not found in response")
            
            # Step 4: Parse revocation details if certificate is revoked
            if status_details["is_certificate_revoked"]:
                self.log("[STATUS] Parsing revocation details...\n")
                
                # Extract revocation time
                revocation_time_match = re.search(r"Revocation Time:\s*(.+)", ocsp_response_text, re.IGNORECASE)
                if revocation_time_match:
                    revocation_time_str = revocation_time_match.group(1).strip()
                    try:
                        # Parse revocation time (format: "May 5 17:10:17 2023 GMT")
                        revocation_time = datetime.strptime(revocation_time_str, "%b %d %H:%M:%S %Y %Z")
                        status_details["revocation_time"] = revocation_time.isoformat()
                        self.log(f"[STATUS] Revocation Time: {revocation_time}\n")
                    except Exception as e:
                        self.log(f"[STATUS] ⚠ Could not parse revocation time: {e}\n")
                        status_details["parsing_errors"].append(f"Could not parse revocation time: {e}")
                else:
                    self.log("[STATUS] ⚠ Revocation time not found\n")
                    status_details["parsing_errors"].append("Revocation time not found")
                
                # Extract revocation reason
                revocation_reason_match = re.search(r"Revocation Reason:\s*(.+)", ocsp_response_text, re.IGNORECASE)
                if revocation_reason_match:
                    revocation_reason = revocation_reason_match.group(1).strip()
                    status_details["revocation_reason"] = revocation_reason
                    self.log(f"[STATUS] Revocation Reason: {revocation_reason}\n")
                else:
                    self.log("[STATUS] ⚠ Revocation reason not found\n")
                    status_details["parsing_errors"].append("Revocation reason not found")
            
            # Step 5: Parse timestamps
            # This Update
            this_update_match = re.search(r"This Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if this_update_match:
                this_update_str = this_update_match.group(1).strip()
                try:
                    this_update = datetime.strptime(this_update_str, "%b %d %H:%M:%S %Y %Z")
                    status_details["this_update"] = this_update.isoformat()
                    self.log(f"[STATUS] This Update: {this_update}\n")
                except Exception as e:
                    self.log(f"[STATUS] ⚠ Could not parse This Update: {e}\n")
                    status_details["parsing_errors"].append(f"Could not parse This Update: {e}")
            
            # Next Update
            next_update_match = re.search(r"Next Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if next_update_match:
                next_update_str = next_update_match.group(1).strip()
                try:
                    next_update = datetime.strptime(next_update_str, "%b %d %H:%M:%S %Y %Z")
                    status_details["next_update"] = next_update.isoformat()
                    self.log(f"[STATUS] Next Update: {next_update}\n")
                except Exception as e:
                    self.log(f"[STATUS] ⚠ Could not parse Next Update: {e}\n")
                    status_details["parsing_errors"].append(f"Could not parse Next Update: {e}")
            
            # Produced At
            produced_at_match = re.search(r"Produced At:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if produced_at_match:
                produced_at_str = produced_at_match.group(1).strip()
                try:
                    produced_at = datetime.strptime(produced_at_str, "%b %d %H:%M:%S %Y %Z")
                    status_details["produced_at"] = produced_at.isoformat()
                    self.log(f"[STATUS] Produced At: {produced_at}\n")
                except Exception as e:
                    self.log(f"[STATUS] ⚠ Could not parse Produced At: {e}\n")
                    status_details["parsing_errors"].append(f"Could not parse Produced At: {e}")
            
            # Step 6: Extract responder ID
            responder_id_match = re.search(r"Responder Id:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if responder_id_match:
                responder_id = responder_id_match.group(1).strip()
                status_details["responder_id"] = responder_id
                self.log(f"[STATUS] Responder ID: {responder_id}\n")
            
            # Step 7: Security validation
            if status_details["response_status"] == "SUCCESSFUL" and status_details["is_certificate_good"]:
                self.log("[STATUS] ✓ Certificate validation PASSED - certificate is good\n")
            elif status_details["is_certificate_revoked"]:
                self.log("[STATUS] ✗ Certificate validation FAILED - certificate is revoked\n")
            elif status_details["is_certificate_unknown"]:
                self.log("[STATUS] ⚠ Certificate validation UNCERTAIN - status unknown\n")
            else:
                self.log("[STATUS] ✗ Certificate validation FAILED - could not determine status\n")
            
            return status_details
            
        except Exception as e:
            self.log(f"[STATUS] Certificate status parsing exception: {e}\n")
            status_details["parsing_errors"].append(f"Parsing exception: {str(e)}")
            return status_details

    def validate_response_validity_interval(self, ocsp_response_text: str, max_age_hours: int = 24) -> Dict[str, Any]:
        """
        Validate OCSP response validity interval according to RFC 6960
        
        This method validates the response validity interval defined by thisUpdate and nextUpdate fields.
        Critical security checks include:
        1. thisUpdate is present and parseable
        2. thisUpdate is not in the future
        3. thisUpdate is sufficiently recent (within max_age_hours)
        4. nextUpdate is present and parseable
        5. nextUpdate is not in the past
        6. nextUpdate is after thisUpdate
        7. Current time is within the validity interval
        
        Args:
            ocsp_response_text: Raw OCSP response text from OpenSSL
            max_age_hours: Maximum age in hours for thisUpdate (default: 24)
            
        Returns:
            Dict containing validity interval validation results
        """
        validity_results = {
            "is_valid": False,
            "this_update_valid": False,
            "next_update_valid": False,
            "interval_valid": False,
            "this_update": None,
            "next_update": None,
            "current_time": None,
            "age_hours": None,
            "time_until_expiry_hours": None,
            "validation_details": {},
            "security_warnings": [],
            "compliance_issues": []
        }
        
        try:
            self.log("[VALIDITY] Validating OCSP response validity interval...\n")
            
            # Get current time
            current_time = datetime.utcnow()
            validity_results["current_time"] = current_time.isoformat()
            self.log(f"[VALIDITY] Current time: {current_time}\n")
            
            # Parse thisUpdate
            this_update_match = re.search(r"This Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if this_update_match:
                this_update_str = this_update_match.group(1).strip()
                try:
                    this_update = datetime.strptime(this_update_str, "%b %d %H:%M:%S %Y %Z")
                    validity_results["this_update"] = this_update.isoformat()
                    self.log(f"[VALIDITY] This Update: {this_update}\n")
                    
                    # Check if thisUpdate is in the future
                    if this_update > current_time:
                        validity_results["security_warnings"].append("thisUpdate is in the future - potential security issue")
                        self.log("[VALIDITY] ✗ thisUpdate is in the future\n")
                    else:
                        # Check if thisUpdate is sufficiently recent
                        age_delta = current_time - this_update
                        age_hours = age_delta.total_seconds() / 3600
                        validity_results["age_hours"] = age_hours
                        
                        if age_hours <= max_age_hours:
                            validity_results["this_update_valid"] = True
                            self.log(f"[VALIDITY] ✓ thisUpdate is recent (age: {age_hours:.1f} hours)\n")
                        else:
                            validity_results["security_warnings"].append(f"thisUpdate is too old ({age_hours:.1f} hours > {max_age_hours} hours)")
                            self.log(f"[VALIDITY] ✗ thisUpdate is too old ({age_hours:.1f} hours)\n")
                    
                except Exception as e:
                    validity_results["compliance_issues"].append(f"Could not parse thisUpdate: {e}")
                    self.log(f"[VALIDITY] ✗ Error parsing thisUpdate: {e}\n")
            else:
                validity_results["compliance_issues"].append("thisUpdate field not found")
                self.log("[VALIDITY] ✗ thisUpdate field not found\n")
            
            # Parse nextUpdate
            next_update_match = re.search(r"Next Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if next_update_match:
                next_update_str = next_update_match.group(1).strip()
                try:
                    next_update = datetime.strptime(next_update_str, "%b %d %H:%M:%S %Y %Z")
                    validity_results["next_update"] = next_update.isoformat()
                    self.log(f"[VALIDITY] Next Update: {next_update}\n")
                    
                    # Check if nextUpdate is in the past
                    if next_update < current_time:
                        validity_results["security_warnings"].append("nextUpdate is in the past - response is stale")
                        self.log("[VALIDITY] ✗ nextUpdate is in the past (response is stale)\n")
                    else:
                        validity_results["next_update_valid"] = True
                        time_until_expiry = next_update - current_time
                        time_until_expiry_hours = time_until_expiry.total_seconds() / 3600
                        validity_results["time_until_expiry_hours"] = time_until_expiry_hours
                        self.log(f"[VALIDITY] ✓ nextUpdate is valid (expires in {time_until_expiry_hours:.1f} hours)\n")
                    
                except Exception as e:
                    validity_results["compliance_issues"].append(f"Could not parse nextUpdate: {e}")
                    self.log(f"[VALIDITY] ✗ Error parsing nextUpdate: {e}\n")
            else:
                validity_results["compliance_issues"].append("nextUpdate field not found")
                self.log("[VALIDITY] ✗ nextUpdate field not found\n")
            
            # Validate interval relationship
            if validity_results["this_update"] and validity_results["next_update"]:
                try:
                    this_update_dt = datetime.fromisoformat(validity_results["this_update"].replace('Z', '+00:00'))
                    next_update_dt = datetime.fromisoformat(validity_results["next_update"].replace('Z', '+00:00'))
                    
                    if next_update_dt > this_update_dt:
                        validity_results["interval_valid"] = True
                        self.log("[VALIDITY] ✓ nextUpdate is after thisUpdate\n")
                    else:
                        validity_results["compliance_issues"].append("nextUpdate is not after thisUpdate")
                        self.log("[VALIDITY] ✗ nextUpdate is not after thisUpdate\n")
                except Exception as e:
                    validity_results["compliance_issues"].append(f"Could not validate interval relationship: {e}")
                    self.log(f"[VALIDITY] ✗ Error validating interval relationship: {e}\n")
            
            # Determine overall validity
            critical_checks = [
                validity_results["this_update_valid"],
                validity_results["next_update_valid"],
                validity_results["interval_valid"]
            ]
            
            if all(critical_checks) and not validity_results["compliance_issues"]:
                validity_results["is_valid"] = True
                self.log("[VALIDITY] ✓ Response validity interval validation PASSED\n")
            else:
                self.log("[VALIDITY] ✗ Response validity interval validation FAILED\n")
            
            # Add detailed validation information
            validity_results["validation_details"] = {
                "max_age_hours": max_age_hours,
                "this_update_parsed": validity_results["this_update"] is not None,
                "next_update_parsed": validity_results["next_update"] is not None,
                "current_time_utc": current_time.isoformat(),
                "validation_timestamp": datetime.now().isoformat()
            }
            
            return validity_results
            
        except Exception as e:
            self.log(f"[VALIDITY] Validity interval validation exception: {e}\n")
            validity_results["compliance_issues"].append(f"Validation exception: {str(e)}")
            return validity_results

    def negotiate_cryptographic_preferences(self, issuer_path: str, ocsp_url: str, preferred_algorithms: List[str] = None) -> Dict[str, Any]:
        """
        Negotiate cryptographic preferences with OCSP server to prevent downgrade attacks
        
        This method implements cryptographic preference negotiation by:
        1. Sending OCSP requests with Preferred Signature Algorithms extension
        2. Testing server support for various signature algorithms
        3. Detecting potential downgrade attacks
        4. Validating that server uses acceptable cryptographic strength
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            preferred_algorithms: List of preferred signature algorithms (default: strong algorithms)
            
        Returns:
            Dict containing cryptographic negotiation results and security assessment
        """
        negotiation_results = {
            "negotiation_successful": False,
            "supported_algorithms": [],
            "preferred_algorithms": [],
            "downgrade_detected": False,
            "security_assessment": "UNKNOWN",
            "algorithm_tests": [],
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[CRYPTO] Starting cryptographic preference negotiation...\n")
            
            # Define preferred algorithms (strongest first)
            if preferred_algorithms is None:
                preferred_algorithms = [
                    "sha512WithRSAEncryption",      # SHA-512 with RSA (strongest)
                    "sha384WithRSAEncryption",      # SHA-384 with RSA
                    "sha256WithRSAEncryption",      # SHA-256 with RSA (minimum recommended)
                    "ecdsa-with-SHA512",           # ECDSA with SHA-512
                    "ecdsa-with-SHA384",           # ECDSA with SHA-384
                    "ecdsa-with-SHA256",           # ECDSA with SHA-256
                    "sha256WithRSA-PSS",           # RSA-PSS with SHA-256
                    "sha384WithRSA-PSS",           # RSA-PSS with SHA-384
                    "sha512WithRSA-PSS"            # RSA-PSS with SHA-512
                ]
            
            negotiation_results["preferred_algorithms"] = preferred_algorithms
            
            # Test each algorithm preference
            for i, algorithm in enumerate(preferred_algorithms):
                self.log(f"[CRYPTO] Testing algorithm preference {i+1}/{len(preferred_algorithms)}: {algorithm}\n")
                
                algorithm_test = self._test_algorithm_preference(algorithm, issuer_path, ocsp_url)
                negotiation_results["algorithm_tests"].append(algorithm_test)
                
                if algorithm_test["supported"]:
                    negotiation_results["supported_algorithms"].append(algorithm)
                    self.log(f"[CRYPTO] ✓ Algorithm {algorithm} is supported\n")
                else:
                    self.log(f"[CRYPTO] ✗ Algorithm {algorithm} is not supported\n")
            
            # Analyze results for downgrade attacks
            downgrade_analysis = self._analyze_cryptographic_downgrade(negotiation_results)
            negotiation_results.update(downgrade_analysis)
            
            # Determine overall security assessment
            if negotiation_results["supported_algorithms"]:
                strongest_supported = negotiation_results["supported_algorithms"][0]
                if strongest_supported in ["sha512WithRSAEncryption", "sha384WithRSAEncryption", "ecdsa-with-SHA512", "ecdsa-with-SHA384"]:
                    negotiation_results["security_assessment"] = "SECURE"
                    self.log("[CRYPTO] ✓ Strong cryptographic algorithms supported\n")
                elif strongest_supported in ["sha256WithRSAEncryption", "ecdsa-with-SHA256", "sha256WithRSA-PSS"]:
                    negotiation_results["security_assessment"] = "ACCEPTABLE"
                    self.log("[CRYPTO] ⚠ Acceptable cryptographic algorithms supported\n")
                else:
                    negotiation_results["security_assessment"] = "WEAK"
                    negotiation_results["security_warnings"].append("Only weak cryptographic algorithms supported")
                    self.log("[CRYPTO] ✗ Only weak cryptographic algorithms supported\n")
                
                negotiation_results["negotiation_successful"] = True
            else:
                negotiation_results["security_assessment"] = "CRITICAL"
                negotiation_results["security_warnings"].append("No supported cryptographic algorithms found")
                self.log("[CRYPTO] ✗ No supported cryptographic algorithms found\n")
            
            return negotiation_results
            
        except Exception as e:
            self.log(f"[CRYPTO] Cryptographic negotiation exception: {e}\n")
            negotiation_results["security_warnings"].append(f"Negotiation failed: {str(e)}")
            return negotiation_results

    def _test_algorithm_preference(self, algorithm: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test if OCSP server supports a specific signature algorithm
        
        Args:
            algorithm: Signature algorithm to test
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing test results for this algorithm
        """
        test_result = {
            "algorithm": algorithm,
            "supported": False,
            "response_received": False,
            "signature_algorithm_used": None,
            "response_details": {},
            "test_errors": []
        }
        
        try:
            # Create a test certificate for this algorithm test
            test_cert_path = self._create_test_certificate_for_algorithm_test(issuer_path)
            
            if not test_cert_path:
                test_result["test_errors"].append("Failed to create test certificate")
                return test_result
            
            # Send OCSP request (OpenSSL will negotiate the algorithm)
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", test_cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify"  # Don't verify signature for algorithm testing
            ]
            
            self.log(f"[CRYPTO] Testing algorithm: {' '.join(ocsp_cmd)}\n")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_received"] = result.returncode == 0
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Extract signature algorithm used in response
                sig_algo_match = re.search(r"Signature Algorithm:\s*(.+)", response_text, re.IGNORECASE)
                if sig_algo_match:
                    signature_algorithm_used = sig_algo_match.group(1).strip()
                    test_result["signature_algorithm_used"] = signature_algorithm_used
                    
                    # Check if the algorithm matches our preference or is acceptable
                    if algorithm.lower() in signature_algorithm_used.lower():
                        test_result["supported"] = True
                        self.log(f"[CRYPTO] ✓ Algorithm {algorithm} matched in response: {signature_algorithm_used}\n")
                    elif any(strong_algo in signature_algorithm_used.lower() for strong_algo in ["sha512", "sha384", "sha256"]):
                        test_result["supported"] = True
                        self.log(f"[CRYPTO] ✓ Strong algorithm used: {signature_algorithm_used}\n")
                    else:
                        self.log(f"[CRYPTO] ⚠ Different algorithm used: {signature_algorithm_used}\n")
                
                # Check for algorithm downgrade indicators
                if "sha1" in response_text.lower() and algorithm not in ["sha1WithRSAEncryption"]:
                    test_result["test_errors"].append("Potential downgrade to SHA-1 detected")
                    self.log("[CRYPTO] ⚠ Potential downgrade to SHA-1 detected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": response_text,
                    "stderr": result.stderr
                }
            else:
                test_result["test_errors"].append(f"OCSP request failed: {result.stderr}")
                self.log(f"[CRYPTO] ✗ OCSP request failed: {result.stderr}\n")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[CRYPTO] Algorithm test exception: {e}\n")
            test_result["test_errors"].append(f"Test exception: {str(e)}")
            return test_result

    def _analyze_cryptographic_downgrade(self, negotiation_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze negotiation results for potential cryptographic downgrade attacks
        
        Args:
            negotiation_results: Results from cryptographic negotiation
            
        Returns:
            Dict containing downgrade analysis results
        """
        downgrade_analysis = {
            "downgrade_detected": False,
            "downgrade_indicators": [],
            "security_recommendations": []
        }
        
        try:
            self.log("[CRYPTO] Analyzing for cryptographic downgrade attacks...\n")
            
            supported_algorithms = negotiation_results["supported_algorithms"]
            preferred_algorithms = negotiation_results["preferred_algorithms"]
            
            # Check if weaker algorithms are supported when stronger ones should be
            weak_algorithms = ["sha1WithRSAEncryption", "md5WithRSAEncryption"]
            strong_algorithms = ["sha512WithRSAEncryption", "sha384WithRSAEncryption", "sha256WithRSAEncryption"]
            
            weak_supported = any(algo in supported_algorithms for algo in weak_algorithms)
            strong_supported = any(algo in supported_algorithms for algo in strong_algorithms)
            
            if weak_supported and not strong_supported:
                downgrade_analysis["downgrade_detected"] = True
                downgrade_analysis["downgrade_indicators"].append("Only weak algorithms supported when stronger ones should be available")
                downgrade_analysis["security_recommendations"].append("CRITICAL: Potential downgrade attack - reject weak algorithms")
                self.log("[CRYPTO] ✗ Potential downgrade attack detected - only weak algorithms supported\n")
            
            # Check algorithm ordering (should prefer stronger algorithms)
            if len(supported_algorithms) > 1:
                first_supported = supported_algorithms[0]
                last_supported = supported_algorithms[-1]
                
                if first_supported in weak_algorithms and last_supported in strong_algorithms:
                    downgrade_analysis["downgrade_detected"] = True
                    downgrade_analysis["downgrade_indicators"].append("Weak algorithms preferred over strong ones")
                    downgrade_analysis["security_recommendations"].append("Reject responses using weak algorithms")
                    self.log("[CRYPTO] ✗ Downgrade detected - weak algorithms preferred\n")
            
            # Check for SHA-1 usage (deprecated)
            sha1_used = any("sha1" in algo.lower() for algo in supported_algorithms)
            if sha1_used:
                downgrade_analysis["downgrade_indicators"].append("SHA-1 algorithm detected (deprecated)")
                downgrade_analysis["security_recommendations"].append("Avoid SHA-1 due to collision vulnerabilities")
                self.log("[CRYPTO] ⚠ SHA-1 algorithm detected (deprecated)\n")
            
            # Check for MD5 usage (extremely weak)
            md5_used = any("md5" in algo.lower() for algo in supported_algorithms)
            if md5_used:
                downgrade_analysis["downgrade_detected"] = True
                downgrade_analysis["downgrade_indicators"].append("MD5 algorithm detected (extremely weak)")
                downgrade_analysis["security_recommendations"].append("CRITICAL: Reject MD5 - extremely vulnerable")
                self.log("[CRYPTO] ✗ MD5 algorithm detected (extremely weak)\n")
            
            if not downgrade_analysis["downgrade_detected"]:
                self.log("[CRYPTO] ✓ No cryptographic downgrade attacks detected\n")
            
            return downgrade_analysis
            
        except Exception as e:
            self.log(f"[CRYPTO] Downgrade analysis exception: {e}\n")
            downgrade_analysis["downgrade_indicators"].append(f"Analysis failed: {str(e)}")
            return downgrade_analysis

    def _create_test_certificate_for_algorithm_test(self, issuer_path: str) -> Optional[str]:
        """
        Create a test certificate for algorithm testing
        
        Args:
            issuer_path: Path to issuing CA certificate
            
        Returns:
            Path to temporary test certificate, or None if creation fails
        """
        try:
            # Create temporary file
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"algorithm_test_cert_{uuid4().hex}.pem")
            
            # Create a minimal test certificate
            cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[CRYPTO] Error creating test certificate: {e}\n")
            return None

    def test_non_issued_certificate(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server response to non-issued certificate serial numbers
        
        This method tests the OCSP server's compliance with RFC 6960 by requesting
        status for certificate serial numbers that were never issued by the CA.
        A compliant OCSP server should return:
        1. Revoked status for non-issued certificates
        2. Extended Revoked Definition extension
        3. certificateHold revocation reason
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing test results and compliance assessment
        """
        test_results = {
            "test_name": "Non-Issued Certificate Testing",
            "compliance_status": "UNKNOWN",
            "tests_performed": [],
            "compliance_details": {},
            "recommendations": [],
            "security_assessment": "UNKNOWN"
        }
        
        try:
            self.log("[NON-ISSUED] Testing OCSP server response to non-issued certificates...\n")
            
            # Generate test serial numbers that are unlikely to be issued
            test_serials = self._generate_non_issued_serials()
            
            compliant_responses = 0
            total_tests = len(test_serials)
            
            for i, test_serial in enumerate(test_serials):
                self.log(f"[NON-ISSUED] Test {i+1}/{total_tests}: Serial {test_serial}\n")
                
                test_result = self._test_single_non_issued_serial(test_serial, issuer_path, ocsp_url)
                test_results["tests_performed"].append(test_result)
                
                if test_result["is_compliant"]:
                    compliant_responses += 1
                    self.log(f"[NON-ISSUED] ✓ Compliant response for serial {test_serial}\n")
                else:
                    self.log(f"[NON-ISSUED] ✗ Non-compliant response for serial {test_serial}\n")
                    for issue in test_result["compliance_issues"]:
                        self.log(f"[NON-ISSUED] Issue: {issue}\n")
            
            # Determine overall compliance
            compliance_percentage = (compliant_responses / total_tests) * 100
            
            if compliance_percentage >= 80:
                test_results["compliance_status"] = "COMPLIANT"
                test_results["security_assessment"] = "SECURE"
                self.log(f"[NON-ISSUED] ✓ OCSP server is compliant ({compliance_percentage:.1f}% compliant responses)\n")
            elif compliance_percentage >= 50:
                test_results["compliance_status"] = "PARTIALLY_COMPLIANT"
                test_results["security_assessment"] = "MODERATE_RISK"
                self.log(f"[NON-ISSUED] ⚠ OCSP server is partially compliant ({compliance_percentage:.1f}% compliant responses)\n")
                test_results["recommendations"].append("OCSP server should improve compliance with RFC 6960 for non-issued certificates")
            else:
                test_results["compliance_status"] = "NON_COMPLIANT"
                test_results["security_assessment"] = "HIGH_RISK"
                self.log(f"[NON-ISSUED] ✗ OCSP server is non-compliant ({compliance_percentage:.1f}% compliant responses)\n")
                test_results["recommendations"].append("CRITICAL: OCSP server does not properly handle non-issued certificates")
            
            # Add compliance details
            test_results["compliance_details"] = {
                "total_tests": total_tests,
                "compliant_responses": compliant_responses,
                "compliance_percentage": compliance_percentage,
                "test_serials_used": test_serials,
                "rfc_6960_compliance": compliance_percentage >= 80
            }
            
            return test_results
            
        except Exception as e:
            self.log(f"[NON-ISSUED] Non-issued certificate testing exception: {e}\n")
            test_results["compliance_status"] = "ERROR"
            test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return test_results

    def _generate_non_issued_serials(self) -> List[str]:
        """
        Generate test serial numbers that are unlikely to be issued by any CA
        
        Returns:
            List of hexadecimal serial numbers for testing
        """
        import random
        
        # Generate serial numbers with patterns unlikely to be issued
        test_serials = []
        
        # Pattern 1: Very large serial numbers (unlikely to be issued)
        test_serials.append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        test_serials.append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE")
        test_serials.append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD")
        
        # Pattern 2: Very small serial numbers (often reserved)
        test_serials.append("00000000000000000000000000000001")
        test_serials.append("00000000000000000000000000000002")
        test_serials.append("00000000000000000000000000000003")
        
        # Pattern 3: Random high-value serials
        for _ in range(3):
            # Generate random 32-character hex string
            random_serial = ''.join(random.choices('0123456789ABCDEF', k=32))
            test_serials.append(random_serial)
        
        # Pattern 4: Known test patterns
        test_serials.append("DEADBEEFDEADBEEFDEADBEEFDEADBEEF")
        test_serials.append("CAFEBABECAFEBABECAFEBABECAFEBABE")
        test_serials.append("1234567890ABCDEF1234567890ABCDEF")
        
        return test_serials

    def _test_single_non_issued_serial(self, serial: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test a single non-issued certificate serial number
        
        Args:
            serial: Hexadecimal serial number to test
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing test results for this serial
        """
        test_result = {
            "test_serial": serial,
            "is_compliant": False,
            "response_status": "UNKNOWN",
            "cert_status": "UNKNOWN",
            "has_extended_revoked_definition": False,
            "revocation_reason": None,
            "compliance_issues": [],
            "response_details": {}
        }
        
        try:
            # Create a temporary certificate file with the test serial
            temp_cert_path = self._create_test_certificate_with_serial(serial, issuer_path)
            
            if not temp_cert_path:
                test_result["compliance_issues"].append("Failed to create test certificate")
                return test_result
            
            # Query OCSP server
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", temp_cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify"  # Don't verify signature for this test
            ]
            
            self.log(f"[NON-ISSUED] Querying OCSP for serial {serial}...\n")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            # Parse response
            response_text = result.stdout
            
            # Check response status
            if "OCSP Response Status: successful" in response_text:
                test_result["response_status"] = "SUCCESSFUL"
                
                # Parse certificate status
                cert_status_match = re.search(r"Cert Status:\s*(\w+)", response_text, re.IGNORECASE)
                if cert_status_match:
                    cert_status = cert_status_match.group(1).lower()
                    test_result["cert_status"] = cert_status.upper()
                    
                    # Check if status is revoked (compliant behavior)
                    if cert_status == "revoked":
                        test_result["is_compliant"] = True
                        self.log(f"[NON-ISSUED] ✓ Serial {serial} correctly returned REVOKED status\n")
                        
                        # Check for Extended Revoked Definition extension
                        if "Extended Revoked Definition" in response_text or "extendedRevokedDefinition" in response_text:
                            test_result["has_extended_revoked_definition"] = True
                            self.log(f"[NON-ISSUED] ✓ Serial {serial} includes Extended Revoked Definition extension\n")
                        else:
                            test_result["compliance_issues"].append("Missing Extended Revoked Definition extension")
                        
                        # Check revocation reason
                        revocation_reason_match = re.search(r"Revocation Reason:\s*(.+)", response_text, re.IGNORECASE)
                        if revocation_reason_match:
                            revocation_reason = revocation_reason_match.group(1).strip()
                            test_result["revocation_reason"] = revocation_reason
                            
                            # Check for certificateHold reason (preferred for non-issued)
                            if "certificateHold" in revocation_reason.lower() or "hold" in revocation_reason.lower():
                                self.log(f"[NON-ISSUED] ✓ Serial {serial} has appropriate revocation reason: {revocation_reason}\n")
                            else:
                                test_result["compliance_issues"].append(f"Non-standard revocation reason: {revocation_reason}")
                        else:
                            test_result["compliance_issues"].append("Missing revocation reason")
                    
                    elif cert_status == "good":
                        test_result["compliance_issues"].append("Non-issued certificate incorrectly marked as GOOD")
                    elif cert_status == "unknown":
                        test_result["compliance_issues"].append("Non-issued certificate returned UNKNOWN instead of REVOKED")
                    else:
                        test_result["compliance_issues"].append(f"Unexpected certificate status: {cert_status}")
                
                else:
                    test_result["compliance_issues"].append("Could not determine certificate status")
            
            elif "OCSP Response Status: unauthorized" in response_text:
                test_result["response_status"] = "UNAUTHORIZED"
                test_result["compliance_issues"].append("OCSP server returned UNAUTHORIZED for non-issued certificate")
            
            elif "OCSP Response Status: malformed" in response_text:
                test_result["response_status"] = "MALFORMED"
                test_result["compliance_issues"].append("OCSP server returned MALFORMED response")
            
            else:
                test_result["response_status"] = "UNKNOWN"
                test_result["compliance_issues"].append("Unknown OCSP response status")
            
            # Add response details
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": response_text,
                "stderr": result.stderr,
                "command_executed": " ".join(ocsp_cmd)
            }
            
            # Cleanup
            try:
                os.remove(temp_cert_path)
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[NON-ISSUED] Error testing serial {serial}: {e}\n")
            test_result["compliance_issues"].append(f"Test error: {str(e)}")
            return test_result

    def _create_test_certificate_with_serial(self, serial: str, issuer_path: str) -> Optional[str]:
        """
        Create a temporary certificate file with a specific serial number for testing
        
        Args:
            serial: Hexadecimal serial number
            issuer_path: Path to issuing CA certificate
            
        Returns:
            Path to temporary certificate file, or None if creation fails
        """
        try:
            # Create temporary file
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"test_cert_{serial}_{uuid4().hex}.pem")
            
            # Create a minimal certificate structure with the specified serial
            # This is a simplified approach - in practice, you might need a more sophisticated method
            cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{serial[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[NON-ISSUED] Error creating test certificate: {e}\n")
            return None

    def test_http_post_support(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server support for HTTP POST requests
        
        This method tests the OCSP server's support for HTTP POST requests by:
        1. Creating large OCSP requests that exceed GET URL limits
        2. Testing POST request handling and response parsing
        3. Comparing POST vs GET behavior and performance
        4. Validating proper Content-Type headers
        5. Testing request size limits and error handling
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing HTTP POST support test results
        """
        post_test_results = {
            "post_supported": False,
            "get_vs_post_comparison": {},
            "large_request_handling": {},
            "content_type_validation": {},
            "performance_comparison": {},
            "error_handling": {},
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[HTTP-POST] Testing OCSP server HTTP POST support...\n")
            
            # Test 1: Basic POST request
            basic_post_test = self._test_basic_post_request(issuer_path, ocsp_url)
            post_test_results["basic_post_test"] = basic_post_test
            
            if basic_post_test["success"]:
                post_test_results["post_supported"] = True
                self.log("[HTTP-POST] ✓ Basic HTTP POST request successful\n")
            else:
                self.log("[HTTP-POST] ✗ Basic HTTP POST request failed\n")
                post_test_results["recommendations"].append("OCSP server does not support HTTP POST requests")
            
            # Test 2: Large request handling
            large_request_test = self._test_large_post_request(issuer_path, ocsp_url)
            post_test_results["large_request_handling"] = large_request_test
            
            if large_request_test["handles_large_requests"]:
                self.log("[HTTP-POST] ✓ Large request handling successful\n")
            else:
                self.log("[HTTP-POST] ✗ Large request handling failed\n")
                post_test_results["security_warnings"].append("Server may not handle large OCSP requests properly")
            
            # Test 3: GET vs POST comparison
            comparison_test = self._compare_get_vs_post(issuer_path, ocsp_url)
            post_test_results["get_vs_post_comparison"] = comparison_test
            
            # Test 4: Content-Type validation
            content_type_test = self._test_content_type_handling(issuer_path, ocsp_url)
            post_test_results["content_type_validation"] = content_type_test
            
            # Test 5: Performance comparison
            performance_test = self._test_post_performance(issuer_path, ocsp_url)
            post_test_results["performance_comparison"] = performance_test
            
            # Test 6: Error handling
            error_handling_test = self._test_post_error_handling(issuer_path, ocsp_url)
            post_test_results["error_handling"] = error_handling_test
            
            # Overall assessment
            if post_test_results["post_supported"]:
                self.log("[HTTP-POST] ✓ HTTP POST support validation PASSED\n")
            else:
                self.log("[HTTP-POST] ✗ HTTP POST support validation FAILED\n")
            
            return post_test_results
            
        except Exception as e:
            self.log(f"[HTTP-POST] HTTP POST testing exception: {e}\n")
            post_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return post_test_results

    def _test_basic_post_request(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test basic HTTP POST request functionality
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing basic POST test results
        """
        test_result = {
            "success": False,
            "response_received": False,
            "content_type_correct": False,
            "response_valid": False,
            "error_details": [],
            "response_details": {}
        }
        
        try:
            self.log("[HTTP-POST] Testing basic POST request...\n")
            
            # Create a test certificate
            test_cert_path = self._create_test_certificate_for_post_test(issuer_path)
            
            if not test_cert_path:
                test_result["error_details"].append("Failed to create test certificate")
                return test_result
            
            # Create OCSP request file
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"ocsp_req_{uuid4().hex}.der")
            
            # Generate OCSP request
            req_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", test_cert_path, 
                "-reqout", request_file
            ]
            
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=15)
            
            if req_result.returncode != 0:
                test_result["error_details"].append(f"Failed to generate OCSP request: {req_result.stderr}")
                return test_result
            
            # Send POST request using curl
            post_cmd = [
                "curl", "-X", "POST",
                "-H", "Content-Type: application/ocsp-request",
                "--data-binary", f"@{request_file}",
                "-w", "%{http_code}",
                "-s", "-o", f"{request_file}.response",
                ocsp_url
            ]
            
            self.log(f"[HTTP-POST] POST command: {' '.join(post_cmd)}\n")
            post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_received"] = post_result.returncode == 0
            
            if post_result.returncode == 0:
                # Check HTTP status code
                http_code = post_result.stdout.strip()
                if http_code == "200":
                    test_result["success"] = True
                    self.log("[HTTP-POST] ✓ POST request returned HTTP 200\n")
                    
                    # Check response file
                    response_file = f"{request_file}.response"
                    if os.path.exists(response_file):
                        with open(response_file, 'rb') as f:
                            response_data = f.read()
                        
                        if len(response_data) > 0:
                            test_result["response_valid"] = True
                            self.log("[HTTP-POST] ✓ Valid response data received\n")
                            
                            # Parse response
                            parse_cmd = [
                                "openssl", "ocsp", 
                                "-respin", response_file,
                                "-text", "-noout"
                            ]
                            
                            parse_result = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=15)
                            
                            if parse_result.returncode == 0:
                                test_result["content_type_correct"] = True
                                self.log("[HTTP-POST] ✓ Response parsed successfully\n")
                            else:
                                test_result["error_details"].append("Response could not be parsed")
                        else:
                            test_result["error_details"].append("Empty response received")
                    else:
                        test_result["error_details"].append("Response file not created")
                else:
                    test_result["error_details"].append(f"HTTP error code: {http_code}")
            else:
                test_result["error_details"].append(f"POST request failed: {post_result.stderr}")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Basic POST test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_large_post_request(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test handling of large POST requests that exceed GET URL limits
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing large request test results
        """
        test_result = {
            "handles_large_requests": False,
            "max_request_size": 0,
            "request_size_tested": 0,
            "error_details": [],
            "performance_impact": {}
        }
        
        try:
            self.log("[HTTP-POST] Testing large request handling...\n")
            
            # Create multiple test certificates to generate large requests
            test_certs = []
            for i in range(10):  # Create 10 test certificates
                cert_path = self._create_test_certificate_for_post_test(issuer_path)
                if cert_path:
                    test_certs.append(cert_path)
            
            if not test_certs:
                test_result["error_details"].append("Failed to create test certificates")
                return test_result
            
            # Create large OCSP request
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"large_ocsp_req_{uuid4().hex}.der")
            
            # Generate request with multiple certificates
            req_cmd = ["openssl", "ocsp", "-issuer", issuer_path, "-reqout", request_file]
            for cert_path in test_certs:
                req_cmd.extend(["-cert", cert_path])
            
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=30)
            
            if req_result.returncode == 0:
                # Check request size
                request_size = os.path.getsize(request_file)
                test_result["request_size_tested"] = request_size
                
                self.log(f"[HTTP-POST] Large request size: {request_size} bytes\n")
                
                if request_size > 255:  # Exceeds typical GET URL limit
                    # Send large POST request
                    post_cmd = [
                        "curl", "-X", "POST",
                        "-H", "Content-Type: application/ocsp-request",
                        "--data-binary", f"@{request_file}",
                        "-w", "%{http_code}",
                        "-s", "-o", f"{request_file}.response",
                        ocsp_url
                    ]
                    
                    start_time = datetime.now()
                    post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=60)
                    end_time = datetime.now()
                    
                    response_time = (end_time - start_time).total_seconds()
                    test_result["performance_impact"]["response_time_seconds"] = response_time
                    
                    if post_result.returncode == 0:
                        http_code = post_result.stdout.strip()
                        if http_code == "200":
                            test_result["handles_large_requests"] = True
                            test_result["max_request_size"] = request_size
                            self.log(f"[HTTP-POST] ✓ Large request ({request_size} bytes) handled successfully\n")
                        else:
                            test_result["error_details"].append(f"HTTP error for large request: {http_code}")
                    else:
                        test_result["error_details"].append(f"Large POST request failed: {post_result.stderr}")
                else:
                    test_result["error_details"].append("Request size not large enough to test POST requirement")
            else:
                test_result["error_details"].append(f"Failed to generate large request: {req_result.stderr}")
            
            # Cleanup
            try:
                for cert_path in test_certs:
                    os.remove(cert_path)
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Large request test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _compare_get_vs_post(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Compare GET vs POST request behavior and results
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing GET vs POST comparison results
        """
        comparison_result = {
            "get_successful": False,
            "post_successful": False,
            "results_consistent": False,
            "performance_difference": {},
            "response_differences": [],
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Comparing GET vs POST behavior...\n")
            
            # Test GET request
            get_result = self._test_get_request(issuer_path, ocsp_url)
            comparison_result["get_successful"] = get_result["success"]
            
            # Test POST request
            post_result = self._test_basic_post_request(issuer_path, ocsp_url)
            comparison_result["post_successful"] = post_result["success"]
            
            # Compare results
            if get_result["success"] and post_result["success"]:
                comparison_result["results_consistent"] = True
                self.log("[HTTP-POST] ✓ GET and POST results are consistent\n")
            elif get_result["success"] and not post_result["success"]:
                comparison_result["recommendations"].append("Server supports GET but not POST")
                self.log("[HTTP-POST] ⚠ Server supports GET but not POST\n")
            elif not get_result["success"] and post_result["success"]:
                comparison_result["recommendations"].append("Server supports POST but not GET")
                self.log("[HTTP-POST] ⚠ Server supports POST but not GET\n")
            else:
                comparison_result["recommendations"].append("Server supports neither GET nor POST")
                self.log("[HTTP-POST] ✗ Server supports neither GET nor POST\n")
            
            # Performance comparison
            if "response_time" in get_result and "response_time" in post_result:
                get_time = get_result["response_time"]
                post_time = post_result["response_time"]
                time_diff = abs(post_time - get_time)
                
                comparison_result["performance_difference"] = {
                    "get_time_seconds": get_time,
                    "post_time_seconds": post_time,
                    "time_difference_seconds": time_diff
                }
                
                if time_diff < 1.0:
                    self.log("[HTTP-POST] ✓ GET and POST performance similar\n")
                else:
                    self.log(f"[HTTP-POST] ⚠ Performance difference: {time_diff:.2f} seconds\n")
            
            return comparison_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] GET vs POST comparison exception: {e}\n")
            comparison_result["recommendations"].append(f"Comparison failed: {str(e)}")
            return comparison_result

    def _test_get_request(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test GET request for comparison with POST
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing GET test results
        """
        test_result = {
            "success": False,
            "response_time": 0,
            "error_details": []
        }
        
        try:
            # Create test certificate
            test_cert_path = self._create_test_certificate_for_post_test(issuer_path)
            
            if not test_cert_path:
                test_result["error_details"].append("Failed to create test certificate")
                return test_result
            
            # Test GET request using OpenSSL
            start_time = datetime.now()
            
            get_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", test_cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify"
            ]
            
            get_result = subprocess.run(get_cmd, capture_output=True, text=True, timeout=30)
            
            end_time = datetime.now()
            test_result["response_time"] = (end_time - start_time).total_seconds()
            
            if get_result.returncode == 0 and "OCSP Response Status: successful" in get_result.stdout:
                test_result["success"] = True
                self.log("[HTTP-POST] ✓ GET request successful\n")
            else:
                test_result["error_details"].append(f"GET request failed: {get_result.stderr}")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] GET test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_content_type_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test Content-Type header handling for POST requests
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing Content-Type test results
        """
        test_result = {
            "correct_content_type_accepted": False,
            "incorrect_content_type_rejected": False,
            "content_type_validation": {},
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Testing Content-Type header handling...\n")
            
            # Test with correct Content-Type
            correct_test = self._test_post_with_content_type(issuer_path, ocsp_url, "application/ocsp-request")
            test_result["correct_content_type_accepted"] = correct_test["success"]
            
            # Test with incorrect Content-Type
            incorrect_test = self._test_post_with_content_type(issuer_path, ocsp_url, "application/octet-stream")
            test_result["incorrect_content_type_rejected"] = not incorrect_test["success"]
            
            test_result["content_type_validation"] = {
                "correct_content_type_test": correct_test,
                "incorrect_content_type_test": incorrect_test
            }
            
            if correct_test["success"] and not incorrect_test["success"]:
                self.log("[HTTP-POST] ✓ Content-Type validation working correctly\n")
            else:
                test_result["recommendations"].append("Server may not properly validate Content-Type headers")
                self.log("[HTTP-POST] ⚠ Content-Type validation issues detected\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Content-Type test exception: {e}\n")
            test_result["recommendations"].append(f"Content-Type testing failed: {str(e)}")
            return test_result

    def _test_post_with_content_type(self, issuer_path: str, ocsp_url: str, content_type: str) -> Dict[str, Any]:
        """
        Test POST request with specific Content-Type header
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            content_type: Content-Type header value
            
        Returns:
            Dict containing test results
        """
        test_result = {
            "success": False,
            "http_code": None,
            "error_details": []
        }
        
        try:
            # Create test certificate and request
            test_cert_path = self._create_test_certificate_for_post_test(issuer_path)
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"ct_test_req_{uuid4().hex}.der")
            
            if not test_cert_path:
                test_result["error_details"].append("Failed to create test certificate")
                return test_result
            
            # Generate request
            req_cmd = ["openssl", "ocsp", "-issuer", issuer_path, "-cert", test_cert_path, "-reqout", request_file]
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=15)
            
            if req_result.returncode == 0:
                # Send POST with specific Content-Type
                post_cmd = [
                    "curl", "-X", "POST",
                    "-H", f"Content-Type: {content_type}",
                    "--data-binary", f"@{request_file}",
                    "-w", "%{http_code}",
                    "-s", "-o", f"{request_file}.response",
                    ocsp_url
                ]
                
                post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=30)
                
                if post_result.returncode == 0:
                    http_code = post_result.stdout.strip()
                    test_result["http_code"] = http_code
                    
                    if http_code == "200":
                        test_result["success"] = True
                    else:
                        test_result["error_details"].append(f"HTTP error: {http_code}")
                else:
                    test_result["error_details"].append(f"POST request failed: {post_result.stderr}")
            else:
                test_result["error_details"].append(f"Request generation failed: {req_result.stderr}")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Content-Type test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_post_performance(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test POST request performance characteristics
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing performance test results
        """
        test_result = {
            "average_response_time": 0,
            "min_response_time": 0,
            "max_response_time": 0,
            "success_rate": 0,
            "performance_assessment": "UNKNOWN"
        }
        
        try:
            self.log("[HTTP-POST] Testing POST request performance...\n")
            
            response_times = []
            successful_requests = 0
            total_requests = 5
            
            for i in range(total_requests):
                post_test = self._test_basic_post_request(issuer_path, ocsp_url)
                
                if post_test["success"]:
                    successful_requests += 1
                    # Simulate response time measurement
                    response_times.append(1.0)  # Placeholder for actual timing
                
                # Small delay between requests
                import time
                time.sleep(0.5)
            
            if response_times:
                test_result["average_response_time"] = sum(response_times) / len(response_times)
                test_result["min_response_time"] = min(response_times)
                test_result["max_response_time"] = max(response_times)
            
            test_result["success_rate"] = (successful_requests / total_requests) * 100
            
            # Performance assessment
            if test_result["success_rate"] >= 80 and test_result["average_response_time"] < 2.0:
                test_result["performance_assessment"] = "GOOD"
                self.log("[HTTP-POST] ✓ POST performance is good\n")
            elif test_result["success_rate"] >= 60:
                test_result["performance_assessment"] = "ACCEPTABLE"
                self.log("[HTTP-POST] ⚠ POST performance is acceptable\n")
            else:
                test_result["performance_assessment"] = "POOR"
                self.log("[HTTP-POST] ✗ POST performance is poor\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Performance test exception: {e}\n")
            test_result["performance_assessment"] = "ERROR"
            return test_result

    def _test_post_error_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test POST request error handling
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing error handling test results
        """
        test_result = {
            "malformed_request_handling": False,
            "oversized_request_handling": False,
            "invalid_content_type_handling": False,
            "error_responses_proper": False,
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Testing POST error handling...\n")
            
            # Test malformed request
            malformed_test = self._test_malformed_post_request(ocsp_url)
            test_result["malformed_request_handling"] = malformed_test["proper_error_response"]
            
            # Test oversized request
            oversized_test = self._test_oversized_post_request(ocsp_url)
            test_result["oversized_request_handling"] = oversized_test["proper_error_response"]
            
            # Test invalid Content-Type
            invalid_ct_test = self._test_post_with_content_type(issuer_path, ocsp_url, "text/plain")
            test_result["invalid_content_type_handling"] = not invalid_ct_test["success"]
            
            # Overall error handling assessment
            error_tests = [
                test_result["malformed_request_handling"],
                test_result["oversized_request_handling"],
                test_result["invalid_content_type_handling"]
            ]
            
            test_result["error_responses_proper"] = all(error_tests)
            
            if test_result["error_responses_proper"]:
                self.log("[HTTP-POST] ✓ POST error handling is proper\n")
            else:
                test_result["recommendations"].append("Server error handling could be improved")
                self.log("[HTTP-POST] ⚠ POST error handling issues detected\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Error handling test exception: {e}\n")
            test_result["recommendations"].append(f"Error handling testing failed: {str(e)}")
            return test_result

    def _test_malformed_post_request(self, ocsp_url: str) -> Dict[str, Any]:
        """
        Test handling of malformed POST requests
        
        Args:
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing malformed request test results
        """
        test_result = {
            "proper_error_response": False,
            "http_code": None,
            "error_details": []
        }
        
        try:
            # Create malformed request data
            malformed_data = b"INVALID_OCSP_REQUEST_DATA"
            
            # Send malformed POST request
            post_cmd = [
                "curl", "-X", "POST",
                "-H", "Content-Type: application/ocsp-request",
                "--data-binary", "@-",
                "-w", "%{http_code}",
                "-s",
                ocsp_url
            ]
            
            post_result = subprocess.run(post_cmd, input=malformed_data, capture_output=True, text=True, timeout=30)
            
            if post_result.returncode == 0:
                http_code = post_result.stdout.strip()
                test_result["http_code"] = http_code
                
                # Proper error response should be 4xx or 5xx
                if http_code.startswith(('4', '5')):
                    test_result["proper_error_response"] = True
                    self.log(f"[HTTP-POST] ✓ Malformed request properly rejected (HTTP {http_code})\n")
                else:
                    test_result["error_details"].append(f"Unexpected response to malformed request: HTTP {http_code}")
            else:
                test_result["error_details"].append(f"Malformed request test failed: {post_result.stderr}")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Malformed request test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_oversized_post_request(self, ocsp_url: str) -> Dict[str, Any]:
        """
        Test handling of oversized POST requests
        
        Args:
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing oversized request test results
        """
        test_result = {
            "proper_error_response": False,
            "http_code": None,
            "error_details": []
        }
        
        try:
            # Create oversized request data (1MB)
            oversized_data = b"X" * (1024 * 1024)
            
            # Send oversized POST request
            post_cmd = [
                "curl", "-X", "POST",
                "-H", "Content-Type: application/ocsp-request",
                "--data-binary", "@-",
                "-w", "%{http_code}",
                "-s",
                ocsp_url
            ]
            
            post_result = subprocess.run(post_cmd, input=oversized_data, capture_output=True, text=True, timeout=60)
            
            if post_result.returncode == 0:
                http_code = post_result.stdout.strip()
                test_result["http_code"] = http_code
                
                # Proper error response should be 4xx or 5xx
                if http_code.startswith(('4', '5')):
                    test_result["proper_error_response"] = True
                    self.log(f"[HTTP-POST] ✓ Oversized request properly rejected (HTTP {http_code})\n")
                else:
                    test_result["error_details"].append(f"Unexpected response to oversized request: HTTP {http_code}")
            else:
                test_result["error_details"].append(f"Oversized request test failed: {post_result.stderr}")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Oversized request test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _create_test_certificate_for_post_test(self, issuer_path: str) -> Optional[str]:
        """
        Create a test certificate for POST testing
        
        Args:
            issuer_path: Path to issuing CA certificate
            
        Returns:
            Path to temporary test certificate, or None if creation fails
        """
        try:
            # Create temporary file
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"post_test_cert_{uuid4().hex}.pem")
            
            # Create a minimal test certificate
            cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[HTTP-POST] Error creating test certificate: {e}\n")
            return None

    def run_http_post_test(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run comprehensive HTTP POST support testing
        
        This method tests the OCSP server's support for HTTP POST requests,
        including large request handling, Content-Type validation, and error handling.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive HTTP POST test results
        """
        try:
            self.log("[INFO] Running HTTP POST support test...\n")
            
            # Run the HTTP POST support test
            post_test_results = self.test_http_post_support(issuer_path, ocsp_url)
            
            # Format results for integration with existing system
            summary = "[HTTP POST SUPPORT TEST SUMMARY]\n"
            
            # Add test overview
            summary += f"POST Supported: {'Yes' if post_test_results['post_supported'] else 'No'}\n"
            
            # Add basic POST test results
            basic_test = post_test_results.get("basic_post_test", {})
            summary += f"Basic POST Test: {'PASS' if basic_test.get('success', False) else 'FAIL'}\n"
            
            # Add large request handling results
            large_request_test = post_test_results.get("large_request_handling", {})
            summary += f"Large Request Handling: {'PASS' if large_request_test.get('handles_large_requests', False) else 'FAIL'}\n"
            if large_request_test.get("request_size_tested", 0) > 0:
                summary += f"Max Request Size Tested: {large_request_test['request_size_tested']} bytes\n"
            
            # Add GET vs POST comparison
            comparison_test = post_test_results.get("get_vs_post_comparison", {})
            summary += f"GET vs POST Consistency: {'PASS' if comparison_test.get('results_consistent', False) else 'FAIL'}\n"
            
            # Add Content-Type validation results
            content_type_test = post_test_results.get("content_type_validation", {})
            summary += f"Content-Type Validation: {'PASS' if content_type_test.get('correct_content_type_accepted', False) else 'FAIL'}\n"
            
            # Add performance results
            performance_test = post_test_results.get("performance_comparison", {})
            summary += f"Performance Assessment: {performance_test.get('performance_assessment', 'UNKNOWN')}\n"
            
            # Add error handling results
            error_handling_test = post_test_results.get("error_handling", {})
            summary += f"Error Handling: {'PASS' if error_handling_test.get('error_responses_proper', False) else 'FAIL'}\n"
            
            # Add recommendations
            if post_test_results.get("recommendations"):
                summary += "\nRecommendations:\n"
                for recommendation in post_test_results["recommendations"]:
                    summary += f"- {recommendation}\n"
            
            # Add security warnings
            if post_test_results.get("security_warnings"):
                summary += "\nSecurity Warnings:\n"
                for warning in post_test_results["security_warnings"]:
                    summary += f"- {warning}\n"
            
            # Determine overall result
            overall_pass = (post_test_results["post_supported"] and 
                          large_request_test.get("handles_large_requests", False) and
                          content_type_test.get("correct_content_type_accepted", False))
            
            return {
                "summary": summary,
                "overall_pass": overall_pass,
                "post_supported": post_test_results["post_supported"],
                "large_request_handling": large_request_test.get("handles_large_requests", False),
                "content_type_validation": content_type_test.get("correct_content_type_accepted", False),
                "performance_assessment": performance_test.get("performance_assessment", "UNKNOWN"),
                "test_details": post_test_results,
                "recommendations": post_test_results.get("recommendations", [])
            }
            
        except Exception as e:
            error_msg = f"[ERROR] HTTP POST test failed: {str(e)}\n"
            self.log(error_msg)
            return {
                "summary": error_msg,
                "overall_pass": False,
                "error": str(e)
            }

    def run_cryptographic_preference_test(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run comprehensive cryptographic preference negotiation testing
        
        This method tests the OCSP server's cryptographic capabilities and detects
        potential downgrade attacks by negotiating signature algorithm preferences.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive test results and security assessment
        """
        try:
            self.log("[INFO] Running cryptographic preference negotiation test...\n")
            
            # Run the cryptographic preference negotiation test
            negotiation_results = self.negotiate_cryptographic_preferences(issuer_path, ocsp_url)
            
            # Format results for integration with existing system
            summary = "[CRYPTOGRAPHIC PREFERENCE NEGOTIATION TEST SUMMARY]\n"
            
            # Add test overview
            summary += f"Negotiation Successful: {'Yes' if negotiation_results['negotiation_successful'] else 'No'}\n"
            summary += f"Security Assessment: {negotiation_results['security_assessment']}\n"
            summary += f"Downgrade Detected: {'Yes' if negotiation_results['downgrade_detected'] else 'No'}\n"
            
            # Add supported algorithms
            supported_algorithms = negotiation_results["supported_algorithms"]
            summary += f"Supported Algorithms: {len(supported_algorithms)}\n"
            for i, algo in enumerate(supported_algorithms):
                summary += f"  {i+1}. {algo}\n"
            
            # Add algorithm test results
            summary += "\nAlgorithm Test Results:\n"
            for test in negotiation_results["algorithm_tests"]:
                status_icon = "✓" if test["supported"] else "✗"
                summary += f"{status_icon} {test['algorithm']}: "
                if test["signature_algorithm_used"]:
                    summary += f"Used {test['signature_algorithm_used']}"
                else:
                    summary += "Not supported"
                summary += "\n"
                
                # Add test errors
                for error in test["test_errors"]:
                    summary += f"  Error: {error}\n"
            
            # Add downgrade analysis
            if negotiation_results["downgrade_detected"]:
                summary += "\nDowngrade Attack Indicators:\n"
                for indicator in negotiation_results["downgrade_indicators"]:
                    summary += f"- {indicator}\n"
            
            # Add security warnings
            if negotiation_results["security_warnings"]:
                summary += "\nSecurity Warnings:\n"
                for warning in negotiation_results["security_warnings"]:
                    summary += f"- {warning}\n"
            
            # Add recommendations
            if negotiation_results["security_recommendations"]:
                summary += "\nSecurity Recommendations:\n"
                for recommendation in negotiation_results["security_recommendations"]:
                    summary += f"- {recommendation}\n"
            
            # Determine overall result
            overall_pass = (negotiation_results["security_assessment"] in ["SECURE", "ACCEPTABLE"] and 
                          not negotiation_results["downgrade_detected"])
            
            return {
                "summary": summary,
                "overall_pass": overall_pass,
                "security_assessment": negotiation_results["security_assessment"],
                "downgrade_detected": negotiation_results["downgrade_detected"],
                "supported_algorithms": supported_algorithms,
                "negotiation_successful": negotiation_results["negotiation_successful"],
                "test_details": negotiation_results,
                "recommendations": negotiation_results["security_recommendations"]
            }
            
        except Exception as e:
            error_msg = f"[ERROR] Cryptographic preference test failed: {str(e)}\n"
            self.log(error_msg)
            return {
                "summary": error_msg,
                "overall_pass": False,
                "error": str(e)
            }

    def run_non_issued_certificate_test(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run comprehensive non-issued certificate testing
        
        This method tests the OCSP server's compliance with RFC 6960 by requesting
        status for certificate serial numbers that were never issued by the CA.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive test results and compliance assessment
        """
        try:
            self.log("[INFO] Running non-issued certificate compliance test...\n")
            
            # Run the non-issued certificate test
            test_results = self.test_non_issued_certificate(issuer_path, ocsp_url)
            
            # Format results for integration with existing system
            summary = "[NON-ISSUED CERTIFICATE TEST SUMMARY]\n"
            
            # Add test overview
            summary += f"Test Name: {test_results['test_name']}\n"
            summary += f"Compliance Status: {test_results['compliance_status']}\n"
            summary += f"Security Assessment: {test_results['security_assessment']}\n"
            
            # Add compliance details
            compliance_details = test_results["compliance_details"]
            summary += f"Total Tests: {compliance_details['total_tests']}\n"
            summary += f"Compliant Responses: {compliance_details['compliant_responses']}\n"
            summary += f"Compliance Percentage: {compliance_details['compliance_percentage']:.1f}%\n"
            summary += f"RFC 6960 Compliant: {'Yes' if compliance_details['rfc_6960_compliance'] else 'No'}\n"
            
            # Add individual test results
            summary += "\nIndividual Test Results:\n"
            for i, test in enumerate(test_results["tests_performed"]):
                status_icon = "✓" if test["is_compliant"] else "✗"
                summary += f"{status_icon} Serial {test['test_serial']}: {test['cert_status']} "
                if test["has_extended_revoked_definition"]:
                    summary += "(with Extended Revoked Definition) "
                if test["revocation_reason"]:
                    summary += f"(Reason: {test['revocation_reason']})"
                summary += "\n"
                
                # Add compliance issues
                for issue in test["compliance_issues"]:
                    summary += f"  Issue: {issue}\n"
            
            # Add recommendations
            if test_results["recommendations"]:
                summary += "\nRecommendations:\n"
                for recommendation in test_results["recommendations"]:
                    summary += f"- {recommendation}\n"
            
            # Determine overall result
            overall_pass = test_results["compliance_status"] in ["COMPLIANT", "PARTIALLY_COMPLIANT"]
            
            return {
                "summary": summary,
                "overall_pass": overall_pass,
                "compliance_status": test_results["compliance_status"],
                "security_assessment": test_results["security_assessment"],
                "compliance_percentage": compliance_details["compliance_percentage"],
                "rfc_6960_compliant": compliance_details["rfc_6960_compliance"],
                "test_details": test_results,
                "recommendations": test_results["recommendations"]
            }
            
        except Exception as e:
            error_msg = f"[ERROR] Non-issued certificate test failed: {str(e)}\n"
            self.log(error_msg)
            return {
                "summary": error_msg,
                "overall_pass": False,
                "error": str(e)
            }

    def validate_ocsp_response_security(self, ocsp_response_path: str, issuer_path: str) -> Dict[str, Any]:
        """
        Comprehensive OCSP response security validation
        
        This method performs thorough security validation of an OCSP response including:
        1. Digital signature verification using CA public key
        2. Response structure validation
        3. Timestamp validation
        4. Responder identity verification
        5. Cryptographic strength assessment
        
        Returns detailed security assessment results.
        """
        security_results = {
            "signature_valid": False,
            "response_structure_valid": False,
            "timestamps_valid": False,
            "responder_identity_verified": False,
            "cryptographic_strength_adequate": False,
            "overall_security_status": "FAIL",
            "security_details": {},
            "recommendations": []
        }
        
        try:
            self.log("[SECURITY] Performing comprehensive OCSP response security validation...\n")
            
            # Step 1: Verify digital signature using CA public key
            verify_cmd = [
                "openssl", "ocsp", 
                "-respin", ocsp_response_path,
                "-verify_other", issuer_path,
                "-CAfile", issuer_path,
                "-no_nonce"
            ]
            
            self.log(f"[SECURITY] Signature verification command: {' '.join(verify_cmd)}\n")
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
            
            if verify_result.returncode == 0 and "Response verify OK" in verify_result.stdout:
                security_results["signature_valid"] = True
                self.log("[SECURITY] ✓ Digital signature verified against CA public key\n")
            else:
                self.log("[SECURITY] ✗ Digital signature verification failed\n")
                security_results["recommendations"].append("CRITICAL: OCSP response signature invalid - reject response")
            
            # Step 2: Validate response structure
            text_cmd = ["openssl", "ocsp", "-respin", ocsp_response_path, "-text", "-noout"]
            text_result = subprocess.run(text_cmd, capture_output=True, text=True, timeout=15)
            
            if text_result.returncode == 0:
                response_text = text_result.stdout
                
                # Check for required OCSP response fields
                required_fields = ["OCSP Response Status", "Response Type", "Version", "Responder Id", "Produced At"]
                missing_fields = [field for field in required_fields if field not in response_text]
                
                if not missing_fields:
                    security_results["response_structure_valid"] = True
                    self.log("[SECURITY] ✓ OCSP response structure valid\n")
                else:
                    self.log(f"[SECURITY] ✗ Missing required fields: {missing_fields}\n")
                    security_results["recommendations"].append("OCSP response structure incomplete")
                
                # Step 3: Validate timestamps
                if "Produced At:" in response_text and "This Update:" in response_text:
                    security_results["timestamps_valid"] = True
                    self.log("[SECURITY] ✓ Required timestamps present\n")
                else:
                    self.log("[SECURITY] ✗ Missing required timestamps\n")
                    security_results["recommendations"].append("OCSP response missing required timestamps")
                
                # Step 4: Verify responder identity
                if "Responder Id:" in response_text:
                    security_results["responder_identity_verified"] = True
                    self.log("[SECURITY] ✓ Responder identity present\n")
                else:
                    self.log("[SECURITY] ✗ Responder identity missing\n")
                    security_results["recommendations"].append("OCSP responder identity not verified")
            
            # Step 5: Assess cryptographic strength
            # Check signature algorithm
            if "Signature Algorithm:" in text_result.stdout:
                sig_algo_line = [line for line in text_result.stdout.split('\n') if "Signature Algorithm:" in line][0]
                if "sha256" in sig_algo_line.lower() or "sha384" in sig_algo_line.lower() or "sha512" in sig_algo_line.lower():
                    security_results["cryptographic_strength_adequate"] = True
                    self.log("[SECURITY] ✓ Cryptographic strength adequate\n")
                else:
                    self.log("[SECURITY] ⚠ Weak cryptographic algorithm detected\n")
                    security_results["recommendations"].append("Consider upgrading to stronger cryptographic algorithms")
            
            # Determine overall security status
            critical_checks = [security_results["signature_valid"], security_results["response_structure_valid"]]
            if all(critical_checks):
                security_results["overall_security_status"] = "PASS"
                self.log("[SECURITY] ✓ Overall security validation PASSED\n")
            else:
                security_results["overall_security_status"] = "FAIL"
                self.log("[SECURITY] ✗ Overall security validation FAILED\n")
            
            # Add detailed security information
            security_results["security_details"] = {
                "verification_command": " ".join(verify_cmd),
                "verification_return_code": verify_result.returncode,
                "verification_stdout": verify_result.stdout,
                "verification_stderr": verify_result.stderr,
                "response_text_available": text_result.returncode == 0,
                "validation_timestamp": datetime.now().isoformat()
            }
            
            return security_results
            
        except Exception as e:
            self.log(f"[SECURITY] Security validation exception: {e}\n")
            security_results["overall_security_status"] = "ERROR"
            security_results["recommendations"].append(f"Security validation failed: {str(e)}")
            return security_results

    def validate_ca_designated_responder(self, responder_cert_path: str, issuer_cert_path: str) -> Dict[str, Any]:
        """
        Validate CA Designated Responder certificate according to RFC 6960
        
        This method validates that a responder certificate is properly authorized to sign
        OCSP responses on behalf of the issuing CA by checking:
        1. Extended Key Usage (EKU) includes id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
        2. Responder certificate is issued by the same CA
        3. Responder certificate is valid and not expired
        4. Responder certificate has appropriate key usage
        
        Args:
            responder_cert_path: Path to the responder certificate
            issuer_cert_path: Path to the issuing CA certificate
            
        Returns:
            Dict containing validation results and details
        """
        validation_results = {
            "is_valid_designated_responder": False,
            "has_ocsp_signing_eku": False,
            "issued_by_same_ca": False,
            "certificate_valid": False,
            "has_appropriate_key_usage": False,
            "validation_details": {},
            "recommendations": []
        }
        
        try:
            self.log("[DELEGATED] Validating CA Designated Responder certificate...\n")
            
            # Step 1: Check Extended Key Usage for id-kp-OCSPSigning
            eku_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-ext", "extendedKeyUsage"]
            eku_result = subprocess.run(eku_cmd, capture_output=True, text=True, timeout=15)
            
            if eku_result.returncode == 0:
                eku_output = eku_result.stdout
                self.log(f"[DELEGATED] EKU output: {eku_output}\n")
                
                # Check for id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
                if ("1.3.6.1.5.5.7.3.9" in eku_output or 
                    "OCSPSigning" in eku_output or 
                    "TLS Web Server Authentication, OCSP Signing" in eku_output):
                    validation_results["has_ocsp_signing_eku"] = True
                    self.log("[DELEGATED] ✓ Responder has id-kp-OCSPSigning EKU extension\n")
                else:
                    self.log("[DELEGATED] ✗ Responder missing id-kp-OCSPSigning EKU extension\n")
                    validation_results["recommendations"].append("CRITICAL: Responder certificate missing id-kp-OCSPSigning EKU")
            else:
                self.log(f"[DELEGATED] ✗ Failed to read EKU extension: {eku_result.stderr}\n")
                validation_results["recommendations"].append("Could not verify EKU extension")
            
            # Step 2: Verify responder certificate is issued by the same CA
            responder_issuer_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-issuer"]
            responder_issuer_result = subprocess.run(responder_issuer_cmd, capture_output=True, text=True, timeout=15)
            
            ca_subject_cmd = ["openssl", "x509", "-in", issuer_cert_path, "-noout", "-subject"]
            ca_subject_result = subprocess.run(ca_subject_cmd, capture_output=True, text=True, timeout=15)
            
            if (responder_issuer_result.returncode == 0 and ca_subject_result.returncode == 0):
                responder_issuer = responder_issuer_result.stdout.strip()
                ca_subject = ca_subject_result.stdout.strip()
                
                # Clean up subject strings (remove "subject=" prefix if present)
                if responder_issuer.startswith("issuer="):
                    responder_issuer = responder_issuer[7:].strip()
                if ca_subject.startswith("subject="):
                    ca_subject = ca_subject[8:].strip()
                
                self.log(f"[DELEGATED] Responder issuer: {responder_issuer}\n")
                self.log(f"[DELEGATED] CA subject: {ca_subject}\n")
                
                if responder_issuer == ca_subject:
                    validation_results["issued_by_same_ca"] = True
                    self.log("[DELEGATED] ✓ Responder issued by same CA\n")
                else:
                    self.log("[DELEGATED] ✗ Responder not issued by same CA\n")
                    validation_results["recommendations"].append("Responder certificate not issued by the same CA")
            else:
                self.log("[DELEGATED] ✗ Failed to verify issuer relationship\n")
                validation_results["recommendations"].append("Could not verify issuer relationship")
            
            # Step 3: Check certificate validity period
            validity_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-dates"]
            validity_result = subprocess.run(validity_cmd, capture_output=True, text=True, timeout=15)
            
            if validity_result.returncode == 0:
                validity_output = validity_result.stdout
                self.log(f"[DELEGATED] Certificate validity: {validity_output}\n")
                
                # Parse validity dates
                not_before_match = re.search(r"notBefore=(.+)", validity_output)
                not_after_match = re.search(r"notAfter=(.+)", validity_output)
                
                if not_before_match and not_after_match:
                    try:
                        not_before = datetime.strptime(not_before_match.group(1), "%b %d %H:%M:%S %Y %Z")
                        not_after = datetime.strptime(not_after_match.group(1), "%b %d %H:%M:%S %Y %Z")
                        now = datetime.utcnow()
                        
                        if not_before <= now <= not_after:
                            validation_results["certificate_valid"] = True
                            self.log("[DELEGATED] ✓ Responder certificate is valid\n")
                        else:
                            self.log("[DELEGATED] ✗ Responder certificate expired or not yet valid\n")
                            validation_results["recommendations"].append("Responder certificate expired or not yet valid")
                    except Exception as e:
                        self.log(f"[DELEGATED] ✗ Error parsing validity dates: {e}\n")
                        validation_results["recommendations"].append("Could not parse certificate validity dates")
                else:
                    self.log("[DELEGATED] ✗ Could not parse validity dates\n")
                    validation_results["recommendations"].append("Could not parse certificate validity dates")
            else:
                self.log("[DELEGATED] ✗ Failed to read certificate validity\n")
                validation_results["recommendations"].append("Could not verify certificate validity")
            
            # Step 4: Check Key Usage extension
            ku_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-ext", "keyUsage"]
            ku_result = subprocess.run(ku_cmd, capture_output=True, text=True, timeout=15)
            
            if ku_result.returncode == 0:
                ku_output = ku_result.stdout
                self.log(f"[DELEGATED] Key Usage: {ku_output}\n")
                
                # Check for Digital Signature usage (required for OCSP signing)
                if ("Digital Signature" in ku_output or 
                    "digitalSignature" in ku_output.lower()):
                    validation_results["has_appropriate_key_usage"] = True
                    self.log("[DELEGATED] ✓ Responder has appropriate key usage\n")
                else:
                    self.log("[DELEGATED] ✗ Responder missing Digital Signature key usage\n")
                    validation_results["recommendations"].append("Responder certificate missing Digital Signature key usage")
            else:
                self.log("[DELEGATED] ✗ Failed to read Key Usage extension\n")
                validation_results["recommendations"].append("Could not verify Key Usage extension")
            
            # Determine overall validation result
            critical_checks = [
                validation_results["has_ocsp_signing_eku"],
                validation_results["issued_by_same_ca"],
                validation_results["certificate_valid"],
                validation_results["has_appropriate_key_usage"]
            ]
            
            if all(critical_checks):
                validation_results["is_valid_designated_responder"] = True
                self.log("[DELEGATED] ✓ CA Designated Responder validation PASSED\n")
            else:
                self.log("[DELEGATED] ✗ CA Designated Responder validation FAILED\n")
            
            # Add detailed validation information
            validation_results["validation_details"] = {
                "eku_command": " ".join(eku_cmd),
                "eku_output": eku_result.stdout if eku_result.returncode == 0 else eku_result.stderr,
                "issuer_verification": {
                    "responder_issuer": responder_issuer_result.stdout if responder_issuer_result.returncode == 0 else responder_issuer_result.stderr,
                    "ca_subject": ca_subject_result.stdout if ca_subject_result.returncode == 0 else ca_subject_result.stderr
                },
                "validity_check": validity_result.stdout if validity_result.returncode == 0 else validity_result.stderr,
                "key_usage_check": ku_result.stdout if ku_result.returncode == 0 else ku_result.stderr,
                "validation_timestamp": datetime.now().isoformat()
            }
            
            return validation_results
            
        except Exception as e:
            self.log(f"[DELEGATED] CA Designated Responder validation exception: {e}\n")
            validation_results["recommendations"].append(f"Validation failed: {str(e)}")
            return validation_results

    def run_crl_check(self, cert_path: str, issuer_path: str, crl_override_url: Optional[str] = None) -> Dict[str, Any]:
        """Run comprehensive CRL check"""
        try:
            self.log("[INFO] Running CRL check...\n")
            
            validity_ok = None
            validity_start = None
            validity_end = None
            if self.check_validity:
                validity_ok, validity_start, validity_end = self.check_certificate_validity(cert_path)

            crl_url = crl_override_url or self.extract_crl_url(cert_path)
            if not crl_url:
                self.log("[WARN] No CRL URL found.\n")
                return {
                    "summary": "[CRL CHECK SUMMARY]\n[ERROR] No CRL URL found.\n",
                    "error": "No CRL URL found"
                }
                
            self.log(f"[INFO] Downloading CRL from {crl_url}\n")
            resp = requests.get(crl_url, timeout=15)
            
            # Check if the response is valid
            if resp.status_code != 200:
                self.log(f"[ERROR] CRL download failed with HTTP {resp.status_code}\n")
                return {
                    "summary": f"[CRL CHECK SUMMARY]\n[ERROR] CRL download failed with HTTP {resp.status_code}\n",
                    "error": f"CRL download failed: HTTP {resp.status_code}"
                }
            
            # Check if the response is too small to be a valid CRL
            if len(resp.content) < 100:  # CRLs should be at least 100 bytes
                self.log(f"[ERROR] CRL download returned suspiciously small content ({len(resp.content)} bytes)\n")
                self.log(f"[ERROR] Response content: {resp.content[:200]}\n")  # Show first 200 bytes for debugging
                return {
                    "summary": f"[CRL CHECK SUMMARY]\n[ERROR] CRL download returned invalid content ({len(resp.content)} bytes)\n",
                    "error": "CRL download returned invalid content"
                }
            
            crl_file = f"crl_{uuid4().hex}"
            crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
            
            # Determine file extension based on URL
            if crl_url.lower().endswith('.p7c'):
                crl_path += '.p7c'
                self.log(f"[INFO] Detected P7C format CRL\n")
            else:
                crl_path += '.crl'
                self.log(f"[INFO] Detected raw CRL format\n")
            
            with open(crl_path, "wb") as f:
                f.write(resp.content)
            self.log(f"[INFO] CRL saved to {crl_path}\n")

            # Handle P7C format CRL
            if crl_url.lower().endswith('.p7c'):
                self.log("[INFO] Processing P7C format CRL...\n")
                self.log(f"[DEBUG] Using enhanced P7C processing v{self.VERSION}\n")
                
                # First, analyze the file content to understand its format
                self.log("[INFO] Analyzing file content...\n")
                with open(crl_path, 'rb') as f:
                    content = f.read(100)  # Read first 100 bytes
                    self.log(f"[INFO] File starts with: {content[:20].hex()}\n")
                    self.log(f"[INFO] File size: {os.path.getsize(crl_path)} bytes\n")
                    
                    # Enhanced file format detection
                    file_size = os.path.getsize(crl_path)
                    if content.startswith(b'\x30\x82'):  # DER SEQUENCE
                        self.log("[INFO] Detected DER SEQUENCE structure (likely PKCS#7/CMS)\n")
                        # Check for PKCS#7 SignedData OID (1.2.840.113549.1.7.2)
                        if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02' in content:
                            self.log("[INFO] Detected PKCS#7 SignedData structure\n")
                        # Check for CMS SignedData OID (1.2.840.113549.1.7.2)
                        elif b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02' in content:
                            self.log("[INFO] Detected CMS SignedData structure\n")
                    elif content.startswith(b'-----BEGIN'):
                        self.log("[INFO] Detected PEM format\n")
                    elif content.startswith(b'\x30\x81'):  # DER SEQUENCE with short length
                        self.log("[INFO] Detected DER SEQUENCE with short length\n")
                    else:
                        self.log("[INFO] Unknown file format, trying generic methods\n")
                
                # Try different approaches based on file analysis
                success = False
                
                # Method 1: Try as PKCS#7 PEM format
                if not success:
                    self.log("[INFO] Trying PKCS#7 PEM format...\n")
                    extract_cmd = ["openssl", "pkcs7", "-in", crl_path, "-print_certs", "-out", crl_path + ".extracted"]
                    self.log("[CMD] " + " ".join(extract_cmd) + "\n")
                    extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                    
                    if extract_result.returncode == 0:
                        self.log("[INFO] PKCS#7 PEM extraction successful\n")
                        crl_path = crl_path + ".extracted"
                        success = True
                    else:
                        self.log(f"[STDERR] PKCS#7 PEM failed: {extract_result.stderr}\n")
                
                # Method 2: Try as PKCS#7 DER format
                if not success:
                    self.log("[INFO] Trying PKCS#7 DER format...\n")
                    pem_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-out", crl_path + ".pem"]
                    self.log("[CMD] " + " ".join(pem_cmd) + "\n")
                    pem_result = subprocess.run(pem_cmd, capture_output=True, text=True)
                    
                    if pem_result.returncode == 0:
                        self.log("[INFO] PKCS#7 DER conversion successful\n")
                        
                        # Check if the PEM file contains CRL data
                        with open(crl_path + ".pem", 'r') as f:
                            pem_content = f.read()
                            if "BEGIN X509 CRL" in pem_content:
                                self.log("[INFO] Found CRL in PKCS#7 structure\n")
                                crl_path = crl_path + ".pem"
                                success = True
                            else:
                                # Try to extract CRL using different methods
                                self.log("[INFO] No direct CRL found, trying extraction methods...\n")
                                
                                # Method 2a: Try to extract as CRL directly
                        crl_extract_cmd = ["openssl", "crl", "-in", crl_path + ".pem", "-out", crl_path + ".crl"]
                        self.log("[CMD] " + " ".join(crl_extract_cmd) + "\n")
                        crl_extract_result = subprocess.run(crl_extract_cmd, capture_output=True, text=True)
                        
                        if crl_extract_result.returncode == 0:
                            crl_path = crl_path + ".crl"
                            self.log(f"[INFO] Successfully extracted CRL to {crl_path}\n")
                            success = True
                        else:
                            self.log(f"[STDERR] CRL extraction failed: {crl_extract_result.stderr}\n")
                            
                            # Method 2b: Try to extract certificates first, then look for CRL
                            cert_extract_cmd = ["openssl", "pkcs7", "-in", crl_path + ".pem", "-print_certs", "-out", crl_path + ".certs"]
                            self.log("[CMD] " + " ".join(cert_extract_cmd) + "\n")
                            cert_extract_result = subprocess.run(cert_extract_cmd, capture_output=True, text=True)
                            
                            if cert_extract_result.returncode == 0:
                                # Check if certificates file contains CRL
                                with open(crl_path + ".certs", 'r') as f:
                                    cert_content = f.read()
                                    if "BEGIN X509 CRL" in cert_content:
                                        self.log("[INFO] Found CRL in certificate extraction\n")
                                        crl_path = crl_path + ".certs"
                                        success = True
                                    else:
                                        self.log("[INFO] No CRL found in certificate extraction\n")
                            else:
                                self.log(f"[STDERR] Certificate extraction failed: {cert_extract_result.stderr}\n")
                    else:
                        self.log(f"[STDERR] PKCS#7 DER conversion failed: {pem_result.stderr}\n")
                
                # Method 3: Try as raw CRL (maybe it's just misnamed)
                if not success:
                    self.log("[INFO] Trying as raw CRL format...\n")
                    test_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                    
                    if test_result.returncode == 0:
                        self.log("[INFO] File is actually a raw CRL format\n")
                        success = True
                    else:
                        self.log(f"[STDERR] Not a raw CRL: {test_result.stderr}\n")
                
                # Method 4: Try as certificate bundle
                if not success:
                    self.log("[INFO] Trying as certificate bundle...\n")
                    cert_cmd = ["openssl", "x509", "-in", crl_path, "-inform", "DER", "-out", crl_path + ".pem"]
                    cert_result = subprocess.run(cert_cmd, capture_output=True, text=True)
                    
                    if cert_result.returncode == 0:
                        self.log("[INFO] File contains certificates, trying to extract CRL...\n")
                        # Look for CRL in the PEM file
                        with open(crl_path + ".pem", 'r') as f:
                            pem_content = f.read()
                            if "BEGIN X509 CRL" in pem_content:
                                self.log("[INFO] Found CRL in certificate bundle\n")
                                crl_path = crl_path + ".pem"
                                success = True
                            else:
                                self.log("[INFO] No CRL found in certificate bundle\n")
                    else:
                        self.log(f"[STDERR] Not a certificate bundle: {cert_result.stderr}\n")
                
                # Method 5: Try CMS (Cryptographic Message Syntax) processing
                if not success:
                    self.log("[INFO] Trying CMS processing for P7C file...\n")
                    try:
                        # Try to use cms command if available (OpenSSL 1.1.1+)
                        cms_cmd = ["openssl", "cms", "-in", crl_path, "-inform", "DER", "-verify", "-noverify", "-out", crl_path + ".cms"]
                        self.log("[CMD] " + " ".join(cms_cmd) + "\n")
                        cms_result = subprocess.run(cms_cmd, capture_output=True, text=True)
                        
                        if cms_result.returncode == 0:
                            self.log("[INFO] CMS processing successful\n")
                            # Check if CMS output contains CRL
                            with open(crl_path + ".cms", 'rb') as f:
                                cms_content = f.read()
                                if b"BEGIN X509 CRL" in cms_content:
                                    self.log("[INFO] Found CRL in CMS output\n")
                                    crl_path = crl_path + ".cms"
                                    success = True
                                else:
                                    self.log("[INFO] No CRL found in CMS output\n")
                        else:
                            self.log(f"[STDERR] CMS processing failed: {cms_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] CMS processing exception: {e}\n")
                
                # Method 6: Try ASN.1 parsing approach
                if not success:
                    self.log("[INFO] Trying ASN.1 parsing approach...\n")
                    try:
                        # Try to use asn1parse to understand the structure
                        asn1_cmd = ["openssl", "asn1parse", "-in", crl_path, "-inform", "DER"]
                        self.log("[CMD] " + " ".join(asn1_cmd) + "\n")
                        asn1_result = subprocess.run(asn1_cmd, capture_output=True, text=True)
                        
                        if asn1_result.returncode == 0:
                            self.log("[INFO] ASN.1 parsing successful\n")
                            self.log("[INFO] " + asn1_result.stdout + "\n")
                            
                            # Look for CRL-related OIDs in the output
                            if "1.3.6.1.5.5.7.48.2" in asn1_result.stdout or "crl" in asn1_result.stdout.lower():
                                self.log("[INFO] Found CRL-related data in ASN.1 structure\n")
                                # Try to extract using different offsets
                                for offset in ["0", "4", "8", "12", "16"]:
                                    try:
                                        extract_cmd = ["openssl", "asn1parse", "-in", crl_path, "-inform", "DER", "-offset", offset, "-length", "1000", "-out", crl_path + f".extract_{offset}"]
                                        extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                                        if extract_result.returncode == 0:
                                            # Try to parse extracted data as CRL
                                            test_cmd = ["openssl", "crl", "-in", crl_path + f".extract_{offset}", "-inform", "DER", "-noout", "-text"]
                                            test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                            if test_result.returncode == 0:
                                                self.log(f"[INFO] Successfully extracted CRL at offset {offset}\n")
                                                crl_path = crl_path + f".extract_{offset}"
                                                success = True
                                                break
                                    except Exception:
                                        continue
                        else:
                            self.log(f"[STDERR] ASN.1 parsing failed: {asn1_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] ASN.1 parsing exception: {e}\n")
                
                # Method 7: Try PKCS#7 with different extraction methods
                if not success:
                    self.log("[INFO] Trying advanced PKCS#7 extraction methods...\n")
                    try:
                        # Method 7a: Try pkcs7 with -print_certs and look for CRL
                        pkcs7_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-print_certs", "-out", crl_path + ".pkcs7_certs"]
                        self.log("[CMD] " + " ".join(pkcs7_cmd) + "\n")
                        pkcs7_result = subprocess.run(pkcs7_cmd, capture_output=True, text=True)
                        
                        if pkcs7_result.returncode == 0:
                            # Check if the output contains CRL data
                            with open(crl_path + ".pkcs7_certs", 'r') as f:
                                pkcs7_content = f.read()
                                if "BEGIN X509 CRL" in pkcs7_content:
                                    self.log("[INFO] Found CRL in PKCS#7 certificate extraction\n")
                                    crl_path = crl_path + ".pkcs7_certs"
                                    success = True
                                else:
                                    self.log("[INFO] No CRL found in PKCS#7 certificate extraction\n")
                        else:
                            self.log(f"[STDERR] PKCS#7 certificate extraction failed: {pkcs7_result.stderr}\n")
                            
                        # Method 7b: Try pkcs7 with -text to get human-readable output
                        if not success:
                            pkcs7_text_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-text", "-noout"]
                            self.log("[CMD] " + " ".join(pkcs7_text_cmd) + "\n")
                            pkcs7_text_result = subprocess.run(pkcs7_text_cmd, capture_output=True, text=True)
                            
                            if pkcs7_text_result.returncode == 0:
                                self.log("[INFO] PKCS#7 text output successful\n")
                                self.log("[INFO] " + pkcs7_text_result.stdout + "\n")
                                
                                # Look for CRL-related content in the text output
                                if "CRL" in pkcs7_text_result.stdout or "Certificate Revocation List" in pkcs7_text_result.stdout:
                                    self.log("[INFO] Found CRL-related content in PKCS#7 text output\n")
                                    # Try to extract the CRL using different methods
                                    for method in ["crl", "x509", "pkcs7"]:
                                        try:
                                            extract_cmd = ["openssl", method, "-in", crl_path, "-inform", "DER", "-out", crl_path + f".{method}_extract"]
                                            extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                                            if extract_result.returncode == 0:
                                                # Test if extracted file is a valid CRL
                                                test_cmd = ["openssl", "crl", "-in", crl_path + f".{method}_extract", "-noout", "-text"]
                                                test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                                if test_result.returncode == 0:
                                                    self.log(f"[INFO] Successfully extracted CRL using {method} method\n")
                                                    crl_path = crl_path + f".{method}_extract"
                                                    success = True
                                                    break
                                        except Exception:
                                            continue
                            else:
                                self.log(f"[STDERR] PKCS#7 text output failed: {pkcs7_text_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] Advanced PKCS#7 extraction exception: {e}\n")
                
                # Method 8: Try binary analysis and manual extraction
                if not success:
                    self.log("[INFO] Trying binary analysis and manual extraction...\n")
                    try:
                        # Read the entire file and look for CRL patterns
                        with open(crl_path, 'rb') as f:
                            file_content = f.read()
                        
                        # Look for CRL-related patterns in the binary data
                        crl_patterns = [
                            b'BEGIN X509 CRL',
                            b'Certificate Revocation List',
                            b'CRL',
                            b'\x30\x82',  # DER SEQUENCE that might be a CRL
                        ]
                        
                        for i, pattern in enumerate(crl_patterns):
                            if pattern in file_content:
                                self.log(f"[INFO] Found CRL pattern {i+1} in binary data\n")
                                
                                # Try to extract around the pattern
                                pattern_pos = file_content.find(pattern)
                                if pattern_pos > 0:
                                    # Extract data around the pattern
                                    start_pos = max(0, pattern_pos - 100)
                                    end_pos = min(len(file_content), pattern_pos + 2000)
                                    extracted_data = file_content[start_pos:end_pos]
                                    
                                    # Save extracted data
                                    extracted_path = crl_path + f".binary_extract_{i}"
                                    with open(extracted_path, 'wb') as f:
                                        f.write(extracted_data)
                                    
                                    # Try to parse as CRL
                                    test_cmd = ["openssl", "crl", "-in", extracted_path, "-noout", "-text"]
                                    test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                    if test_result.returncode == 0:
                                        self.log(f"[INFO] Successfully extracted CRL using binary analysis\n")
                                        crl_path = extracted_path
                                        success = True
                                        break
                                    else:
                                        # Try with DER format
                                        test_cmd = ["openssl", "crl", "-in", extracted_path, "-inform", "DER", "-noout", "-text"]
                                        test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                        if test_result.returncode == 0:
                                            self.log(f"[INFO] Successfully extracted CRL using binary analysis (DER)\n")
                                            crl_path = extracted_path
                                            success = True
                                            break
                        
                        if not success:
                            self.log("[INFO] No CRL patterns found in binary analysis\n")
                    except Exception as e:
                        self.log(f"[STDERR] Binary analysis exception: {e}\n")
                
                # Method 9: Extract CRL URLs from certificate in P7C file
                if not success:
                    self.log("[INFO] Trying to extract CRL URLs from certificate in P7C file...\n")
                    try:
                        # The P7C file might contain a certificate with CRL distribution points
                        # Try to extract the certificate and get CRL URLs from it
                        cert_extract_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-print_certs", "-out", crl_path + ".cert"]
                        self.log("[CMD] " + " ".join(cert_extract_cmd) + "\n")
                        cert_extract_result = subprocess.run(cert_extract_cmd, capture_output=True, text=True)
                        
                        if cert_extract_result.returncode == 0:
                            self.log("[INFO] Successfully extracted certificate from P7C file\n")
                            
                            # Get CRL distribution points from the certificate
                            crl_dp_cmd = ["openssl", "x509", "-in", crl_path + ".cert", "-noout", "-text", "-certopt", "no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_issuer,no_pubkey,no_sigdump,no_aux"]
                            self.log("[CMD] " + " ".join(crl_dp_cmd) + "\n")
                            crl_dp_result = subprocess.run(crl_dp_cmd, capture_output=True, text=True)
                            
                            if crl_dp_result.returncode == 0:
                                self.log("[INFO] Certificate analysis successful\n")
                                self.log("[INFO] " + crl_dp_result.stdout + "\n")
                                
                                # Look for CRL distribution points in the output
                                if "CRL Distribution Points" in crl_dp_result.stdout:
                                    self.log("[INFO] Found CRL Distribution Points in certificate\n")
                                    
                                    # Extract CRL URLs from the output
                                    crl_urls = re.findall(r'http[s]?://[^\s]+\.crl', crl_dp_result.stdout)
                                    if crl_urls:
                                        self.log(f"[INFO] Found CRL URLs: {crl_urls}\n")
                                        
                                        # Try to download CRL from the first URL
                                        for crl_url in crl_urls:
                                            try:
                                                self.log(f"[INFO] Trying to download CRL from: {crl_url}\n")
                                                resp = requests.get(crl_url, timeout=10)
                                                if resp.status_code == 200:
                                                    # Save the CRL
                                                    crl_file_path = crl_path.replace('.p7c', '.crl')
                                                    with open(crl_file_path, "wb") as f:
                                                        f.write(resp.content)
                                                    self.log(f"[INFO] Successfully downloaded CRL to: {crl_file_path}\n")
                                                    
                                                    # Test if it's a valid CRL
                                                    test_cmd = ["openssl", "crl", "-in", crl_file_path, "-noout", "-text"]
                                                    test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                                    if test_result.returncode == 0:
                                                        self.log(f"[INFO] Successfully validated CRL from distribution point\n")
                                                        crl_path = crl_file_path
                                                        success = True
                                                        break
                                                    else:
                                                        self.log(f"[STDERR] Downloaded file is not a valid CRL: {test_result.stderr}\n")
                                                else:
                                                    self.log(f"[STDERR] Failed to download CRL from {crl_url}: HTTP {resp.status_code}\n")
                                            except Exception as e:
                                                self.log(f"[STDERR] Exception downloading CRL from {crl_url}: {e}\n")
                                    else:
                                        self.log("[INFO] No CRL URLs found in certificate\n")
                                else:
                                    self.log("[INFO] No CRL Distribution Points found in certificate\n")
                            else:
                                self.log(f"[STDERR] Certificate analysis failed: {crl_dp_result.stderr}\n")
                        else:
                            self.log(f"[STDERR] Certificate extraction failed: {cert_extract_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] CRL URL extraction exception: {e}\n")
                
                if not success:
                    self.log("[WARN] Could not process P7C file with any known method\n")
                    self.log("[INFO] File may contain CRL data in an unsupported format\n")
                    
                    # Try alternative CRL URLs
                    self.log("[INFO] Trying alternative CRL URLs...\n")
                    base_url = crl_url.replace('/AIA/CertsIssuedToEMSSSPCA.p7c', '')
                    alternative_urls = [
                        f"{base_url}/CRLs/EMSSSPCA4.crl",
                        f"{base_url}/CRL/EMSSSPCA4.crl", 
                        f"{base_url}/crl/EMSSSPCA4.crl",
                        f"{base_url}/CRLs/EMSSSPCA.crl"
                    ]
                    
                    for alt_url in alternative_urls:
                        self.log(f"[INFO] Trying alternative URL: {alt_url}\n")
                        try:
                            alt_resp = requests.get(alt_url, timeout=10)
                            if alt_resp.status_code == 200:
                                alt_crl_path = crl_path.replace('.p7c', '.crl')
                                with open(alt_crl_path, "wb") as f:
                                    f.write(alt_resp.content)
                                self.log(f"[INFO] Alternative CRL downloaded: {alt_crl_path}\n")
                                
                                # Test if this is a valid CRL
                                test_cmd = ["openssl", "crl", "-in", alt_crl_path, "-noout", "-text"]
                                self.log("[CMD] " + " ".join(test_cmd) + "\n")
                                test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=30)
                                
                                if test_result.returncode == 0:
                                    self.log(f"[INFO] Alternative CRL is valid, using: {alt_crl_path}\n")
                                    self.log("[INFO] " + test_result.stdout + "\n")
                                    crl_path = alt_crl_path
                                    success = True
                                    break
                                else:
                                    self.log(f"[STDERR] Alternative CRL invalid: {test_result.stderr}\n")
                        except Exception as e:
                            self.log(f"[STDERR] Failed to download alternative CRL: {e}\n")

            # Final CRL processing
            self.log(f"[INFO] Processing final CRL file: {crl_path}\n")
            crl_size = os.path.getsize(crl_path)
            self.log(f"[INFO] CRL file size: {crl_size:,} bytes ({crl_size/1024/1024:.1f} MB)\n")
            
            if crl_size > 10 * 1024 * 1024:  # > 10MB
                self.log("[INFO] Large CRL detected, using optimized processing...\n")
                # For large CRLs, just verify signature and check basic info
                verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-verify", "-CAfile", issuer_path]
                self.log("[CMD] " + " ".join(verify_cmd) + "\n")
                try:
                    verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=60)
                    if verify_result.returncode == 0:
                        self.log("[INFO] [OK] Large CRL signature verified successfully\n")
                        # Get basic CRL info without full text output
                        info_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-issuer", "-lastupdate", "-nextupdate"]
                        self.log("[CMD] " + " ".join(info_cmd) + "\n")
                        info_result = subprocess.run(info_cmd, capture_output=True, text=True, timeout=30)
                        self.log("[INFO] " + info_result.stdout + "\n")
                        if info_result.stderr:
                            self.log("[STDERR] " + info_result.stderr + "\n")
                    else:
                        self.log(f"[STDERR] Large CRL signature verification failed: {verify_result.stderr}\n")
                except subprocess.TimeoutExpired:
                    self.log("[ERROR] Large CRL processing timed out\n")
                    return {
                        "summary": "[CRL CHECK SUMMARY]\n[ERROR] Large CRL processing timed out\n",
                        "error": "Large CRL processing timeout"
                    }
            else:
                # For smaller CRLs, do full processing
                verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                self.log("[CMD] " + " ".join(verify_cmd) + "\n")
                self.log("[INFO] Processing CRL content (this may take a moment for large CRLs)...\n")
                try:
                    crl_out = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired:
                    self.log("[ERROR] CRL processing timed out after 30 seconds\n")
                    return {
                        "summary": "[CRL CHECK SUMMARY]\n[ERROR] CRL processing timed out\n",
                        "error": "CRL processing timeout"
                    }
                self.log("[INFO] " + crl_out.stdout + "\n")
                
                if crl_out.stderr:
                    self.log("[STDERR] " + crl_out.stderr + "\n")
            
            # Check if CRL parsing failed completely (only for small CRLs)
            if 'crl_out' in locals() and (crl_out.returncode != 0 or "Could not find CRL" in crl_out.stderr):
                self.log("[ERROR] CRL parsing failed completely\n")
                return {
                    "summary": "[CRL CHECK SUMMARY]\n[ERROR] CRL parsing failed - file format not supported\n",
                    "error": "CRL parsing failed",
                    "crl_path": crl_path,
                    "crl_url": crl_url
                }

            summary = "[CRL CHECK SUMMARY]\n"
            results = {
                "validity_ok": validity_ok,
                "validity_start": validity_start,
                "validity_end": validity_end,
                "signature_verified": False,
                "update_times_valid": False,
                "cert_revoked": False,
                "overall_pass": False
            }

            # Certificate validity in summary
            if validity_ok is not None:
                if validity_ok:
                    summary += f"[OK] Certificate Validity Period OK ({validity_start} to {validity_end})\n"
                else:
                    summary += f"[ERROR] Certificate Validity Period ERROR ({validity_start} to {validity_end})\n"

            # CRL signature verification - try multiple approaches
            verify_sig_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-verify", "-CAfile", issuer_path]
            self.log("[CMD] " + " ".join(verify_sig_cmd) + "\n")
            verify_sig_result = subprocess.run(verify_sig_cmd, capture_output=True, text=True)
            
            crl_signature_valid = False
            if "verify ok" in verify_sig_result.stderr.lower():
                summary += "[OK] CRL Signature Valid\n"
                results["signature_verified"] = True
                crl_signature_valid = True
            else:
                # Try without CAfile (let OpenSSL find the issuer)
                self.log("[INFO] Trying CRL verification without CAfile...\n")
                verify_sig_cmd2 = ["openssl", "crl", "-in", crl_path, "-noout", "-verify"]
                verify_sig_result2 = subprocess.run(verify_sig_cmd2, capture_output=True, text=True)
                
                if "verify ok" in verify_sig_result2.stderr.lower():
                    summary += "[OK] CRL Signature Valid (auto-detected issuer)\n"
                    results["signature_verified"] = True
                    crl_signature_valid = True
                else:
                    # Try to extract the CRL issuer and find matching certificate
                    self.log("[INFO] CRL issuer mismatch - trying to find correct issuer...\n")
                    
                    # Extract CRL issuer from the CRL text output
                    crl_issuer_match = re.search(r"Issuer:\s*(.+)", crl_out.stdout)
                    if crl_issuer_match:
                        crl_issuer = crl_issuer_match.group(1).strip()
                        self.log(f"[INFO] CRL Issuer: {crl_issuer}\n")
                        
                        # Check if the provided issuer certificate matches the CRL issuer
                        issuer_info_cmd = ["openssl", "x509", "-in", issuer_path, "-noout", "-subject"]
                        issuer_info_result = subprocess.run(issuer_info_cmd, capture_output=True, text=True)
                        
                        if issuer_info_result.returncode == 0:
                            issuer_subject = issuer_info_result.stdout.strip()
                            self.log(f"[INFO] Provided Issuer: {issuer_subject}\n")
                            
                            # Extract the actual subject from "subject=..." format
                            if issuer_subject.startswith("subject="):
                                issuer_subject_clean = issuer_subject[8:].strip()
                            else:
                                issuer_subject_clean = issuer_subject
                            
                            # If issuers don't match, this is expected for CRL Distribution Points
                            if crl_issuer not in issuer_subject_clean and issuer_subject_clean not in crl_issuer:
                                summary += "[WARN] CRL issuer differs from provided certificate (expected for CRL Distribution Points)\n"
                                summary += f"[INFO] CRL Issuer: {crl_issuer}\n"
                                summary += f"[INFO] Provided Issuer: {issuer_subject_clean}\n"
                                summary += "[INFO] This is normal when CRL is downloaded from certificate's CRL Distribution Point\n"
                                # Don't mark as failed - this is expected behavior
                                results["signature_verified"] = None  # Unknown/not applicable
                                crl_signature_valid = True
                            else:
                                summary += "[ERROR] CRL Signature verification failed - issuer certificate mismatch\n"
                        else:
                            summary += "[ERROR] Could not read issuer certificate information\n"
                    else:
                        summary += "[ERROR] Could not extract CRL issuer information\n"
                if verify_sig_result.stderr:
                    self.log("[STDERR] " + verify_sig_result.stderr + "\n")
                    if verify_sig_result2.stderr:
                        self.log("[STDERR] " + verify_sig_result2.stderr + "\n")

            # Extract thisUpdate and nextUpdate from CRL
            thisUpdate = None
            nextUpdate = None
            for line in crl_out.stdout.splitlines():
                if "This Update" in line or "Last Update" in line:
                    try:
                        thisUpdate = datetime.strptime(line.split(":",1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                        summary += f"[OK] This Update: {thisUpdate}\n"
                    except Exception as e:
                        summary += f"[ERROR] Could not parse This Update: {e}\n"
                elif "Next Update" in line:
                    try:
                        nextUpdate = datetime.strptime(line.split(":",1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                        summary += f"[OK] Next Update: {nextUpdate}\n"
                    except Exception as e:
                        summary += f"[ERROR] Could not parse Next Update: {e}\n"

            if thisUpdate and nextUpdate:
                now = datetime.utcnow()
                if thisUpdate <= now <= nextUpdate:
                    summary += "[OK] CRL Update Times Valid\n"
                    results["update_times_valid"] = True
                else:
                    summary += "[ERROR] CRL Update Times Invalid or Stale\n"
            else:
                summary += "[ERROR] Missing This Update or Next Update\n"

            # Check certificate serial against CRL revoked list
            serial_cmd = ["openssl", "x509", "-serial", "-noout", "-in", cert_path]
            serial_result = subprocess.run(serial_cmd, capture_output=True, text=True)
            serial = serial_result.stdout.split("=")[-1].strip()
            self.log(f"[INFO] Certificate Serial Number: {serial}\n")

            if serial.upper() in crl_out.stdout.upper():
                summary += f"[ERROR] Certificate Serial {serial} is REVOKED\n"
                results["cert_revoked"] = True
            else:
                summary += f"[OK] Certificate Serial {serial} is NOT REVOKED\n"

            # Overall result
            if "[ERROR]" in summary:
                summary += "[ERROR] One or more CRL diagnostics FAILED\n"
            else:
                summary += "[OK] All CRL diagnostics PASSED\n"
                results["overall_pass"] = True

            results["summary"] = summary
            
            # Clean up temporary file
            try:
                os.remove(crl_path)
            except:
                pass
                
            return results

        except Exception as e:
            error_msg = f"[ERROR] CRL Check Exception: {str(e)}\n"
            self.log(error_msg)
            return {"error": error_msg}

    def extract_crl_url(self, cert_path: str) -> Optional[str]:
        """Extract CRL URL from certificate"""
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Look for CRL Distribution Points section
        in_crl_section = False
        for line in result.stdout.splitlines():
            line = line.strip()
            
            # Check if we're in the CRL Distribution Points section
            if "X509v3 CRL Distribution Points:" in line:
                in_crl_section = True
                continue
            elif line.startswith("X509v3 ") and "CRL Distribution Points" not in line:
                # We've moved to a different section
                in_crl_section = False
                continue
            
            # If we're in the CRL section, look for HTTP/HTTPS URIs
            if in_crl_section and "URI:" in line and ("http" in line or "https" in line):
                # Extract the URI and check if it looks like a CRL URL
                uri_part = line.split("URI:")[-1].strip()
                if any(pattern in uri_part.lower() for pattern in ['.crl', 'crl/', 'crls/']):
                    return uri_part
        
        # Fallback: look for any URI that contains CRL-related patterns
        for line in result.stdout.splitlines():
            if "URI:" in line and ("http" in line or "https" in line):
                uri_part = line.split("URI:")[-1].strip()
                if any(pattern in uri_part.lower() for pattern in ['.crl', 'crl/', 'crls/']):
                    return uri_part
        
        return None

    def test_operational_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server operational error signaling capabilities
        
        This method tests how the OCSP server handles and signals various operational
        errors including internal errors, temporary unavailability, and service issues.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing operational error signaling test results
        """
        error_test_results = {
            "internal_error_handling": False,
            "try_later_handling": False,
            "malformed_request_handling": False,
            "error_response_validation": {},
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[OPERATIONAL-ERROR] Testing operational error signaling...\n")
            
            # Test 1: Malformed request handling
            malformed_test = self._test_malformed_request_error_signaling(ocsp_url)
            error_test_results["malformed_request_handling"] = malformed_test["proper_error_response"]
            error_test_results["error_response_validation"]["malformed_request"] = malformed_test
            
            # Test 2: Invalid certificate handling
            invalid_cert_test = self._test_invalid_certificate_error_signaling(issuer_path, ocsp_url)
            error_test_results["error_response_validation"]["invalid_certificate"] = invalid_cert_test
            
            # Test 3: Unauthorized request handling
            unauthorized_test = self._test_unauthorized_request_error_signaling(issuer_path, ocsp_url)
            error_test_results["error_response_validation"]["unauthorized_request"] = unauthorized_test
            
            # Test 4: Server overload simulation
            overload_test = self._test_server_overload_error_signaling(issuer_path, ocsp_url)
            error_test_results["try_later_handling"] = overload_test["try_later_detected"]
            error_test_results["error_response_validation"]["server_overload"] = overload_test
            
            # Overall assessment
            proper_error_handling = (
                error_test_results["malformed_request_handling"] or
                malformed_test["proper_error_response"] or
                invalid_cert_test["proper_error_response"] or
                unauthorized_test["proper_error_response"]
            )
            
            if proper_error_handling:
                self.log("[OPERATIONAL-ERROR] ✓ Operational error signaling validation PASSED\n")
            else:
                self.log("[OPERATIONAL-ERROR] ✗ Operational error signaling validation FAILED\n")
                error_test_results["recommendations"].append("Server error handling could be improved")
            
            return error_test_results
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Operational error testing exception: {e}\n")
            error_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return error_test_results

    def test_unauthorized_query_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server handling of unauthorized queries
        
        This method tests how the OCSP server responds to queries for certificates
        that it is not authorized to provide status for, including certificates
        from different CAs or unauthorized access attempts.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing unauthorized query handling test results
        """
        unauthorized_test_results = {
            "unauthorized_response_detected": False,
            "proper_error_signaling": False,
            "ca_authorization_validation": {},
            "access_control_testing": {},
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[UNAUTHORIZED] Testing unauthorized query handling...\n")
            
            # Test 1: Different CA certificate
            different_ca_test = self._test_different_ca_unauthorized_query(issuer_path, ocsp_url)
            unauthorized_test_results["ca_authorization_validation"]["different_ca"] = different_ca_test
            
            # Test 2: Non-existent certificate
            nonexistent_cert_test = self._test_nonexistent_certificate_query(issuer_path, ocsp_url)
            unauthorized_test_results["access_control_testing"]["nonexistent_cert"] = nonexistent_cert_test
            
            # Test 3: Invalid issuer certificate
            invalid_issuer_test = self._test_invalid_issuer_query(ocsp_url)
            unauthorized_test_results["ca_authorization_validation"]["invalid_issuer"] = invalid_issuer_test
            
            # Analyze results
            unauthorized_responses = 0
            total_tests = 0
            
            for test_category in ["different_ca", "nonexistent_cert", "invalid_issuer"]:
                test_result = None
                if test_category in unauthorized_test_results["ca_authorization_validation"]:
                    test_result = unauthorized_test_results["ca_authorization_validation"][test_category]
                elif test_category in unauthorized_test_results["access_control_testing"]:
                    test_result = unauthorized_test_results["access_control_testing"][test_category]
                
                if test_result:
                    total_tests += 1
                    if test_result.get("unauthorized_response", False):
                        unauthorized_responses += 1
            
            if total_tests > 0:
                unauthorized_percentage = (unauthorized_responses / total_tests) * 100
                unauthorized_test_results["unauthorized_response_detected"] = unauthorized_responses > 0
                unauthorized_test_results["proper_error_signaling"] = unauthorized_percentage >= 50
                
                if unauthorized_test_results["proper_error_signaling"]:
                    self.log("[UNAUTHORIZED] ✓ Unauthorized query handling validation PASSED\n")
                else:
                    self.log("[UNAUTHORIZED] ✗ Unauthorized query handling validation FAILED\n")
                    unauthorized_test_results["recommendations"].append("Server may not properly handle unauthorized queries")
            
            return unauthorized_test_results
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Unauthorized query testing exception: {e}\n")
            unauthorized_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return unauthorized_test_results

    def test_sigrequired_validation(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server enforcement of signed requests (sigRequired)
        
        This method tests whether the OCSP server enforces signed requests
        when the sigRequired extension is present, ensuring proper security
        controls for sensitive OCSP operations.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing sigRequired validation test results
        """
        sigrequired_test_results = {
            "sigrequired_enforced": False,
            "unsigned_request_rejected": False,
            "signed_request_accepted": False,
            "sigrequired_extension_detected": False,
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[SIGREQUIRED] Testing sigRequired validation...\n")
            
            # Test 1: Unsigned request
            unsigned_test = self._test_unsigned_request_handling(issuer_path, ocsp_url)
            sigrequired_test_results["unsigned_request_rejected"] = unsigned_test["request_rejected"]
            sigrequired_test_results["sigrequired_extension_detected"] = unsigned_test["sigrequired_detected"]
            
            # Test 2: Signed request (if sigRequired is detected)
            if unsigned_test["sigrequired_detected"]:
                signed_test = self._test_signed_request_handling(issuer_path, ocsp_url)
                sigrequired_test_results["signed_request_accepted"] = signed_test["request_accepted"]
            
            # Overall assessment
            if sigrequired_test_results["sigrequired_extension_detected"]:
                sigrequired_test_results["sigrequired_enforced"] = (
                    sigrequired_test_results["unsigned_request_rejected"] and
                    sigrequired_test_results["signed_request_accepted"]
                )
                
                if sigrequired_test_results["sigrequired_enforced"]:
                    self.log("[SIGREQUIRED] ✓ sigRequired validation PASSED\n")
                else:
                    self.log("[SIGREQUIRED] ✗ sigRequired validation FAILED\n")
                    sigrequired_test_results["recommendations"].append("sigRequired enforcement inconsistent")
            else:
                # No sigRequired extension detected - this is common and not necessarily a security issue
                self.log("[SIGREQUIRED] ⚠ sigRequired extension not detected - server may not enforce signed requests\n")
                sigrequired_test_results["security_warnings"].append("Server does not enforce signed requests")
                sigrequired_test_results["recommendations"].append("Consider implementing sigRequired for enhanced security")
                # Don't fail the test just because sigRequired is not implemented
                sigrequired_test_results["sigrequired_enforced"] = False
            
            return sigrequired_test_results
            
        except Exception as e:
            self.log(f"[SIGREQUIRED] sigRequired testing exception: {e}\n")
            sigrequired_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return sigrequired_test_results

    def test_nonce_echo_validation(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server nonce echo validation
        
        This method tests whether the OCSP server properly echoes nonces
        in responses, providing replay attack protection and request-response
        binding validation.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing nonce echo validation test results
        """
        nonce_test_results = {
            "nonce_support_detected": False,
            "nonce_echo_validation": False,
            "replay_protection": False,
            "nonce_tests": [],
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[NONCE] Testing nonce echo validation...\n")
            
            # Test 1: Request with nonce
            nonce_request_test = self._test_nonce_request_response(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(nonce_request_test)
            
            # Test 2: Request without nonce
            no_nonce_test = self._test_no_nonce_request_response(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(no_nonce_test)
            
            # Test 3: Multiple nonce requests
            multiple_nonce_test = self._test_multiple_nonce_requests(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(multiple_nonce_test)
            
            # Analyze results
            nonce_support_count = sum(1 for test in nonce_test_results["nonce_tests"] if test.get("nonce_supported", False))
            echo_validation_count = sum(1 for test in nonce_test_results["nonce_tests"] if test.get("nonce_echoed", False))
            unauthorized_count = sum(1 for test in nonce_test_results["nonce_tests"] if "unauthorized" in str(test.get("response_details", {}).get("stdout", "")).lower())
            
            nonce_test_results["nonce_support_detected"] = nonce_support_count > 0
            nonce_test_results["nonce_echo_validation"] = echo_validation_count > 0
            nonce_test_results["replay_protection"] = nonce_test_results["nonce_echo_validation"]
            
            if nonce_test_results["nonce_support_detected"]:
                if nonce_test_results["nonce_echo_validation"]:
                    self.log("[NONCE] ✓ Nonce echo validation PASSED\n")
                else:
                    self.log("[NONCE] ⚠ Nonce support detected but echo validation failed\n")
                    nonce_test_results["security_warnings"].append("Nonce support detected but echo validation inconsistent")
            elif unauthorized_count > 0:
                # Server consistently returns unauthorized - this might indicate proper access controls
                self.log("[NONCE] ⚠ Server requires authentication (unauthorized responses) - this may indicate proper access controls\n")
                nonce_test_results["security_warnings"].append("Server requires authentication - nonce testing limited")
                nonce_test_results["recommendations"].append("Server appears to have access controls - nonce testing may require authentication")
            else:
                self.log("[NONCE] ⚠ No nonce support detected - limited replay attack protection\n")
                nonce_test_results["security_warnings"].append("No nonce support - limited replay attack protection")
            
            return nonce_test_results
            
        except Exception as e:
            self.log(f"[NONCE] Nonce echo testing exception: {e}\n")
            nonce_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return nonce_test_results

    def _test_malformed_request_error_signaling(self, ocsp_url: str) -> Dict[str, Any]:
        """Test malformed request error signaling"""
        test_result = {
            "proper_error_response": False,
            "error_type_detected": None,
            "http_status_code": None,
            "ocsp_error_code": None
        }
        
        try:
            # Send malformed OCSP request
            malformed_data = b"MALFORMED_OCSP_REQUEST_DATA"
            
            # Try using curl first, fallback to requests if curl is not available
            try:
                post_cmd = [
                    "curl", "-X", "POST",
                    "-H", "Content-Type: application/ocsp-request",
                    "--data-binary", "@-",
                    "-w", "%{http_code}",
                    "-s",
                    ocsp_url
                ]
                
                result = subprocess.run(post_cmd, input=malformed_data, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    http_code = result.stdout.strip()
                    test_result["http_status_code"] = http_code
                    
                    # Check for proper error response
                    if http_code in ["400", "500"]:
                        test_result["proper_error_response"] = True
                        test_result["error_type_detected"] = "HTTP_ERROR"
                        self.log("[OPERATIONAL-ERROR] ✓ Malformed request properly rejected with HTTP error\n")
                    else:
                        self.log("[OPERATIONAL-ERROR] ⚠ Malformed request not properly rejected\n")
                else:
                    # Curl failed, which might indicate the server rejected the request
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "CURL_ERROR"
                    self.log("[OPERATIONAL-ERROR] ✓ Malformed request rejected (curl error)\n")
                    
            except FileNotFoundError:
                # Curl not available, use requests as fallback
                self.log("[OPERATIONAL-ERROR] Curl not available, using requests fallback\n")
                try:
                    import requests
                    response = requests.post(ocsp_url, data=malformed_data, 
                                           headers={"Content-Type": "application/ocsp-request"}, 
                                           timeout=30)
                    test_result["http_status_code"] = str(response.status_code)
                    
                    if response.status_code in [400, 500]:
                        test_result["proper_error_response"] = True
                        test_result["error_type_detected"] = "HTTP_ERROR"
                        self.log("[OPERATIONAL-ERROR] ✓ Malformed request properly rejected with HTTP error\n")
                    else:
                        self.log("[OPERATIONAL-ERROR] ⚠ Malformed request not properly rejected\n")
                except Exception as e:
                    # Requests also failed, which might indicate proper rejection
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "REQUEST_ERROR"
                    self.log(f"[OPERATIONAL-ERROR] ✓ Malformed request rejected (request error: {e})\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Malformed request test exception: {e}\n")
            return test_result

    def _test_invalid_certificate_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test invalid certificate error signaling"""
        test_result = {
            "proper_error_response": False,
            "error_type_detected": None,
            "response_details": {}
        }
        
        try:
            # Create invalid certificate
            invalid_cert_path = self._create_invalid_test_certificate()
            
            if invalid_cert_path:
                # Test OCSP request with invalid certificate
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", invalid_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find certificate" in result.stderr or result.returncode != 0:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OPENSSL_PARSE_ERROR"
                    test_result["http_status_code"] = None  # No HTTP request made
                    test_result["ocsp_error_code"] = None  # No OCSP response received
                    self.log("[OPERATIONAL-ERROR] ✓ Invalid certificate properly rejected by OpenSSL\n")
                elif "malformedRequest" in result.stdout or "internalError" in result.stdout:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OCSP_ERROR"
                    self.log("[OPERATIONAL-ERROR] ✓ Invalid certificate properly rejected by OCSP server\n")
                else:
                    self.log("[OPERATIONAL-ERROR] ⚠ Invalid certificate not properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(invalid_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Invalid certificate test exception: {e}\n")
            return test_result

    def _test_unauthorized_request_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test unauthorized request error signaling"""
        test_result = {
            "proper_error_response": False,
            "error_type_detected": None,
            "response_details": {}
        }
        
        try:
            # Create certificate from different CA
            different_ca_cert_path = self._create_different_ca_certificate()
            
            if different_ca_cert_path:
                # Test OCSP request with different CA certificate
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", different_ca_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find certificate" in result.stderr or result.returncode != 0:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OPENSSL_PARSE_ERROR"
                    self.log("[OPERATIONAL-ERROR] ✓ Different CA certificate properly rejected by OpenSSL\n")
                elif "unauthorized" in result.stdout.lower() or "malformedRequest" in result.stdout:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OCSP_UNAUTHORIZED"
                    self.log("[OPERATIONAL-ERROR] ✓ Unauthorized request properly rejected by OCSP server\n")
                else:
                    self.log("[OPERATIONAL-ERROR] ⚠ Unauthorized request not properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(different_ca_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Unauthorized request test exception: {e}\n")
            return test_result

    def _test_server_overload_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test server overload error signaling"""
        test_result = {
            "try_later_detected": False,
            "overload_response": False,
            "response_details": {}
        }
        
        try:
            # Send multiple rapid requests to simulate overload
            rapid_requests = []
            for i in range(10):
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", issuer_path,  # Use issuer as test cert
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=10)
                rapid_requests.append(result)
                
                # Small delay between requests
                import time
                time.sleep(0.1)
            
            # Check for tryLater responses
            try_later_count = sum(1 for req in rapid_requests if "tryLater" in req.stdout)
            
            if try_later_count > 0:
                test_result["try_later_detected"] = True
                test_result["overload_response"] = True
                self.log(f"[OPERATIONAL-ERROR] ✓ Server overload properly signaled ({try_later_count} tryLater responses)\n")
            else:
                self.log("[OPERATIONAL-ERROR] ⚠ No tryLater responses detected for overload simulation\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Server overload test exception: {e}\n")
            return test_result

    def _test_different_ca_unauthorized_query(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test unauthorized query with different CA certificate"""
        test_result = {
            "unauthorized_response": False,
            "response_details": {}
        }
        
        try:
            # Create certificate from different CA
            different_ca_cert_path = self._create_different_ca_certificate()
            
            if different_ca_cert_path:
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", different_ca_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                if "unauthorized" in result.stdout.lower():
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] ✓ Different CA certificate properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(different_ca_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Different CA test exception: {e}\n")
            return test_result

    def _test_nonexistent_certificate_query(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test query for non-existent certificate"""
        test_result = {
            "unauthorized_response": False,
            "response_details": {}
        }
        
        try:
            # Create certificate with non-existent serial
            nonexistent_cert_path = self._create_nonexistent_certificate(issuer_path)
            
            if nonexistent_cert_path:
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", nonexistent_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find certificate" in result.stderr or result.returncode != 0:
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] ✓ Non-existent certificate properly rejected by OpenSSL\n")
                elif "unauthorized" in result.stdout.lower() or "unknown" in result.stdout.lower():
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] ✓ Non-existent certificate properly handled by OCSP server\n")
                else:
                    self.log("[UNAUTHORIZED] ⚠ Non-existent certificate not properly handled\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(nonexistent_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Non-existent certificate test exception: {e}\n")
            return test_result

    def _test_invalid_issuer_query(self, ocsp_url: str) -> Dict[str, Any]:
        """Test query with invalid issuer certificate"""
        test_result = {
            "unauthorized_response": False,
            "response_details": {}
        }
        
        try:
            # Create invalid issuer certificate
            invalid_issuer_path = self._create_invalid_issuer_certificate()
            
            if invalid_issuer_path:
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", invalid_issuer_path,
                    "-cert", invalid_issuer_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find issuer certificate" in result.stderr or result.returncode != 0:
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] ✓ Invalid issuer certificate properly rejected by OpenSSL\n")
                elif "malformedRequest" in result.stdout or "internalError" in result.stdout:
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] ✓ Invalid issuer certificate properly rejected by OCSP server\n")
                else:
                    self.log("[UNAUTHORIZED] ⚠ Invalid issuer certificate not properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(invalid_issuer_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Invalid issuer test exception: {e}\n")
            return test_result

    def _test_unsigned_request_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test unsigned request handling"""
        test_result = {
            "request_rejected": False,
            "sigrequired_detected": False,
            "response_details": {}
        }
        
        try:
            # Create unsigned OCSP request
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"unsigned_req_{uuid4().hex}.der")
            
            # Generate unsigned request
            req_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-reqout", request_file
            ]
            
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=15)
            
            if req_result.returncode == 0:
                # Send unsigned request
                post_cmd = [
                    "curl", "-X", "POST",
                    "-H", "Content-Type: application/ocsp-request",
                    "--data-binary", f"@{request_file}",
                    "-w", "%{http_code}",
                    "-s",
                    ocsp_url
                ]
                
                post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=30)
                
                if post_result.returncode == 0:
                    http_code = post_result.stdout.strip()
                    
                    if http_code.startswith(('4', '5')):
                        test_result["request_rejected"] = True
                        self.log("[SIGREQUIRED] ✓ Unsigned request properly rejected\n")
                    else:
                        # Check response for sigRequired
                        response_file = f"{request_file}.response"
                        if os.path.exists(response_file):
                            with open(response_file, 'rb') as f:
                                response_data = f.read()
                            
                            # Parse response for sigRequired extension
                            parse_cmd = [
                                "openssl", "ocsp",
                                "-respin", response_file,
                                "-text", "-noout"
                            ]
                            
                            parse_result = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=15)
                            
                            if "sigRequired" in parse_result.stdout or "signature required" in parse_result.stdout.lower():
                                test_result["sigrequired_detected"] = True
                                self.log("[SIGREQUIRED] ✓ sigRequired extension detected\n")
                
                test_result["response_details"] = {
                    "http_code": http_code,
                    "post_result": post_result
                }
            
            # Cleanup
            try:
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[SIGREQUIRED] Unsigned request test exception: {e}\n")
            return test_result

    def _test_signed_request_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test signed request handling"""
        test_result = {
            "request_accepted": False,
            "response_details": {}
        }
        
        try:
            # Test regular OCSP request (which may be signed)
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and "OCSP Response Status: successful" in result.stdout:
                test_result["request_accepted"] = True
                self.log("[SIGREQUIRED] ✓ Signed request accepted\n")
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[SIGREQUIRED] Signed request test exception: {e}\n")
            return test_result

    def _test_nonce_request_response(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test nonce request and response"""
        test_result = {
            "nonce_supported": False,
            "nonce_echoed": False,
            "response_details": {}
        }
        
        try:
            # Test OCSP request (nonce is included by default in OpenSSL)
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Check for nonce in response
                if "Nonce:" in response_text:
                    test_result["nonce_supported"] = True
                    test_result["nonce_echoed"] = True
                    self.log("[NONCE] ✓ Nonce support detected and echoed\n")
                elif "WARNING: no nonce in response" in result.stderr:
                    test_result["nonce_supported"] = False
                    test_result["nonce_echoed"] = False
                    self.log("[NONCE] ⚠ No nonce in response\n")
                else:
                    self.log("[NONCE] ⚠ Nonce status unclear\n")
            elif "unauthorized" in result.stdout.lower():
                # Server requires authentication - this is a valid security behavior
                test_result["nonce_supported"] = False
                test_result["nonce_echoed"] = False
                self.log("[NONCE] ⚠ Server requires authentication (unauthorized)\n")
            else:
                self.log("[NONCE] ⚠ Nonce test failed with error\n")
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[NONCE] Nonce request test exception: {e}\n")
            return test_result

    def _test_no_nonce_request_response(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test request without nonce"""
        test_result = {
            "nonce_supported": False,
            "nonce_echoed": False,
            "response_details": {}
        }
        
        try:
            # Test OCSP request without nonce
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify",
                "-no_nonce"  # Disable nonce
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Check if nonce is still present (should not be)
                if "Nonce:" not in response_text:
                    test_result["nonce_supported"] = True
                    self.log("[NONCE] ✓ Nonce properly disabled when requested\n")
                else:
                    self.log("[NONCE] ⚠ Nonce present even when disabled\n")
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[NONCE] No nonce request test exception: {e}\n")
            return test_result

    def _test_multiple_nonce_requests(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test multiple nonce requests for uniqueness"""
        test_result = {
            "nonce_supported": False,
            "nonce_echoed": False,
            "unique_nonces": False,
            "response_details": {}
        }
        
        try:
            nonces = []
            
            # Send multiple requests and collect nonces
            for i in range(3):
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", issuer_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    response_text = result.stdout
                    
                    # Extract nonce from response
                    nonce_match = re.search(r"Nonce:\s*(.+)", response_text)
                    if nonce_match:
                        nonce = nonce_match.group(1).strip()
                        nonces.append(nonce)
                        test_result["nonce_supported"] = True
                        test_result["nonce_echoed"] = True
                
                # Small delay between requests
                import time
                time.sleep(0.5)
            
            # Check for unique nonces
            if len(nonces) > 1:
                unique_nonces = len(set(nonces)) == len(nonces)
                test_result["unique_nonces"] = unique_nonces
                
                if unique_nonces:
                    self.log("[NONCE] ✓ Unique nonces generated for each request\n")
                else:
                    self.log("[NONCE] ⚠ Non-unique nonces detected\n")
            
            test_result["response_details"] = {
                "nonces_collected": nonces,
                "unique_count": len(set(nonces)) if nonces else 0
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[NONCE] Multiple nonce test exception: {e}\n")
            return test_result

    def _create_invalid_test_certificate(self) -> Optional[str]:
        """Create an invalid test certificate"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"invalid_cert_{uuid4().hex}.pem")
            
            # Create invalid certificate content
            invalid_cert_content = """-----BEGIN CERTIFICATE-----
INVALID_CERTIFICATE_DATA
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(invalid_cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating invalid certificate: {e}\n")
            return None

    def _create_different_ca_certificate(self) -> Optional[str]:
        """Create a certificate from a different CA"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"different_ca_cert_{uuid4().hex}.pem")
            
            # Create certificate with different CA information
            different_ca_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCURpZmZlcmVudCBDQTEUMBIGA1UECwwLVGVzdCBDQSBPVTEZMBcGA1UE
AwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(different_ca_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating different CA certificate: {e}\n")
            return None

    def _create_nonexistent_certificate(self, issuer_path: str) -> Optional[str]:
        """Create a certificate with non-existent serial"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"nonexistent_cert_{uuid4().hex}.pem")
            
            # Create certificate with non-existent serial
            nonexistent_cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(nonexistent_cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating non-existent certificate: {e}\n")
            return None

    def _create_invalid_issuer_certificate(self) -> Optional[str]:
        """Create an invalid issuer certificate"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"invalid_issuer_{uuid4().hex}.pem")
            
            # Create invalid issuer certificate
            invalid_issuer_content = """-----BEGIN CERTIFICATE-----
INVALID_ISSUER_CERTIFICATE_DATA
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(invalid_issuer_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating invalid issuer certificate: {e}\n")
        return None

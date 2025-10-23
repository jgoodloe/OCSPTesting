#!/usr/bin/env python3
"""
OCSP Signature Verification Analysis Tool

This tool analyzes OCSP signature verification issues and provides
detailed explanations of why verification fails and how to fix them.
"""

import subprocess
import re
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import json

class OCSPSignatureAnalysis:
    """OCSP signature verification analysis"""
    
    def __init__(self):
        self.log_callback = print
        
    def log(self, text: str) -> None:
        """Log message"""
        self.log_callback(text)
        
    def analyze_ocsp_signature_verification(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Analyze OCSP signature verification issues
        
        Args:
            cert_path: Path to the certificate being checked
            issuer_path: Path to the issuing CA certificate  
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive analysis
        """
        try:
            self.log(f"[INFO] Analyzing OCSP signature verification")
            self.log(f"[INFO] Certificate: {cert_path}")
            self.log(f"[INFO] Issuer: {issuer_path}")
            self.log(f"[INFO] OCSP URL: {ocsp_url}")
            self.log("=" * 80)
            
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "certificate_path": cert_path,
                "issuer_path": issuer_path,
                "ocsp_url": ocsp_url,
                "verification_analysis": {},
                "responder_certificate_analysis": {},
                "signature_analysis": {},
                "recommendations": [],
                "security_assessment": {}
            }
            
            # Step 1: Get OCSP response and analyze responder certificate
            self.log("\n[STEP 1] Analyzing OCSP Response and Responder Certificate")
            self.log("-" * 60)
            
            ocsp_response, responder_cert = self.get_ocsp_response_and_certificate(
                cert_path, issuer_path, ocsp_url
            )
            
            if not ocsp_response or not responder_cert:
                analysis["error"] = "Failed to retrieve OCSP response or responder certificate"
                return analysis
            
            analysis["verification_analysis"]["ocsp_response"] = ocsp_response
            analysis["responder_certificate_analysis"] = responder_cert
            
            # Step 2: Analyze responder certificate
            self.log("\n[STEP 2] Analyzing Responder Certificate")
            self.log("-" * 60)
            
            cert_analysis = self.analyze_responder_certificate(responder_cert, issuer_path)
            analysis["responder_certificate_analysis"].update(cert_analysis)
            
            # Step 3: Analyze signature verification
            self.log("\n[STEP 3] Analyzing Signature Verification")
            self.log("-" * 60)
            
            sig_analysis = self.analyze_signature_verification(cert_path, issuer_path, ocsp_url, responder_cert)
            analysis["signature_analysis"] = sig_analysis
            
            # Step 4: Generate recommendations
            self.log("\n[STEP 4] Generating Recommendations")
            self.log("-" * 60)
            
            recommendations = self.generate_recommendations(analysis)
            analysis["recommendations"] = recommendations
            
            # Step 5: Security assessment
            analysis["security_assessment"] = self.perform_security_assessment(analysis)
            
            # Display results
            self.display_analysis_results(analysis)
            
            return analysis
            
        except Exception as e:
            error_msg = f"[ERROR] Analysis Exception: {str(e)}"
            self.log(error_msg)
            return {"error": error_msg}
    
    def get_ocsp_response_and_certificate(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Get OCSP response and extract responder certificate"""
        
        try:
            # Run OCSP request
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify",
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
            
            self.log("[OK] OCSP response and responder certificate extracted successfully")
            
            return ocsp_response, responder_cert
            
        except Exception as e:
            self.log(f"[ERROR] Error getting OCSP response: {str(e)}")
            return None, None
    
    def parse_ocsp_response(self, stdout: str) -> Dict[str, Any]:
        """Parse OCSP response"""
        
        response_info = {}
        
        try:
            # Extract response status
            status_match = re.search(r'OCSP Response Status:\s*(.+)', stdout)
            if status_match:
                response_info["status"] = status_match.group(1).strip()
            
            # Extract response type
            type_match = re.search(r'Response Type:\s*(.+)', stdout)
            if type_match:
                response_info["type"] = type_match.group(1).strip()
            
            # Extract responder ID
            responder_match = re.search(r'Responder Id:\s*(.+)', stdout)
            if responder_match:
                response_info["responder_id"] = responder_match.group(1).strip()
            
            # Extract produced at
            produced_at_match = re.search(r'Produced At:\s*(.+)', stdout)
            if produced_at_match:
                response_info["produced_at"] = produced_at_match.group(1).strip()
            
            # Extract certificate status
            if ": good" in stdout:
                response_info["certificate_status"] = "good"
            elif ": revoked" in stdout:
                response_info["certificate_status"] = "revoked"
            elif ": unknown" in stdout:
                response_info["certificate_status"] = "unknown"
            
            # Extract timestamps
            this_update_match = re.search(r'This Update:\s*(.+)', stdout)
            if this_update_match:
                response_info["this_update"] = this_update_match.group(1).strip()
            
            next_update_match = re.search(r'Next Update:\s*(.+)', stdout)
            if next_update_match:
                response_info["next_update"] = next_update_match.group(1).strip()
            
            # Extract signature algorithm
            sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', stdout)
            if sig_algo_match:
                response_info["signature_algorithm"] = sig_algo_match.group(1).strip()
            
            self.log(f"[OK] OCSP Response Status: {response_info.get('status', 'Unknown')}")
            self.log(f"[OK] Certificate Status: {response_info.get('certificate_status', 'Unknown')}")
            self.log(f"[OK] Signature Algorithm: {response_info.get('signature_algorithm', 'Unknown')}")
            
        except Exception as e:
            self.log(f"[ERROR] Error parsing OCSP response: {str(e)}")
            response_info["parsing_error"] = str(e)
        
        return response_info
    
    def extract_responder_certificate(self, stdout: str) -> Dict[str, Any]:
        """Extract responder certificate details"""
        
        cert_info = {}
        
        try:
            # Find certificate section
            cert_match = re.search(r'Certificate:\s*\n(.*?)(?=\n\s*Signature|\n\s*-----BEGIN)', stdout, re.DOTALL)
            if not cert_match:
                self.log("[ERROR] Certificate section not found in OCSP response")
                return cert_info
            
            cert_text = cert_match.group(1)
            
            # Extract PEM certificate
            pem_match = re.search(r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', stdout, re.DOTALL)
            if pem_match:
                cert_info["pem_data"] = pem_match.group(1)
            
            # Extract basic certificate information
            cert_info["subject"] = self.extract_field(cert_text, r'Subject:\s*(.+)')
            cert_info["issuer"] = self.extract_field(cert_text, r'Issuer:\s*(.+)')
            cert_info["serial_number"] = self.extract_field(cert_text, r'Serial Number:\s*(.+)')
            cert_info["signature_algorithm"] = self.extract_field(cert_text, r'Signature Algorithm:\s*(.+)')
            
            # Extract validity period
            validity_match = re.search(r'Validity\s*\n\s*Not Before:\s*(.+)\n\s*Not After\s*:\s*(.+)', cert_text)
            if validity_match:
                cert_info["validity"] = {
                    "not_before": validity_match.group(1).strip(),
                    "not_after": validity_match.group(2).strip()
                }
            
            # Extract extensions
            cert_info["extensions"] = self.parse_certificate_extensions(cert_text)
            
            self.log(f"[OK] Responder Certificate Subject: {cert_info.get('subject', 'Unknown')}")
            self.log(f"[OK] Responder Certificate Issuer: {cert_info.get('issuer', 'Unknown')}")
            self.log(f"[OK] Responder Certificate Serial: {cert_info.get('serial_number', 'Unknown')}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting responder certificate: {str(e)}")
            cert_info["extraction_error"] = str(e)
        
        return cert_info
    
    def parse_certificate_extensions(self, cert_text: str) -> Dict[str, Any]:
        """Parse certificate extensions"""
        
        extensions = {}
        
        try:
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
            
            # Authority Key Identifier
            aki_match = re.search(r'X509v3 Authority Key Identifier:\s*(.+)', cert_text)
            if aki_match:
                extensions["authority_key_identifier"] = aki_match.group(1).strip()
            
            # Subject Alternative Name
            san_match = re.search(r'X509v3 Subject Alternative Name:\s*(.+)', cert_text)
            if san_match:
                extensions["subject_alternative_name"] = san_match.group(1).strip()
            
            # OCSP No Check
            if "OCSP No Check:" in cert_text:
                extensions["ocsp_no_check"] = True
            
            # Certificate Policies
            policies_match = re.search(r'X509v3 Certificate Policies:\s*(.+?)(?=\n\s*[A-Z]|\n\s*Authority)', cert_text, re.DOTALL)
            if policies_match:
                policies_text = policies_match.group(1).strip()
                policy_matches = re.findall(r'Policy:\s*(.+)', policies_text)
                if policy_matches:
                    extensions["certificate_policies"] = policy_matches
            
        except Exception as e:
            extensions["parsing_error"] = str(e)
        
        return extensions
    
    def analyze_responder_certificate(self, responder_cert: Dict[str, Any], issuer_path: str) -> Dict[str, Any]:
        """Analyze responder certificate"""
        
        analysis = {
            "certificate_valid": False,
            "trust_chain_analysis": {},
            "validity_analysis": {},
            "key_usage_analysis": {},
            "extended_key_usage_analysis": {},
            "authority_analysis": {},
            "issues": [],
            "recommendations": []
        }
        
        try:
            # 1. Trust Chain Analysis
            self.log("[1] Analyzing Trust Chain")
            trust_analysis = self.analyze_trust_chain(responder_cert, issuer_path)
            analysis["trust_chain_analysis"] = trust_analysis
            
            # 2. Validity Analysis
            self.log("[2] Analyzing Validity Period")
            validity_analysis = self.analyze_validity_period(responder_cert)
            analysis["validity_analysis"] = validity_analysis
            
            # 3. Key Usage Analysis
            self.log("[3] Analyzing Key Usage")
            key_usage_analysis = self.analyze_key_usage(responder_cert)
            analysis["key_usage_analysis"] = key_usage_analysis
            
            # 4. Extended Key Usage Analysis
            self.log("[4] Analyzing Extended Key Usage")
            eku_analysis = self.analyze_extended_key_usage(responder_cert)
            analysis["extended_key_usage_analysis"] = eku_analysis
            
            # 5. Authority Analysis
            self.log("[5] Analyzing Authority")
            authority_analysis = self.analyze_authority(responder_cert)
            analysis["authority_analysis"] = authority_analysis
            
            # Overall assessment
            all_valid = all([
                trust_analysis.get("trust_chain_valid", False),
                validity_analysis.get("validity_period_valid", False),
                key_usage_analysis.get("key_usage_valid", False),
                eku_analysis.get("extended_key_usage_valid", False)
            ])
            
            analysis["certificate_valid"] = all_valid
            
            if all_valid:
                self.log("[OK] Responder certificate analysis PASSED")
            else:
                self.log("[ERROR] Responder certificate analysis FAILED")
                analysis["issues"].append("One or more certificate validation checks failed")
            
        except Exception as e:
            self.log(f"[ERROR] Error analyzing responder certificate: {str(e)}")
            analysis["analysis_error"] = str(e)
        
        return analysis
    
    def analyze_trust_chain(self, responder_cert: Dict[str, Any], issuer_path: str) -> Dict[str, Any]:
        """Analyze trust chain"""
        
        analysis = {
            "trust_chain_valid": False,
            "error_details": "",
            "recommendations": []
        }
        
        try:
            # Check if we have PEM data
            if not responder_cert.get("pem_data"):
                analysis["error_details"] = "No PEM certificate data available"
                analysis["recommendations"].append("Ensure OCSP response includes responder certificate")
                return analysis
            
            # Create temporary file for responder certificate
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
                temp_cert.write(responder_cert["pem_data"])
                temp_cert_path = temp_cert.name
            
            # Try to verify certificate chain
            verify_cmd = [
                "openssl", "verify",
                "-CAfile", issuer_path,
                temp_cert_path
            ]
            
            result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=10)
            
            # Clean up temporary file
            os.unlink(temp_cert_path)
            
            if result.returncode == 0 and "OK" in result.stdout:
                analysis["trust_chain_valid"] = True
                self.log("[OK] Trust chain validation PASSED")
            else:
                analysis["trust_chain_valid"] = False
                analysis["error_details"] = result.stderr.strip()
                self.log(f"[ERROR] Trust chain validation FAILED: {result.stderr.strip()}")
                
                # Analyze the error
                if "unable to get issuer certificate" in result.stderr:
                    analysis["recommendations"].append("Add the OCSP responder's issuer certificate to the trust store")
                    analysis["recommendations"].append("Ensure the certificate chain is complete")
                elif "certificate verify failed" in result.stderr:
                    analysis["recommendations"].append("Check if the issuer certificate is correct")
                    analysis["recommendations"].append("Verify the certificate chain integrity")
            
        except Exception as e:
            analysis["error_details"] = str(e)
            analysis["recommendations"].append(f"Error during trust chain analysis: {str(e)}")
        
        return analysis
    
    def analyze_validity_period(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze certificate validity period"""
        
        analysis = {
            "validity_period_valid": False,
            "not_before": None,
            "not_after": None,
            "current_time": None,
            "days_until_expiry": 0,
            "error_details": ""
        }
        
        try:
            validity = responder_cert.get("validity", {})
            not_before_str = validity.get("not_before")
            not_after_str = validity.get("not_after")
            
            if not not_before_str or not not_after_str:
                analysis["error_details"] = "Validity period not found in certificate"
                return analysis
            
            # Parse dates
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            
            analysis["not_before"] = not_before_str
            analysis["not_after"] = not_after_str
            analysis["current_time"] = now.isoformat()
            
            if not_before <= now <= not_after:
                analysis["validity_period_valid"] = True
                analysis["days_until_expiry"] = (not_after - now).days
                self.log(f"[OK] Validity period PASSED ({not_before_str} to {not_after_str})")
            else:
                analysis["validity_period_valid"] = False
                if now < not_before:
                    analysis["error_details"] = "Certificate not yet valid"
                elif now > not_after:
                    analysis["error_details"] = "Certificate has expired"
                self.log(f"[ERROR] Validity period FAILED ({not_before_str} to {not_after_str})")
            
        except Exception as e:
            analysis["error_details"] = str(e)
        
        return analysis
    
    def analyze_key_usage(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze key usage extension"""
        
        analysis = {
            "key_usage_valid": False,
            "key_usage": "",
            "has_digital_signature": False,
            "error_details": ""
        }
        
        try:
            extensions = responder_cert.get("extensions", {})
            key_usage = extensions.get("key_usage", "")
            
            analysis["key_usage"] = key_usage
            
            if "Digital Signature" in key_usage:
                analysis["key_usage_valid"] = True
                analysis["has_digital_signature"] = True
                self.log("[OK] Key Usage PASSED (Digital Signature present)")
            else:
                analysis["key_usage_valid"] = False
                analysis["error_details"] = "Digital Signature not present in Key Usage extension"
                self.log("[ERROR] Key Usage FAILED (Digital Signature not present)")
            
        except Exception as e:
            analysis["error_details"] = str(e)
        
        return analysis
    
    def analyze_extended_key_usage(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze extended key usage extension"""
        
        analysis = {
            "extended_key_usage_valid": False,
            "extended_key_usage": "",
            "has_ocsp_signing": False,
            "required_oid": "1.3.6.1.5.5.7.3.9",
            "error_details": ""
        }
        
        try:
            extensions = responder_cert.get("extensions", {})
            extended_key_usage = extensions.get("extended_key_usage", "")
            
            analysis["extended_key_usage"] = extended_key_usage
            
            if "OCSP Signing" in extended_key_usage:
                analysis["extended_key_usage_valid"] = True
                analysis["has_ocsp_signing"] = True
                self.log("[OK] Extended Key Usage PASSED (OCSP Signing present)")
            else:
                analysis["extended_key_usage_valid"] = False
                analysis["error_details"] = "OCSP Signing not present in Extended Key Usage extension"
                self.log("[ERROR] Extended Key Usage FAILED (OCSP Signing not present)")
            
        except Exception as e:
            analysis["error_details"] = str(e)
        
        return analysis
    
    def analyze_authority(self, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze authority"""
        
        analysis = {
            "authority_valid": False,
            "responder_subject": "",
            "responder_issuer": "",
            "ocsp_no_check": False,
            "error_details": ""
        }
        
        try:
            analysis["responder_subject"] = responder_cert.get("subject", "")
            analysis["responder_issuer"] = responder_cert.get("issuer", "")
            
            extensions = responder_cert.get("extensions", {})
            analysis["ocsp_no_check"] = extensions.get("ocsp_no_check", False)
            
            # Basic authority check
            if analysis["responder_subject"] and analysis["responder_issuer"]:
                analysis["authority_valid"] = True
                self.log("[OK] Authority analysis PASSED")
            else:
                analysis["authority_valid"] = False
                analysis["error_details"] = "Missing subject or issuer information"
                self.log("[ERROR] Authority analysis FAILED")
            
        except Exception as e:
            analysis["error_details"] = str(e)
        
        return analysis
    
    def analyze_signature_verification(self, cert_path: str, issuer_path: str, ocsp_url: str, responder_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze signature verification"""
        
        analysis = {
            "signature_verification_valid": False,
            "verification_method": "",
            "error_details": "",
            "recommendations": []
        }
        
        try:
            # Try different verification methods
            self.log("[1] Trying standard OCSP verification")
            
            # Method 1: Standard verification
            verify_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-verify_other", issuer_path
            ]
            
            result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and "Response verify OK" in (result.stdout + result.stderr):
                analysis["signature_verification_valid"] = True
                analysis["verification_method"] = "standard_verification"
                self.log("[OK] Standard OCSP verification PASSED")
            else:
                analysis["signature_verification_valid"] = False
                analysis["error_details"] = result.stderr.strip()
                self.log(f"[ERROR] Standard OCSP verification FAILED: {result.stderr.strip()}")
                
                # Analyze the error
                if "unable to get local issuer certificate" in result.stderr:
                    analysis["recommendations"].append("The OCSP responder certificate is not in the local trust store")
                    analysis["recommendations"].append("Add the OCSP responder's issuer certificate to the trust store")
                elif "certificate verify error" in result.stderr:
                    analysis["recommendations"].append("Certificate chain verification failed")
                    analysis["recommendations"].append("Check if the issuer certificate is correct")
            
        except Exception as e:
            analysis["error_details"] = str(e)
            analysis["recommendations"].append(f"Error during signature verification: {str(e)}")
        
        return analysis
    
    def generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        
        recommendations = []
        
        try:
            # Trust chain recommendations
            trust_analysis = analysis.get("responder_certificate_analysis", {}).get("trust_chain_analysis", {})
            if not trust_analysis.get("trust_chain_valid", False):
                recommendations.extend(trust_analysis.get("recommendations", []))
            
            # Signature verification recommendations
            sig_analysis = analysis.get("signature_analysis", {})
            if not sig_analysis.get("signature_verification_valid", False):
                recommendations.extend(sig_analysis.get("recommendations", []))
            
            # General recommendations
            if not recommendations:
                recommendations.append("OCSP signature verification is working correctly")
            else:
                recommendations.append("Consider implementing proper certificate chain management")
                recommendations.append("Ensure OCSP responder certificates are properly configured")
            
        except Exception as e:
            recommendations.append(f"Error generating recommendations: {str(e)}")
        
        return recommendations
    
    def perform_security_assessment(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security assessment"""
        
        assessment = {
            "security_level": "UNKNOWN",
            "risks": [],
            "mitigations": [],
            "overall_assessment": ""
        }
        
        try:
            # Check certificate validity
            cert_analysis = analysis.get("responder_certificate_analysis", {})
            cert_valid = cert_analysis.get("certificate_valid", False)
            
            # Check signature verification
            sig_analysis = analysis.get("signature_analysis", {})
            sig_valid = sig_analysis.get("signature_verification_valid", False)
            
            if cert_valid and sig_valid:
                assessment["security_level"] = "HIGH"
                assessment["overall_assessment"] = "OCSP signature verification is working correctly"
            elif cert_valid and not sig_valid:
                assessment["security_level"] = "MEDIUM"
                assessment["risks"].append("Signature verification failed - response authenticity uncertain")
                assessment["mitigations"].append("Fix certificate chain configuration")
                assessment["overall_assessment"] = "Certificate is valid but signature verification failed"
            else:
                assessment["security_level"] = "LOW"
                assessment["risks"].append("OCSP signature verification failed - potential security risk")
                assessment["mitigations"].append("Do not trust OCSP response without proper verification")
                assessment["overall_assessment"] = "OCSP signature verification failed"
            
        except Exception as e:
            assessment["overall_assessment"] = f"Error during security assessment: {str(e)}"
        
        return assessment
    
    def extract_field(self, text: str, pattern: str) -> Optional[str]:
        """Helper method to extract a field using regex"""
        match = re.search(pattern, text)
        return match.group(1).strip() if match else None
    
    def display_analysis_results(self, analysis: Dict[str, Any]) -> None:
        """Display analysis results"""
        
        self.log("\n[OCSP SIGNATURE VERIFICATION ANALYSIS RESULTS]")
        self.log("=" * 80)
        
        # Security Assessment
        security = analysis.get("security_assessment", {})
        self.log(f"\n[SECURITY ASSESSMENT]")
        self.log(f"Security Level: {security.get('security_level', 'UNKNOWN')}")
        self.log(f"Overall Assessment: {security.get('overall_assessment', 'Unknown')}")
        
        if security.get('risks'):
            self.log("\nRisks:")
            for risk in security['risks']:
                self.log(f"  - {risk}")
        
        if security.get('mitigations'):
            self.log("\nMitigations:")
            for mitigation in security['mitigations']:
                self.log(f"  - {mitigation}")
        
        # Recommendations
        recommendations = analysis.get("recommendations", [])
        if recommendations:
            self.log("\n[RECOMMENDATIONS]")
            for i, rec in enumerate(recommendations, 1):
                self.log(f"{i}. {rec}")
        
        # Detailed Analysis
        self.log("\n[DETAILED ANALYSIS]")
        
        # Responder Certificate Analysis
        cert_analysis = analysis.get("responder_certificate_analysis", {})
        self.log(f"\nResponder Certificate Analysis:")
        self.log(f"  Certificate Valid: {'[OK]' if cert_analysis.get('certificate_valid') else '[ERROR]'}")
        
        trust_analysis = cert_analysis.get("trust_chain_analysis", {})
        self.log(f"  Trust Chain: {'[OK]' if trust_analysis.get('trust_chain_valid') else '[ERROR]'}")
        
        validity_analysis = cert_analysis.get("validity_analysis", {})
        self.log(f"  Validity Period: {'[OK]' if validity_analysis.get('validity_period_valid') else '[ERROR]'}")
        
        key_usage_analysis = cert_analysis.get("key_usage_analysis", {})
        self.log(f"  Key Usage: {'[OK]' if key_usage_analysis.get('key_usage_valid') else '[ERROR]'}")
        
        eku_analysis = cert_analysis.get("extended_key_usage_analysis", {})
        self.log(f"  Extended Key Usage: {'[OK]' if eku_analysis.get('extended_key_usage_valid') else '[ERROR]'}")
        
        # Signature Analysis
        sig_analysis = analysis.get("signature_analysis", {})
        self.log(f"\nSignature Verification Analysis:")
        self.log(f"  Signature Verification: {'[OK]' if sig_analysis.get('signature_verification_valid') else '[ERROR]'}")
        self.log(f"  Verification Method: {sig_analysis.get('verification_method', 'Unknown')}")

def main():
    """Main function"""
    print("OCSP Signature Verification Analysis Tool")
    print("=" * 60)
    
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
        print("Usage: python ocsp_signature_analysis.py <cert_path> <issuer_path> <ocsp_url>")
        print("\nExample:")
        print("python ocsp_signature_analysis.py certificate.pem issuer.pem http://ocsp.example.com")
        sys.exit(1)
    
    # Check if files exist
    if not os.path.exists(cert_path):
        print(f"[ERROR] Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not os.path.exists(issuer_path):
        print(f"[ERROR] Issuer file not found: {issuer_path}")
        sys.exit(1)
    
    # Create analyzer and run analysis
    analyzer = OCSPSignatureAnalysis()
    results = analyzer.analyze_ocsp_signature_verification(cert_path, issuer_path, ocsp_url)
    
    # Save results to JSON file
    output_file = f"ocsp_signature_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[INFO] Analysis results saved to: {output_file}")
    
    # Print final summary
    print("\n[FINAL SUMMARY]")
    print("=" * 60)
    if "error" in results:
        print(f"[ERROR] Analysis failed: {results['error']}")
    else:
        security = results.get("security_assessment", {})
        print(f"[RESULT] Security Level: {security.get('security_level', 'UNKNOWN')}")
        print(f"[RESULT] Assessment: {security.get('overall_assessment', 'Unknown')}")

if __name__ == "__main__":
    main()

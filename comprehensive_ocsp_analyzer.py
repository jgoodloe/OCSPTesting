#!/usr/bin/env python3
"""
Comprehensive OCSP Signer Analysis Script

This script provides detailed analysis of OCSP responses and extracts
comprehensive signer information including responder certificate details.
"""

import subprocess
import re
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
import json

class ComprehensiveOCSPAnalyzer:
    """Comprehensive OCSP response analyzer"""
    
    def __init__(self):
        self.log_callback = print
        
    def log(self, text: str) -> None:
        """Log message"""
        self.log_callback(text)
        
    def analyze_ocsp_response(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Comprehensive OCSP response analysis
        
        Args:
            cert_path: Path to the certificate being checked
            issuer_path: Path to the issuing CA certificate  
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive OCSP analysis
        """
        try:
            self.log(f"[INFO] Analyzing OCSP response for certificate: {cert_path}")
            self.log(f"[INFO] Using issuer: {issuer_path}")
            self.log(f"[INFO] OCSP URL: {ocsp_url}")
            self.log("=" * 80)
            
            # Run OCSP check without verification to get raw response
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify",  # Skip signature verification
                "-text"
            ]
            
            self.log(f"[CMD] {' '.join(ocsp_cmd)}")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            # Log the raw output
            self.log("\n[OCSP RESPONSE ANALYSIS]")
            self.log("=" * 80)
            
            # Parse the response
            analysis = self.parse_ocsp_response(result.stdout, result.stderr)
            
            # Add metadata
            analysis["metadata"] = {
                "certificate_path": cert_path,
                "issuer_path": issuer_path,
                "ocsp_url": ocsp_url,
                "timestamp": datetime.now().isoformat(),
                "return_code": result.returncode,
                "raw_stdout": result.stdout,
                "raw_stderr": result.stderr
            }
            
            # Display analysis results
            self.display_analysis_results(analysis)
            
            return analysis
            
        except Exception as e:
            error_msg = f"[ERROR] OCSP Analysis Exception: {str(e)}"
            self.log(error_msg)
            return {"error": error_msg}
    
    def parse_ocsp_response(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse OCSP response comprehensively"""
        analysis = {
            "request_info": {},
            "response_info": {},
            "certificate_statuses": [],
            "responder_certificate": {},
            "signature_info": {},
            "security_analysis": {},
            "timestamps": {},
            "extensions": {}
        }
        
        try:
            # Parse request information
            analysis["request_info"] = self.parse_request_info(stdout)
            
            # Parse response information
            analysis["response_info"] = self.parse_response_info(stdout)
            
            # Parse certificate statuses
            analysis["certificate_statuses"] = self.parse_certificate_statuses(stdout)
            
            # Parse responder certificate
            analysis["responder_certificate"] = self.parse_responder_certificate(stdout)
            
            # Parse signature information
            analysis["signature_info"] = self.parse_signature_info(stdout, stderr)
            
            # Perform security analysis
            analysis["security_analysis"] = self.perform_security_analysis(stdout, stderr)
            
            # Parse timestamps
            analysis["timestamps"] = self.parse_timestamps(stdout)
            
            # Parse extensions
            analysis["extensions"] = self.parse_extensions(stdout)
            
        except Exception as e:
            self.log(f"[ERROR] Error parsing OCSP response: {str(e)}")
            analysis["parsing_error"] = str(e)
        
        return analysis
    
    def parse_request_info(self, stdout: str) -> Dict[str, Any]:
        """Parse OCSP request information"""
        request_info = {}
        
        try:
            # Extract request data
            request_match = re.search(r'OCSP Request Data:(.*?)(?=OCSP Response Data:)', stdout, re.DOTALL)
            if request_match:
                request_text = request_match.group(1)
                
                # Extract version
                version_match = re.search(r'Version:\s*(\d+)', request_text)
                if version_match:
                    request_info["version"] = version_match.group(1)
                
                # Extract certificate ID
                cert_id_match = re.search(r'Certificate ID:(.*?)(?=Request Extensions:)', request_text, re.DOTALL)
                if cert_id_match:
                    cert_id_text = cert_id_match.group(1)
                    
                    # Hash algorithm
                    hash_algo_match = re.search(r'Hash Algorithm:\s*(.+)', cert_id_text)
                    if hash_algo_match:
                        request_info["hash_algorithm"] = hash_algo_match.group(1).strip()
                    
                    # Issuer name hash
                    issuer_name_hash_match = re.search(r'Issuer Name Hash:\s*(.+)', cert_id_text)
                    if issuer_name_hash_match:
                        request_info["issuer_name_hash"] = issuer_name_hash_match.group(1).strip()
                    
                    # Issuer key hash
                    issuer_key_hash_match = re.search(r'Issuer Key Hash:\s*(.+)', cert_id_text)
                    if issuer_key_hash_match:
                        request_info["issuer_key_hash"] = issuer_key_hash_match.group(1).strip()
                    
                    # Serial number
                    serial_match = re.search(r'Serial Number:\s*(.+)', cert_id_text)
                    if serial_match:
                        request_info["serial_number"] = serial_match.group(1).strip()
                
                # Extract nonce
                nonce_match = re.search(r'OCSP Nonce:\s*(.+)', request_text)
                if nonce_match:
                    request_info["nonce"] = nonce_match.group(1).strip()
                    request_info["nonce_present"] = True
                else:
                    request_info["nonce_present"] = False
            
        except Exception as e:
            request_info["parsing_error"] = str(e)
        
        return request_info
    
    def parse_response_info(self, stdout: str) -> Dict[str, Any]:
        """Parse OCSP response information"""
        response_info = {}
        
        try:
            # Extract response data
            response_match = re.search(r'OCSP Response Data:(.*?)(?=Certificate:)', stdout, re.DOTALL)
            if response_match:
                response_text = response_match.group(1)
                
                # Response status
                status_match = re.search(r'OCSP Response Status:\s*(.+)', response_text)
                if status_match:
                    response_info["status"] = status_match.group(1).strip()
                
                # Response type
                type_match = re.search(r'Response Type:\s*(.+)', response_text)
                if type_match:
                    response_info["type"] = type_match.group(1).strip()
                
                # Version
                version_match = re.search(r'Version:\s*(\d+)', response_text)
                if version_match:
                    response_info["version"] = version_match.group(1)
                
                # Responder ID
                responder_match = re.search(r'Responder Id:\s*(.+)', response_text)
                if responder_match:
                    response_info["responder_id"] = responder_match.group(1).strip()
                
                # Produced At
                produced_at_match = re.search(r'Produced At:\s*(.+)', response_text)
                if produced_at_match:
                    response_info["produced_at"] = produced_at_match.group(1).strip()
            
        except Exception as e:
            response_info["parsing_error"] = str(e)
        
        return response_info
    
    def parse_certificate_statuses(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse certificate status information"""
        statuses = []
        
        try:
            # Find all certificate status entries
            cert_status_pattern = r'Certificate ID:(.*?)(?=Certificate ID:|Signature Algorithm:)'
            cert_matches = re.findall(cert_status_pattern, stdout, re.DOTALL)
            
            for cert_text in cert_matches:
                status_info = {}
                
                # Hash algorithm
                hash_algo_match = re.search(r'Hash Algorithm:\s*(.+)', cert_text)
                if hash_algo_match:
                    status_info["hash_algorithm"] = hash_algo_match.group(1).strip()
                
                # Issuer name hash
                issuer_name_hash_match = re.search(r'Issuer Name Hash:\s*(.+)', cert_text)
                if issuer_name_hash_match:
                    status_info["issuer_name_hash"] = issuer_name_hash_match.group(1).strip()
                
                # Issuer key hash
                issuer_key_hash_match = re.search(r'Issuer Key Hash:\s*(.+)', cert_text)
                if issuer_key_hash_match:
                    status_info["issuer_key_hash"] = issuer_key_hash_match.group(1).strip()
                
                # Serial number
                serial_match = re.search(r'Serial Number:\s*(.+)', cert_text)
                if serial_match:
                    status_info["serial_number"] = serial_match.group(1).strip()
                
                # Certificate status
                cert_status_match = re.search(r'Cert Status:\s*(.+)', cert_text)
                if cert_status_match:
                    status_info["status"] = cert_status_match.group(1).strip()
                
                # Revocation time
                rev_time_match = re.search(r'Revocation Time:\s*(.+)', cert_text)
                if rev_time_match:
                    status_info["revocation_time"] = rev_time_match.group(1).strip()
                
                # Revocation reason
                rev_reason_match = re.search(r'Revocation Reason:\s*(.+)', cert_text)
                if rev_reason_match:
                    status_info["revocation_reason"] = rev_reason_match.group(1).strip()
                
                # This Update
                this_update_match = re.search(r'This Update:\s*(.+)', cert_text)
                if this_update_match:
                    status_info["this_update"] = this_update_match.group(1).strip()
                
                # Next Update
                next_update_match = re.search(r'Next Update:\s*(.+)', cert_text)
                if next_update_match:
                    status_info["next_update"] = next_update_match.group(1).strip()
                
                statuses.append(status_info)
            
        except Exception as e:
            self.log(f"[ERROR] Error parsing certificate statuses: {str(e)}")
        
        return statuses
    
    def parse_responder_certificate(self, stdout: str) -> Dict[str, Any]:
        """Parse responder certificate details"""
        cert_info = {}
        
        try:
            # Find certificate section
            cert_match = re.search(r'Certificate:\s*\n(.*?)(?=\n\s*Signature|\n\s*-----BEGIN)', stdout, re.DOTALL)
            if cert_match:
                cert_text = cert_match.group(1)
                
                # Basic certificate info
                cert_info["version"] = self.extract_field(cert_text, r'Version:\s*(\d+)')
                cert_info["serial_number"] = self.extract_field(cert_text, r'Serial Number:\s*(.+)')
                cert_info["signature_algorithm"] = self.extract_field(cert_text, r'Signature Algorithm:\s*(.+)')
                cert_info["issuer"] = self.extract_field(cert_text, r'Issuer:\s*(.+)')
                cert_info["subject"] = self.extract_field(cert_text, r'Subject:\s*(.+)')
                
                # Validity period
                validity_match = re.search(r'Validity\s*\n\s*Not Before:\s*(.+)\n\s*Not After\s*:\s*(.+)', cert_text)
                if validity_match:
                    cert_info["validity"] = {
                        "not_before": validity_match.group(1).strip(),
                        "not_after": validity_match.group(2).strip()
                    }
                
                # Public key info
                pubkey_match = re.search(r'Public Key Algorithm:\s*(.+)', cert_text)
                if pubkey_match:
                    cert_info["public_key_algorithm"] = pubkey_match.group(1).strip()
                
                # Extensions
                cert_info["extensions"] = self.parse_certificate_extensions(cert_text)
            
        except Exception as e:
            cert_info["parsing_error"] = str(e)
        
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
            
            # Subject Alternative Name
            san_match = re.search(r'X509v3 Subject Alternative Name:\s*(.+)', cert_text)
            if san_match:
                extensions["subject_alternative_name"] = san_match.group(1).strip()
            
            # Authority Key Identifier
            aki_match = re.search(r'X509v3 Authority Key Identifier:\s*(.+)', cert_text)
            if aki_match:
                extensions["authority_key_identifier"] = aki_match.group(1).strip()
            
            # Subject Key Identifier
            ski_match = re.search(r'X509v3 Subject Key Identifier:\s*(.+)', cert_text)
            if ski_match:
                extensions["subject_key_identifier"] = ski_match.group(1).strip()
            
            # Certificate Policies
            policies_match = re.search(r'X509v3 Certificate Policies:\s*(.+?)(?=\n\s*[A-Z]|\n\s*Authority)', cert_text, re.DOTALL)
            if policies_match:
                policies_text = policies_match.group(1).strip()
                policy_matches = re.findall(r'Policy:\s*(.+)', policies_text)
                if policy_matches:
                    extensions["certificate_policies"] = policy_matches
            
            # Authority Information Access
            aia_match = re.search(r'Authority Information Access:\s*(.+?)(?=\n\s*[A-Z]|\n\s*X509v3)', cert_text, re.DOTALL)
            if aia_match:
                aia_text = aia_match.group(1).strip()
                extensions["authority_information_access"] = aia_text
            
            # OCSP No Check
            if "OCSP No Check:" in cert_text:
                extensions["ocsp_no_check"] = True
            
        except Exception as e:
            extensions["parsing_error"] = str(e)
        
        return extensions
    
    def parse_signature_info(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse signature information"""
        sig_info = {}
        
        try:
            # Signature algorithm
            sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', stdout)
            if sig_algo_match:
                sig_info["algorithm"] = sig_algo_match.group(1).strip()
            
            # Signature value
            sig_value_match = re.search(r'Signature Value:\s*([0-9a-fA-F:\s]+)', stdout)
            if sig_value_match:
                signature_value = sig_value_match.group(1).strip()
                signature_value = re.sub(r'[\s:]', '', signature_value)
                sig_info["value"] = signature_value
            
            # Verification status
            if "Response verify OK" in stdout or "Response verify OK" in stderr:
                sig_info["verified"] = True
                sig_info["verification_method"] = "openssl_builtin"
            elif "Response Verify Failure" in stderr:
                sig_info["verified"] = False
                sig_info["verification_method"] = "failed"
            else:
                sig_info["verified"] = False
                sig_info["verification_method"] = "unknown"
            
            # Verification errors
            sig_info["errors"] = []
            if stderr:
                error_lines = stderr.split('\n')
                for line in error_lines:
                    if 'error:' in line.lower() or 'verify error:' in line.lower():
                        sig_info["errors"].append(line.strip())
            
        except Exception as e:
            sig_info["parsing_error"] = str(e)
        
        return sig_info
    
    def perform_security_analysis(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Perform security analysis of the OCSP response"""
        security = {
            "nonce_support": None,
            "signature_verification": None,
            "response_freshness": None,
            "certificate_status_validation": None,
            "security_warnings": [],
            "security_recommendations": []
        }
        
        try:
            # Nonce support analysis
            if "WARNING: no nonce in response" in stderr:
                security["nonce_support"] = False
                security["security_warnings"].append("No nonce in response - potential replay attack vulnerability")
            elif "OCSP Nonce:" in stdout:
                security["nonce_support"] = True
            else:
                security["nonce_support"] = None
            
            # Signature verification analysis
            if "Response verify OK" in stdout or "Response verify OK" in stderr:
                security["signature_verification"] = True
            elif "Response Verify Failure" in stderr:
                security["signature_verification"] = False
                security["security_warnings"].append("OCSP response signature verification failed")
                security["security_recommendations"].append("Verify certificate chain and OCSP responder certificate")
            else:
                security["signature_verification"] = None
            
            # Response freshness analysis
            this_update_match = re.search(r'This Update:\s*(.+)', stdout)
            next_update_match = re.search(r'Next Update:\s*(.+)', stdout)
            if this_update_match and next_update_match:
                try:
                    from datetime import datetime
                    this_update = datetime.strptime(this_update_match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                    next_update = datetime.strptime(next_update_match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    
                    if this_update <= now <= next_update:
                        security["response_freshness"] = True
                    else:
                        security["response_freshness"] = False
                        security["security_warnings"].append("OCSP response is outside validity period")
                except:
                    security["response_freshness"] = None
            
            # Certificate status validation
            if ": good" in stdout:
                security["certificate_status_validation"] = "good"
            elif ": revoked" in stdout:
                security["certificate_status_validation"] = "revoked"
                security["security_warnings"].append("Certificate is revoked")
            elif ": unknown" in stdout:
                security["certificate_status_validation"] = "unknown"
                security["security_warnings"].append("Certificate status is unknown")
            else:
                security["certificate_status_validation"] = None
            
        except Exception as e:
            security["analysis_error"] = str(e)
        
        return security
    
    def parse_timestamps(self, stdout: str) -> Dict[str, Any]:
        """Parse timestamp information"""
        timestamps = {}
        
        try:
            # This Update
            this_update_match = re.search(r'This Update:\s*(.+)', stdout)
            if this_update_match:
                timestamps["this_update"] = this_update_match.group(1).strip()
            
            # Next Update
            next_update_match = re.search(r'Next Update:\s*(.+)', stdout)
            if next_update_match:
                timestamps["next_update"] = next_update_match.group(1).strip()
            
            # Produced At
            produced_at_match = re.search(r'Produced At:\s*(.+)', stdout)
            if produced_at_match:
                timestamps["produced_at"] = produced_at_match.group(1).strip()
            
        except Exception as e:
            timestamps["parsing_error"] = str(e)
        
        return timestamps
    
    def parse_extensions(self, stdout: str) -> Dict[str, Any]:
        """Parse OCSP extensions"""
        extensions = {}
        
        try:
            # Look for extensions in the response
            # This is a placeholder for future extension parsing
            extensions["parsed"] = False
            extensions["note"] = "Extension parsing not implemented yet"
            
        except Exception as e:
            extensions["parsing_error"] = str(e)
        
        return extensions
    
    def extract_field(self, text: str, pattern: str) -> Optional[str]:
        """Helper method to extract a field using regex"""
        match = re.search(pattern, text)
        return match.group(1).strip() if match else None
    
    def display_analysis_results(self, analysis: Dict[str, Any]) -> None:
        """Display comprehensive analysis results"""
        self.log("\n[COMPREHENSIVE OCSP ANALYSIS RESULTS]")
        self.log("=" * 80)
        
        # Request Information
        if analysis.get("request_info"):
            self.log("\n[REQUEST INFORMATION]")
            self.log("-" * 40)
            req_info = analysis["request_info"]
            self.log(f"Version: {req_info.get('version', 'N/A')}")
            self.log(f"Hash Algorithm: {req_info.get('hash_algorithm', 'N/A')}")
            self.log(f"Serial Number: {req_info.get('serial_number', 'N/A')}")
            self.log(f"Nonce Present: {req_info.get('nonce_present', 'N/A')}")
        
        # Response Information
        if analysis.get("response_info"):
            self.log("\n[RESPONSE INFORMATION]")
            self.log("-" * 40)
            resp_info = analysis["response_info"]
            self.log(f"Status: {resp_info.get('status', 'N/A')}")
            self.log(f"Type: {resp_info.get('type', 'N/A')}")
            self.log(f"Version: {resp_info.get('version', 'N/A')}")
            self.log(f"Responder ID: {resp_info.get('responder_id', 'N/A')}")
            self.log(f"Produced At: {resp_info.get('produced_at', 'N/A')}")
        
        # Certificate Statuses
        if analysis.get("certificate_statuses"):
            self.log("\n[CERTIFICATE STATUSES]")
            self.log("-" * 40)
            for i, status in enumerate(analysis["certificate_statuses"]):
                self.log(f"Certificate {i+1}:")
                self.log(f"  Serial: {status.get('serial_number', 'N/A')}")
                self.log(f"  Status: {status.get('status', 'N/A')}")
                if status.get('revocation_time'):
                    self.log(f"  Revocation Time: {status['revocation_time']}")
                if status.get('revocation_reason'):
                    self.log(f"  Revocation Reason: {status['revocation_reason']}")
        
        # Responder Certificate
        if analysis.get("responder_certificate"):
            self.log("\n[RESPONDER CERTIFICATE]")
            self.log("-" * 40)
            cert_info = analysis["responder_certificate"]
            self.log(f"Subject: {cert_info.get('subject', 'N/A')}")
            self.log(f"Issuer: {cert_info.get('issuer', 'N/A')}")
            self.log(f"Serial Number: {cert_info.get('serial_number', 'N/A')}")
            self.log(f"Signature Algorithm: {cert_info.get('signature_algorithm', 'N/A')}")
            
            if cert_info.get('extensions'):
                extensions = cert_info['extensions']
                self.log(f"Key Usage: {extensions.get('key_usage', 'N/A')}")
                self.log(f"Extended Key Usage: {extensions.get('extended_key_usage', 'N/A')}")
                self.log(f"Subject Alternative Name: {extensions.get('subject_alternative_name', 'N/A')}")
                self.log(f"Subject Key Identifier: {extensions.get('subject_key_identifier', 'N/A')}")
        
        # Signature Information
        if analysis.get("signature_info"):
            self.log("\n[SIGNATURE INFORMATION]")
            self.log("-" * 40)
            sig_info = analysis["signature_info"]
            self.log(f"Algorithm: {sig_info.get('algorithm', 'N/A')}")
            self.log(f"Verified: {sig_info.get('verified', 'N/A')}")
            self.log(f"Verification Method: {sig_info.get('verification_method', 'N/A')}")
            if sig_info.get('errors'):
                self.log(f"Errors: {len(sig_info['errors'])} verification errors")
        
        # Security Analysis
        if analysis.get("security_analysis"):
            self.log("\n[SECURITY ANALYSIS]")
            self.log("-" * 40)
            security = analysis["security_analysis"]
            self.log(f"Nonce Support: {security.get('nonce_support', 'N/A')}")
            self.log(f"Signature Verification: {security.get('signature_verification', 'N/A')}")
            self.log(f"Response Freshness: {security.get('response_freshness', 'N/A')}")
            self.log(f"Certificate Status: {security.get('certificate_status_validation', 'N/A')}")
            
            if security.get('security_warnings'):
                self.log("\nSecurity Warnings:")
                for warning in security['security_warnings']:
                    self.log(f"  - {warning}")
            
            if security.get('security_recommendations'):
                self.log("\nSecurity Recommendations:")
                for rec in security['security_recommendations']:
                    self.log(f"  - {rec}")

def main():
    """Main function"""
    print("Comprehensive OCSP Signer Analysis Tool")
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
        print("Usage: python comprehensive_ocsp_analyzer.py <cert_path> <issuer_path> <ocsp_url>")
        print("\nExample:")
        print("python comprehensive_ocsp_analyzer.py certificate.pem issuer.pem http://ocsp.example.com")
        sys.exit(1)
    
    # Check if files exist
    if not os.path.exists(cert_path):
        print(f"[ERROR] Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not os.path.exists(issuer_path):
        print(f"[ERROR] Issuer file not found: {issuer_path}")
        sys.exit(1)
    
    # Create analyzer and run analysis
    analyzer = ComprehensiveOCSPAnalyzer()
    results = analyzer.analyze_ocsp_response(cert_path, issuer_path, ocsp_url)
    
    # Save results to JSON file
    output_file = f"comprehensive_ocsp_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[INFO] Analysis results saved to: {output_file}")
    
    # Print final summary
    print("\n[FINAL SUMMARY]")
    print("=" * 60)
    if "error" in results:
        print(f"[ERROR] Analysis failed: {results['error']}")
    else:
        print("[OK] Comprehensive OCSP analysis completed successfully!")
        print("Check the detailed results above and the saved JSON file for complete information.")

if __name__ == "__main__":
    main()

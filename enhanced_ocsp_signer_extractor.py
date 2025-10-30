#!/usr/bin/env python3
"""
Enhanced OCSP Signer Extraction Script

This script handles OCSP verification issues and extracts signer information
even when signature verification fails due to certificate chain issues.
"""

import subprocess
import re
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
import json

class EnhancedOCSPSignerExtractor:
    """Enhanced OCSP signer extractor that handles verification issues"""
    
    def __init__(self):
        self.log_callback = print
        
    def log(self, text: str) -> None:
        """Log message"""
        self.log_callback(text)
        
    def run_ocsp_check_with_signer_extraction(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run OCSP check and extract signer information, handling verification issues
        
        Args:
            cert_path: Path to the certificate being checked
            issuer_path: Path to the issuing CA certificate  
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing OCSP response details and signer information
        """
        try:
            self.log(f"[INFO] Running OCSP check for certificate: {cert_path}")
            self.log(f"[INFO] Using issuer: {issuer_path}")
            self.log(f"[INFO] OCSP URL: {ocsp_url}")
            self.log("=" * 60)
            
            # First, try with verification
            ocsp_cmd_with_verify = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-verify_other", issuer_path,
                "-text"
            ]
            
            self.log(f"[CMD] {' '.join(ocsp_cmd_with_verify)}")
            result_with_verify = subprocess.run(ocsp_cmd_with_verify, capture_output=True, text=True, timeout=30)
            
            # If verification fails, try without verification to get the raw response
            if result_with_verify.returncode != 0 or "Response Verify Failure" in result_with_verify.stderr:
                self.log("\n[INFO] Verification failed, trying without verification to extract signer info...")
                
                ocsp_cmd_no_verify = [
                    "openssl", "ocsp", 
                    "-issuer", issuer_path, 
                    "-cert", cert_path, 
                    "-url", ocsp_url, 
                    "-resp_text", 
                    "-noverify",  # Skip signature verification
                    "-text"
                ]
                
                self.log(f"[CMD] {' '.join(ocsp_cmd_no_verify)}")
                result_no_verify = subprocess.run(ocsp_cmd_no_verify, capture_output=True, text=True, timeout=30)
                
                # Use the no-verify result for extraction
                stdout = result_no_verify.stdout
                stderr = result_no_verify.stderr
                return_code = result_no_verify.returncode
            else:
                stdout = result_with_verify.stdout
                stderr = result_with_verify.stderr
                return_code = result_with_verify.returncode
            
            # Log the raw output
            self.log("\n[OCSP RESPONSE OUTPUT]")
            self.log("=" * 40)
            self.log(stdout)
            if stderr:
                self.log("\n[OCSP STDERR OUTPUT]")
                self.log("=" * 40)
                self.log(stderr)
            
            # Extract signer information
            signer_info = self.extract_signer_information(stdout, stderr)
            
            # Extract certificate status
            cert_status = self.extract_certificate_status(stdout)
            
            # Extract response timestamps
            timestamps = self.extract_response_timestamps(stdout)
            
            # Extract signature information
            signature_info = self.extract_signature_information(stdout, stderr)
            
            # Extract OCSP responder certificate details
            responder_cert_info = self.extract_responder_certificate(stdout)
            
            # Compile results
            results = {
                "certificate_path": cert_path,
                "issuer_path": issuer_path,
                "ocsp_url": ocsp_url,
                "timestamp": datetime.now().isoformat(),
                "return_code": return_code,
                "signer_information": signer_info,
                "certificate_status": cert_status,
                "response_timestamps": timestamps,
                "signature_information": signature_info,
                "responder_certificate": responder_cert_info,
                "raw_stdout": stdout,
                "raw_stderr": stderr
            }
            
            self.log("\n[EXTRACTED SIGNER INFORMATION]")
            self.log("=" * 40)
            self.log(json.dumps(signer_info, indent=2))
            
            if responder_cert_info:
                self.log("\n[EXTRACTED RESPONDER CERTIFICATE]")
                self.log("=" * 40)
                self.log(json.dumps(responder_cert_info, indent=2))
            
            return results
            
        except Exception as e:
            error_msg = f"[ERROR] OCSP Check Exception: {str(e)}"
            self.log(error_msg)
            return {"error": error_msg}
    
    def extract_signer_information(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Extract OCSP signer information from response"""
        signer_info = {
            "responder_id": None,
            "responder_id_type": None,
            "signature_algorithm": None,
            "signature_value": None,
            "signature_verified": False,
            "verification_errors": [],
            "nonce_support": None
        }
        
        try:
            # Extract Responder ID
            responder_match = re.search(r'Responder ID:\s*(.+)', stdout)
            if responder_match:
                responder_id = responder_match.group(1).strip()
                signer_info["responder_id"] = responder_id
                
                # Determine responder ID type
                if responder_id.startswith("CN=") or "CN=" in responder_id:
                    signer_info["responder_id_type"] = "subject_name"
                elif len(responder_id.replace(":", "")) == 40:  # SHA1 hash length
                    signer_info["responder_id_type"] = "key_hash"
                else:
                    signer_info["responder_id_type"] = "unknown"
            
            # Extract Signature Algorithm
            sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', stdout)
            if sig_algo_match:
                signer_info["signature_algorithm"] = sig_algo_match.group(1).strip()
            
            # Extract Signature Value
            sig_value_match = re.search(r'Signature Value:\s*([0-9a-fA-F:\s]+)', stdout)
            if sig_value_match:
                signature_value = sig_value_match.group(1).strip()
                # Clean up the signature value (remove spaces and colons)
                signature_value = re.sub(r'[\s:]', '', signature_value)
                signer_info["signature_value"] = signature_value
            
            # Check if signature verification passed
            if "Response verify OK" in stdout or "Response verify OK" in stderr:
                signer_info["signature_verified"] = True
            elif "Response Verify Failure" in stderr:
                signer_info["signature_verified"] = False
                # Extract verification errors
                error_lines = stderr.split('\n')
                for line in error_lines:
                    if 'error:' in line.lower() or 'verify error:' in line.lower():
                        signer_info["verification_errors"].append(line.strip())
            
            # Check nonce support
            if "WARNING: no nonce in response" in stderr:
                signer_info["nonce_support"] = False
            elif "Nonce" in stdout:
                signer_info["nonce_support"] = True
            else:
                signer_info["nonce_support"] = None
            
            self.log(f"[SIGNER] Responder ID: {signer_info['responder_id']}")
            self.log(f"[SIGNER] Responder ID Type: {signer_info['responder_id_type']}")
            self.log(f"[SIGNER] Signature Algorithm: {signer_info['signature_algorithm']}")
            self.log(f"[SIGNER] Signature Verified: {signer_info['signature_verified']}")
            self.log(f"[SIGNER] Nonce Support: {signer_info['nonce_support']}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting signer information: {str(e)}")
            signer_info["extraction_error"] = str(e)
        
        return signer_info
    
    def extract_responder_certificate(self, stdout: str) -> Dict[str, Any]:
        """Extract OCSP responder certificate details from response"""
        cert_info = {
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "validity_period": None,
            "public_key_algorithm": None,
            "key_usage": None,
            "extended_key_usage": None,
            "subject_alternative_name": None,
            "authority_key_identifier": None,
            "subject_key_identifier": None,
            "certificate_policies": None
        }
        
        try:
            # Look for certificate section
            cert_section_match = re.search(r'Certificate:\s*\n(.*?)(?=\n\s*Signature|\n\s*-----BEGIN)', stdout, re.DOTALL)
            if cert_section_match:
                cert_text = cert_section_match.group(1)
                
                # Extract subject
                subject_match = re.search(r'Subject:\s*(.+)', cert_text)
                if subject_match:
                    cert_info["subject"] = subject_match.group(1).strip()
                
                # Extract issuer
                issuer_match = re.search(r'Issuer:\s*(.+)', cert_text)
                if issuer_match:
                    cert_info["issuer"] = issuer_match.group(1).strip()
                
                # Extract serial number
                serial_match = re.search(r'Serial Number:\s*(.+)', cert_text)
                if serial_match:
                    cert_info["serial_number"] = serial_match.group(1).strip()
                
                # Extract validity period
                validity_match = re.search(r'Validity\s*\n\s*Not Before:\s*(.+)\n\s*Not After\s*:\s*(.+)', cert_text)
                if validity_match:
                    cert_info["validity_period"] = {
                        "not_before": validity_match.group(1).strip(),
                        "not_after": validity_match.group(2).strip()
                    }
                
                # Extract public key algorithm
                pubkey_match = re.search(r'Public Key Algorithm:\s*(.+)', cert_text)
                if pubkey_match:
                    cert_info["public_key_algorithm"] = pubkey_match.group(1).strip()
                
                # Extract key usage
                key_usage_match = re.search(r'X509v3 Key Usage:\s*(.+)', cert_text)
                if key_usage_match:
                    cert_info["key_usage"] = key_usage_match.group(1).strip()
                
                # Extract extended key usage
                ext_key_usage_match = re.search(r'X509v3 Extended Key Usage:\s*(.+)', cert_text)
                if ext_key_usage_match:
                    cert_info["extended_key_usage"] = ext_key_usage_match.group(1).strip()
                
                # Extract subject alternative name
                san_match = re.search(r'X509v3 Subject Alternative Name:\s*(.+)', cert_text)
                if san_match:
                    cert_info["subject_alternative_name"] = san_match.group(1).strip()
                
                # Extract authority key identifier
                aki_match = re.search(r'X509v3 Authority Key Identifier:\s*(.+)', cert_text)
                if aki_match:
                    cert_info["authority_key_identifier"] = aki_match.group(1).strip()
                
                # Extract subject key identifier
                ski_match = re.search(r'X509v3 Subject Key Identifier:\s*(.+)', cert_text)
                if ski_match:
                    cert_info["subject_key_identifier"] = ski_match.group(1).strip()
                
                # Extract certificate policies
                policies_match = re.search(r'X509v3 Certificate Policies:\s*(.+?)(?=\n\s*[A-Z]|\n\s*Authority)', cert_text, re.DOTALL)
                if policies_match:
                    policies_text = policies_match.group(1).strip()
                    # Extract individual policies
                    policy_matches = re.findall(r'Policy:\s*(.+)', policies_text)
                    if policy_matches:
                        cert_info["certificate_policies"] = policy_matches
            
            self.log(f"[RESPONDER CERT] Subject: {cert_info['subject']}")
            self.log(f"[RESPONDER CERT] Issuer: {cert_info['issuer']}")
            self.log(f"[RESPONDER CERT] Serial: {cert_info['serial_number']}")
            if cert_info['extended_key_usage']:
                self.log(f"[RESPONDER CERT] Extended Key Usage: {cert_info['extended_key_usage']}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting responder certificate: {str(e)}")
            cert_info["extraction_error"] = str(e)
        
        return cert_info
    
    def extract_certificate_status(self, stdout: str) -> Dict[str, Any]:
        """Extract certificate status information"""
        status_info = {
            "status": "UNKNOWN",
            "serial_number": None,
            "revocation_time": None,
            "revocation_reason": None
        }
        
        try:
            # Extract certificate status - look for ": good", ": revoked", ": unknown"
            if ": good" in stdout:
                status_info["status"] = "GOOD"
            elif ": revoked" in stdout:
                status_info["status"] = "REVOKED"
            elif ": unknown" in stdout:
                status_info["status"] = "UNKNOWN"
            
            # Extract serial number from the certificate being checked
            serial_match = re.search(r'Serial Number:\s*(.+)', stdout)
            if serial_match:
                status_info["serial_number"] = serial_match.group(1).strip()
            
            # Extract revocation details if revoked
            if status_info["status"] == "REVOKED":
                rev_time_match = re.search(r'Revocation Time:\s*(.+)', stdout)
                if rev_time_match:
                    status_info["revocation_time"] = rev_time_match.group(1).strip()
                
                rev_reason_match = re.search(r'Revocation Reason:\s*(.+)', stdout)
                if rev_reason_match:
                    status_info["revocation_reason"] = rev_reason_match.group(1).strip()
            
            self.log(f"[STATUS] Certificate Status: {status_info['status']}")
            if status_info['serial_number']:
                self.log(f"[STATUS] Serial Number: {status_info['serial_number']}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting certificate status: {str(e)}")
            status_info["extraction_error"] = str(e)
        
        return status_info
    
    def extract_response_timestamps(self, stdout: str) -> Dict[str, Any]:
        """Extract response timestamps"""
        timestamps = {
            "this_update": None,
            "next_update": None,
            "produced_at": None
        }
        
        try:
            # Extract thisUpdate
            this_update_match = re.search(r'This Update:\s*(.+)', stdout)
            if this_update_match:
                timestamps["this_update"] = this_update_match.group(1).strip()
            
            # Extract nextUpdate
            next_update_match = re.search(r'Next Update:\s*(.+)', stdout)
            if next_update_match:
                timestamps["next_update"] = next_update_match.group(1).strip()
            
            # Extract Produced At
            produced_at_match = re.search(r'Produced At:\s*(.+)', stdout)
            if produced_at_match:
                timestamps["produced_at"] = produced_at_match.group(1).strip()
            
            self.log(f"[TIMESTAMPS] This Update: {timestamps['this_update']}")
            self.log(f"[TIMESTAMPS] Next Update: {timestamps['next_update']}")
            self.log(f"[TIMESTAMPS] Produced At: {timestamps['produced_at']}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting timestamps: {str(e)}")
            timestamps["extraction_error"] = str(e)
        
        return timestamps
    
    def extract_signature_information(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Extract signature verification information"""
        sig_info = {
            "signature_verified": False,
            "verification_method": None,
            "verification_errors": [],
            "signature_algorithm": None,
            "signature_value": None
        }
        
        try:
            # Check verification status
            if "Response verify OK" in stdout or "Response verify OK" in stderr:
                sig_info["signature_verified"] = True
                sig_info["verification_method"] = "openssl_builtin"
            elif "Response Verify Failure" in stderr:
                sig_info["signature_verified"] = False
                sig_info["verification_method"] = "failed"
            else:
                sig_info["verification_method"] = "unknown"
            
            # Extract signature algorithm
            sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', stdout)
            if sig_algo_match:
                sig_info["signature_algorithm"] = sig_algo_match.group(1).strip()
            
            # Extract signature value
            sig_value_match = re.search(r'Signature Value:\s*([0-9a-fA-F:\s]+)', stdout)
            if sig_value_match:
                signature_value = sig_value_match.group(1).strip()
                signature_value = re.sub(r'[\s:]', '', signature_value)
                sig_info["signature_value"] = signature_value
            
            # Extract verification errors
            if stderr:
                error_lines = stderr.split('\n')
                for line in error_lines:
                    if 'error:' in line.lower() or 'verify error:' in line.lower():
                        sig_info["verification_errors"].append(line.strip())
            
            self.log(f"[SIGNATURE] Verified: {sig_info['signature_verified']}")
            self.log(f"[SIGNATURE] Method: {sig_info['verification_method']}")
            if sig_info['verification_errors']:
                self.log(f"[SIGNATURE] Errors: {sig_info['verification_errors']}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting signature information: {str(e)}")
            sig_info["extraction_error"] = str(e)
        
        return sig_info

def main():
    """Main function to run OCSP check and extract signer information"""
    print("Enhanced OCSP Signer Extraction Tool")
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
        print("Usage: python enhanced_ocsp_signer_extractor.py <cert_path> <issuer_path> <ocsp_url>")
        print("\nExample:")
        print("python enhanced_ocsp_signer_extractor.py certificate.pem issuer.pem http://ocsp.example.com")
        sys.exit(1)
    
    # Check if files exist
    if not os.path.exists(cert_path):
        print(f"[ERROR] Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not os.path.exists(issuer_path):
        print(f"[ERROR] Issuer file not found: {issuer_path}")
        sys.exit(1)
    
    # Create extractor and run check
    extractor = EnhancedOCSPSignerExtractor()
    results = extractor.run_ocsp_check_with_signer_extraction(cert_path, issuer_path, ocsp_url)
    
    # Save results to JSON file
    output_file = f"enhanced_ocsp_signer_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[INFO] Results saved to: {output_file}")
    
    # Print summary
    print("\n[SUMMARY]")
    print("=" * 50)
    if "error" in results:
        print(f"[ERROR] Error: {results['error']}")
    else:
        signer_info = results.get("signer_information", {})
        cert_status = results.get("certificate_status", {})
        responder_cert = results.get("responder_certificate", {})
        
        print(f"[OK] OCSP Check Completed")
        print(f"Certificate Status: {cert_status.get('status', 'UNKNOWN')}")
        print(f"Signature Verified: {signer_info.get('signature_verified', False)}")
        print(f"Responder ID: {signer_info.get('responder_id', 'Not found')}")
        print(f"Signature Algorithm: {signer_info.get('signature_algorithm', 'Not found')}")
        print(f"Nonce Support: {signer_info.get('nonce_support', 'Unknown')}")
        
        if responder_cert.get('subject'):
            print(f"Responder Subject: {responder_cert['subject']}")
        if responder_cert.get('extended_key_usage'):
            print(f"Responder Key Usage: {responder_cert['extended_key_usage']}")
        
        if signer_info.get('verification_errors'):
            print(f"Verification Errors: {len(signer_info['verification_errors'])} errors found")

if __name__ == "__main__":
    main()


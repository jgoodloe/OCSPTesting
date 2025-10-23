#!/usr/bin/env python3
"""
OCSP Signer Extraction Script

This script runs an OCSP check and extracts the OCSP signer information from the response.
It uses the existing OCSP testing framework to perform the check and then parses the response
to extract signer details.
"""

import subprocess
import re
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
import json

class OCSPSignerExtractor:
    """Extract OCSP signer information from OCSP responses"""
    
    def __init__(self):
        self.log_callback = print
        
    def log(self, text: str) -> None:
        """Log message"""
        self.log_callback(text)
        
    def run_ocsp_check_with_signer_extraction(self, cert_path: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run OCSP check and extract signer information
        
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
            
            # Run OCSP check with detailed output
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-verify_other", issuer_path,
                "-text"  # Get detailed text output
            ]
            
            self.log(f"[CMD] {' '.join(ocsp_cmd)}")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            # Log the raw output
            self.log("\n[OCSP RESPONSE OUTPUT]")
            self.log("=" * 40)
            self.log(result.stdout)
            if result.stderr:
                self.log("\n[OCSP STDERR OUTPUT]")
                self.log("=" * 40)
                self.log(result.stderr)
            
            # Extract signer information
            signer_info = self.extract_signer_information(result.stdout, result.stderr)
            
            # Extract certificate status
            cert_status = self.extract_certificate_status(result.stdout)
            
            # Extract response timestamps
            timestamps = self.extract_response_timestamps(result.stdout)
            
            # Extract signature information
            signature_info = self.extract_signature_information(result.stdout, result.stderr)
            
            # Compile results
            results = {
                "certificate_path": cert_path,
                "issuer_path": issuer_path,
                "ocsp_url": ocsp_url,
                "timestamp": datetime.now().isoformat(),
                "return_code": result.returncode,
                "signer_information": signer_info,
                "certificate_status": cert_status,
                "response_timestamps": timestamps,
                "signature_information": signature_info,
                "raw_stdout": result.stdout,
                "raw_stderr": result.stderr
            }
            
            self.log("\n[EXTRACTED SIGNER INFORMATION]")
            self.log("=" * 40)
            self.log(json.dumps(signer_info, indent=2))
            
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
            "signer_certificate": None,
            "signer_subject": None,
            "signer_issuer": None,
            "signer_serial": None,
            "signer_validity": None
        }
        
        try:
            # Extract Responder ID
            responder_match = re.search(r'Responder ID:\s*(.+)', stdout)
            if responder_match:
                responder_id = responder_match.group(1).strip()
                signer_info["responder_id"] = responder_id
                
                # Determine responder ID type
                if responder_id.startswith("CN="):
                    signer_info["responder_id_type"] = "subject_name"
                elif len(responder_id) == 40:  # SHA1 hash length
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
            
            # Extract signer certificate information if available
            # Look for certificate details in the response
            cert_match = re.search(r'Certificate:\s*\n(.*?)(?=\n\s*\n|\n\s*Signature)', stdout, re.DOTALL)
            if cert_match:
                cert_text = cert_match.group(1)
                
                # Extract subject
                subject_match = re.search(r'Subject:\s*(.+)', cert_text)
                if subject_match:
                    signer_info["signer_subject"] = subject_match.group(1).strip()
                
                # Extract issuer
                issuer_match = re.search(r'Issuer:\s*(.+)', cert_text)
                if issuer_match:
                    signer_info["signer_issuer"] = issuer_match.group(1).strip()
                
                # Extract serial number
                serial_match = re.search(r'Serial Number:\s*(.+)', cert_text)
                if serial_match:
                    signer_info["signer_serial"] = serial_match.group(1).strip()
                
                # Extract validity period
                validity_match = re.search(r'Validity\s*\n\s*Not Before:\s*(.+)\n\s*Not After:\s*(.+)', cert_text)
                if validity_match:
                    not_before = validity_match.group(1).strip()
                    not_after = validity_match.group(2).strip()
                    signer_info["signer_validity"] = {
                        "not_before": not_before,
                        "not_after": not_after
                    }
            
            self.log(f"[SIGNER] Responder ID: {signer_info['responder_id']}")
            self.log(f"[SIGNER] Responder ID Type: {signer_info['responder_id_type']}")
            self.log(f"[SIGNER] Signature Algorithm: {signer_info['signature_algorithm']}")
            self.log(f"[SIGNER] Signature Verified: {signer_info['signature_verified']}")
            if signer_info['signer_subject']:
                self.log(f"[SIGNER] Signer Subject: {signer_info['signer_subject']}")
            if signer_info['signer_issuer']:
                self.log(f"[SIGNER] Signer Issuer: {signer_info['signer_issuer']}")
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting signer information: {str(e)}")
            signer_info["extraction_error"] = str(e)
        
        return signer_info
    
    def extract_certificate_status(self, stdout: str) -> Dict[str, Any]:
        """Extract certificate status information"""
        status_info = {
            "status": "UNKNOWN",
            "serial_number": None,
            "revocation_time": None,
            "revocation_reason": None
        }
        
        try:
            # Extract certificate status
            status_match = re.search(r'Cert Status:\s*(\w+)', stdout)
            if status_match:
                status_info["status"] = status_match.group(1).upper()
            
            # Extract serial number
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
            elif "verify OK" in stderr.lower():
                sig_info["signature_verified"] = True
                sig_info["verification_method"] = "openssl_builtin"
            else:
                sig_info["signature_verified"] = False
                sig_info["verification_method"] = "failed"
            
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
                    if 'error' in line.lower() or 'fail' in line.lower():
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
    print("OCSP Signer Extraction Tool")
    print("=" * 40)
    
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
        print("Usage: python ocsp_signer_extractor.py <cert_path> <issuer_path> <ocsp_url>")
        print("\nExample:")
        print("python ocsp_signer_extractor.py certificate.pem issuer.pem http://ocsp.example.com")
        sys.exit(1)
    
    # Check if files exist
    if not os.path.exists(cert_path):
        print(f"[ERROR] Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not os.path.exists(issuer_path):
        print(f"[ERROR] Issuer file not found: {issuer_path}")
        sys.exit(1)
    
    # Create extractor and run check
    extractor = OCSPSignerExtractor()
    results = extractor.run_ocsp_check_with_signer_extraction(cert_path, issuer_path, ocsp_url)
    
    # Save results to JSON file
    output_file = f"ocsp_signer_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[INFO] Results saved to: {output_file}")
    
    # Print summary
    print("\n[SUMMARY]")
    print("=" * 40)
    if "error" in results:
        print(f"[ERROR] Error: {results['error']}")
    else:
        signer_info = results.get("signer_information", {})
        cert_status = results.get("certificate_status", {})
        
        print(f"[OK] OCSP Check Completed")
        print(f"Certificate Status: {cert_status.get('status', 'UNKNOWN')}")
        print(f"Signature Verified: {signer_info.get('signature_verified', False)}")
        print(f"Responder ID: {signer_info.get('responder_id', 'Not found')}")
        print(f"Signature Algorithm: {signer_info.get('signature_algorithm', 'Not found')}")
        
        if signer_info.get('signer_subject'):
            print(f"Signer Subject: {signer_info['signer_subject']}")

if __name__ == "__main__":
    main()

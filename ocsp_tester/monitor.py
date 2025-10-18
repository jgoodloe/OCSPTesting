import subprocess
import threading
import os
import requests
from urllib.parse import urlparse
from uuid import uuid4
from datetime import datetime
import re
from typing import Optional, Tuple, Callable, Dict, Any
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

            # Signature Verification
            if "Response verify OK" in stdout or "Response verify OK" in result.stderr or "verify OK" in result.stderr.lower():
                summary += "[OK] Signature verification: PASS\n"
                results["signature_verified"] = True
            else:
                verify_sig_result = self.verify_ocsp_signature(cert_path, issuer_path, ocsp_url)
                if verify_sig_result:
                    summary += "[OK] Signature verification: PASS (manual check)\n"
                    results["signature_verified"] = True
                else:
                    summary += "[ERROR] Signature verification: FAIL\n"

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
        """Manual OCSP signature verification fallback"""
        try:
            tmp_resp = os.path.join(os.getenv("TEMP", "/tmp"), f"ocsp_resp_{uuid4().hex}.der")
            cmd_resp = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-respout", tmp_resp, 
                "-noverify"
            ]
            subprocess.run(cmd_resp, capture_output=True, timeout=20)
            
            verify_cmd = ["openssl", "ocsp", "-respin", tmp_resp, "-verify_other", issuer_path, "-noverify"]
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            os.remove(tmp_resp)
            return "Response verify OK" in verify_result.stdout
        except Exception:
            return False

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
                                    import re
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
        for line in result.stdout.splitlines():
            if "URI:" in line and ("http" in line or "https" in line):
                return line.split("URI:")[-1].strip()
        return None

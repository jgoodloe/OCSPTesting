#!/usr/bin/env python3
"""Test script to verify CRL URL extraction"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ocsp_tester.monitor import OCSPMonitor

def test_crl_extraction():
    """Test CRL URL extraction"""
    monitor = OCSPMonitor()
    
    cert_path = r"C:\Users\jcgoo\Downloads\jasonocsptest.cer"
    
    print("Testing CRL URL extraction...")
    print(f"Certificate: {cert_path}")
    
    crl_url = monitor.extract_crl_url(cert_path)
    
    if crl_url:
        print(f"[OK] Extracted CRL URL: {crl_url}")
        
        # Test if we can download the CRL
        import requests
        try:
            print(f"Testing download from: {crl_url}")
            resp = requests.get(crl_url, timeout=10)
            print(f"[OK] Download successful: HTTP {resp.status_code}")
            print(f"[OK] Content size: {len(resp.content)} bytes")
            
            if len(resp.content) < 100:
                print(f"[WARN] Content seems too small: {resp.content}")
            else:
                print("[OK] Content size looks reasonable")
                
        except Exception as e:
            print(f"[ERROR] Download failed: {e}")
    else:
        print("[ERROR] No CRL URL found")

if __name__ == "__main__":
    test_crl_extraction()

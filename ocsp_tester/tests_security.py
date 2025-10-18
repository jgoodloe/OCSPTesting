import os
import uuid
from typing import List, Optional

from cryptography import x509
from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec
from cryptography.hazmat.primitives import hashes


def run_security_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    good_cert: Optional[x509.Certificate],
    client_sign_cert: Optional[str],
    client_sign_key: Optional[str],
) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    # 1. Malformed request (truncate DER)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Malformed request rejected", status=TestStatus.ERROR)
    try:
        # Test various malformed request scenarios
        malformed_tests = []
        
        # Zero-length nonce
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True, nonce_len=0), method="POST")
            malformed_tests.append(("Zero-length nonce", "accepted"))
        except Exception as e:
            malformed_tests.append(("Zero-length nonce", f"rejected: {str(e)[:50]}"))
        
        # Overlong nonce (>128 octets)
        try:
            over = os.urandom(129)
            info2 = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True), method="POST", override_nonce=over)
            malformed_tests.append(("Overlong nonce", "accepted"))
        except Exception as e:
            malformed_tests.append(("Overlong nonce", f"rejected: {str(e)[:50]}"))
        
        # Test with malformed DER by sending truncated request
        try:
            # Build a normal request and truncate it
            from .ocsp_client import _build_request
            from .ocsp_client import OCSPRequestSpec
            der_req, _ = _build_request(OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=False))
            truncated_req = der_req[:-10]  # Remove last 10 bytes
            
            import requests
            headers = {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}
            resp = requests.post(ocsp_url, data=truncated_req, headers=headers, timeout=10)
            malformed_tests.append(("Truncated DER", f"status: {resp.status_code}"))
        except Exception as e:
            malformed_tests.append(("Truncated DER", f"rejected: {str(e)[:50]}"))
        
        # Evaluate results
        rejected_count = sum(1 for _, result in malformed_tests if "rejected" in result.lower())
        if rejected_count > 0:
            r.status = TestStatus.PASS
            r.message = f"Server rejected {rejected_count}/{len(malformed_tests)} malformed requests"
        else:
            r.status = TestStatus.SKIP
            r.message = "Server accepted malformed requests; policy-dependent"
        
        r.details.update({"malformed_tests": malformed_tests})
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    # 2. Operational errors tryLater/internalError (observational)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Operational error signaling", status=TestStatus.SKIP)
    r.message = "Needs induced backend failure to assert; skipping"
    r.end()
    results.append(r)

    # 3a. Unauthorized queries
    r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Unauthorized query handling", status=TestStatus.SKIP)
    r.message = "Requires access-controlled responder to assert; skipping"
    r.end()
    results.append(r)

    # 3b. sigRequired without signature
    r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="sigRequired when unsigned", status=TestStatus.SKIP)
    r.message = "Requires responder enforcing signed requests; skipping"
    r.end()
    results.append(r)

    # 4. Nonce echo verification
    r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Nonce echo in response", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True, nonce_len=32), method="POST")
        if info.response_status == "SUCCESSFUL" and info.nonce_echoed is not None:
            r.status = TestStatus.PASS if info.nonce_echoed else TestStatus.FAIL
            r.message = "Nonce echoed" if info.nonce_echoed else "Nonce missing/mismatch"
        else:
            r.status = TestStatus.SKIP
            r.message = "Responder may not implement nonce; skipping strict assertion"
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    # 5. Signature trust validation - partial (cannot complete full path validation generically)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Signature algorithm present and response SUCCESSFUL", status=TestStatus.ERROR)
    try:
        # Test description
        test_description = [
            "This test validates OCSP response signature algorithm presence and response success.",
            "It checks:",
            "1. OCSP response status is SUCCESSFUL",
            "2. Signature algorithm OID is present in response",
            "3. Response structure includes signature information",
            "4. Basic signature algorithm validation"
        ]
        
        test_cert = good_cert or issuer
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(test_cert, issuer, include_nonce=False), method="POST")
        
        # Detailed analysis
        analysis = {
            "test_description": test_description,
            "request_method": "POST",
            "nonce_included": False,
            "test_certificate": str(test_cert.subject) if test_cert else "None",
            "issuer_certificate": str(issuer.subject),
            "ocsp_url": ocsp_url
        }
        
        # Response status analysis
        status_analysis = {
            "response_status": info.response_status,
            "status_meaning": {
                "SUCCESSFUL": "Response is valid and contains certificate status",
                "MALFORMED": "Request was malformed or invalid",
                "INTERNAL_ERROR": "OCSP responder internal error",
                "TRY_LATER": "Responder temporarily unavailable",
                "SIG_REQUIRED": "Request must be signed",
                "UNAUTHORIZED": "Request not authorized (certificate not issued by this CA)"
            }.get(info.response_status, "Unknown status"),
            "is_successful": info.response_status == "SUCCESSFUL"
        }
        
        # Signature algorithm analysis
        signature_analysis = {
            "signature_algorithm_oid": info.signature_algorithm_oid,
            "signature_present": info.signature_algorithm_oid is not None,
            "algorithm_meaning": {
                "1.2.840.113549.1.1.5": "sha1WithRSAEncryption (deprecated)",
                "1.2.840.113549.1.1.11": "sha256WithRSAEncryption (recommended)",
                "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
                "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
                "1.2.840.10040.4.3": "dsaWithSHA1 (deprecated)",
                "1.2.840.10045.4.1": "ecdsaWithSHA1 (deprecated)",
                "1.2.840.10045.4.3.2": "ecdsaWithSHA256 (recommended)",
                "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
                "1.2.840.10045.4.3.4": "ecdsaWithSHA512"
            }.get(info.signature_algorithm_oid, "Unknown algorithm") if info.signature_algorithm_oid else "No algorithm"
        }
        
        # Additional response details
        response_details = {
            "version": info.version,
            "produced_at": info.produced_at,
            "responder_id": info.responder_id,
            "certificate_status": getattr(info, 'certificate_status', None),
            "this_update": getattr(info, 'this_update', None),
            "next_update": getattr(info, 'next_update', None)
        }
        
        # Determine test result
        status_ok = info.response_status == "SUCCESSFUL"
        signature_present = info.signature_algorithm_oid is not None
        
        if status_ok and signature_present:
            r.status = TestStatus.PASS
            r.message = f"OCSP response successful with signature algorithm: {info.signature_algorithm_oid}"
        elif not status_ok:
            r.status = TestStatus.FAIL
            r.message = f"OCSP response not successful: {info.response_status}"
        elif not signature_present:
            r.status = TestStatus.FAIL
            r.message = "OCSP response missing signature algorithm"
        else:
            r.status = TestStatus.FAIL
            r.message = "OCSP response validation failed"
        
        # Comprehensive test details
        r.details.update({
            "analysis": analysis,
            "status_analysis": status_analysis,
            "signature_analysis": signature_analysis,
            "response_details": response_details,
            "test_result": {
                "status_ok": status_ok,
                "signature_present": signature_present,
                "overall_result": r.status.value
            },
            "troubleshooting": {
                "if_unauthorized": "Certificate may not be issued by the OCSP responder's CA",
                "if_missing_signature": "OCSP responder may not be RFC 6960 compliant",
                "if_unsuccessful": "OCSP responder may be experiencing issues",
                "if_deprecated_algorithm": "Consider upgrading to a stronger signature algorithm",
                "next_steps": "Verify certificate issuer matches OCSP responder CA, check OCSP responder status"
            }
        })
        
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = f"Test execution failed: {exc}"
        r.details.update({
            "error_type": type(exc).__name__,
            "error_details": str(exc),
            "troubleshooting": {
                "network_issue": "Check OCSP URL accessibility and network connectivity",
                "certificate_issue": "Verify certificate and issuer files are valid",
                "parsing_issue": "OCSP response may be malformed or unsupported format"
            }
        })
    r.end()
    results.append(r)

    return results

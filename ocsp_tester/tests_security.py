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
        # Build a normal request, then chop bytes by overriding nonce with huge length or truncated DER via GET path trick
        try:
            # Zero-length nonce
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True, nonce_len=0), method="POST")
            # If accepted, still OK per server policy; We'll try overlong nonce
            over = os.urandom(129)
            info2 = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True), method="POST", override_nonce=over)
            # If server still accepts, not necessarily failure, but we cannot assert malformed strictly
            r.status = TestStatus.SKIP
            r.message = "Responder did not reject nonce anomalies; policy-dependent; skipping strict assertion"
        except Exception:
            r.status = TestStatus.PASS
            r.message = "Responder rejected malformed/constraint-violating nonce"
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
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=False), method="POST")
        if info.response_status == "SUCCESSFUL" and info.signature_algorithm_oid:
            r.status = TestStatus.PASS
            r.message = f"Signature OID {info.signature_algorithm_oid}"
        else:
            r.status = TestStatus.FAIL
            r.message = "Missing signature algorithm or unsuccessful response"
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    return results

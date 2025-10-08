import uuid
from datetime import datetime
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec


def run_protocol_tests(ocsp_url: str, issuer: x509.Certificate, leaf: x509.Certificate) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    # 1. HTTP GET
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="HTTP GET transport", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=True, nonce_len=16), method="GET")
        r.status = TestStatus.PASS
        r.message = "GET accepted"
        r.details.update({"latency_ms": info.latency_ms, "response_status": info.response_status})
    except Exception as exc:
        r.status = TestStatus.FAIL
        r.message = f"GET failed: {exc}"
    r.end()
    results.append(r)

    # 1. HTTP POST
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="HTTP POST transport", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=True, nonce_len=16), method="POST")
        r.status = TestStatus.PASS
        r.message = "POST accepted"
        r.details.update({"latency_ms": info.latency_ms, "response_status": info.response_status})
    except Exception as exc:
        r.status = TestStatus.FAIL
        r.message = f"POST failed: {exc}"
    r.end()
    results.append(r)

    # 2-3. DER encoding, Basic response structure, version producedAt extracted
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="DER encoding and basic response fields", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=False), method="POST")
        ok = info.response_status == "SUCCESSFUL"
        has_fields = info.signature_algorithm_oid is not None
        r.status = TestStatus.PASS if (ok and has_fields) else TestStatus.FAIL
        r.message = "Parsed basic fields" if r.status == TestStatus.PASS else "Missing required fields"
        r.details.update({
            "response_status": info.response_status,
            "version": info.version,
            "produced_at": info.produced_at,
            "responder_id": info.responder_id,
            "signature_algorithm_oid": info.signature_algorithm_oid,
        })
    except Exception as exc:
        r.status = TestStatus.FAIL
        r.message = f"Could not parse response: {exc}"
    r.end()
    results.append(r)

    # 4. CertID SHA-1 usage (request side)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="CertID SHA-1 for issuer hashes", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=False, hash_algo=hashes.SHA1()), method="POST")
        r.status = TestStatus.PASS if info.response_status == "SUCCESSFUL" else TestStatus.FAIL
        r.message = "Request with SHA-1 identifier accepted"
    except Exception as exc:
        r.status = TestStatus.FAIL
        r.message = f"Request failed: {exc}"
    r.end()
    results.append(r)

    return results

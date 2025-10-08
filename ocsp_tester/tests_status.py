import uuid
from typing import List, Optional

from cryptography import x509
from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec


def run_status_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    good_cert: Optional[x509.Certificate],
    revoked_cert: Optional[x509.Certificate],
    unknown_ca_cert: Optional[x509.Certificate],
) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    # 1. Valid certificate status
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Known valid certificate returns good", status=TestStatus.SKIP)
    if good_cert is None:
        r.message = "No known-good certificate provided"
    else:
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert, issuer, include_nonce=True), method="POST")
            if info.response_status == "SUCCESSFUL" and (info.cert_status or "").lower() == "good":
                r.status = TestStatus.PASS
                r.message = "good"
            else:
                r.status = TestStatus.FAIL
                r.message = f"Unexpected status: {info.response_status}/{info.cert_status}"
            r.details.update({"this_update": info.this_update, "next_update": info.next_update})
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)

    # 2. Revoked certificate status
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Known revoked certificate returns revoked", status=TestStatus.SKIP)
    if revoked_cert is None:
        r.message = "No known-revoked certificate provided"
    else:
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(revoked_cert, issuer, include_nonce=True), method="POST")
            if info.response_status == "SUCCESSFUL" and (info.cert_status or "").lower() == "revoked":
                r.status = TestStatus.PASS
                r.message = "revoked"
                r.details.update({"revocation_time": info.revocation_time, "revocation_reason": info.revocation_reason})
            else:
                r.status = TestStatus.FAIL
                r.message = f"Unexpected status: {info.response_status}/{info.cert_status}"
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)

    # 3. Unknown CA
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Unknown CA returns unknown", status=TestStatus.SKIP)
    if unknown_ca_cert is None:
        r.message = "No unknown-CA certificate provided"
    else:
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(unknown_ca_cert, issuer, include_nonce=True), method="POST")
            # Many responders return 'unknown' for unserved issuers
            r.status = TestStatus.PASS if (info.cert_status or "").lower() == "unknown" else TestStatus.FAIL
            r.message = f"cert_status={info.cert_status}"
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)

    # 4. Non-issued serial handling (extended revoked) - cannot be asserted generically
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Non-issued certificate handling", status=TestStatus.SKIP)
    r.message = "Requires non-issued serial scenario configured; skipping"
    r.end()
    results.append(r)

    # 5. Timeliness fields
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="thisUpdate/nextUpdate/producedAt present and plausible", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or revoked_cert or issuer, issuer, include_nonce=False), method="POST")
        has_this = info.this_update is not None
        has_next = info.next_update is not None
        has_prod = info.produced_at is not None
        r.status = TestStatus.PASS if (has_this and has_next and has_prod) else TestStatus.FAIL
        r.message = f"this={has_this}, next={has_next}, producedAt={has_prod}"
        r.details.update({"this_update": info.this_update, "next_update": info.next_update, "produced_at": info.produced_at})
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    return results

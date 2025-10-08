import os
import uuid
from dataclasses import dataclass
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import TestCaseResult, TestStatus
from .tests_protocol import run_protocol_tests
from .tests_status import run_status_tests
from .tests_security import run_security_tests
from .tests_performance import run_perf_tests
from .tests_ikev2 import run_ikev2_tests


@dataclass
class TestInputs:
    ocsp_url: str
    issuer_path: str
    known_good_cert_path: Optional[str] = None
    known_revoked_cert_path: Optional[str] = None
    unknown_ca_cert_path: Optional[str] = None
    client_sign_cert_path: Optional[str] = None
    client_sign_key_path: Optional[str] = None
    latency_samples: int = 5
    enable_load_test: bool = False
    load_concurrency: int = 5
    load_requests: int = 50


def _load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return x509.load_der_x509_certificate(data)


class TestRunner:
    def run_all(self, inputs: TestInputs) -> List[TestCaseResult]:
        results: List[TestCaseResult] = []

        # Load required certs
        try:
            issuer = _load_cert(inputs.issuer_path)
        except Exception as exc:
            r = TestCaseResult(id=str(uuid.uuid4()), category="Setup", name="Load issuer certificate", status=TestStatus.ERROR, message=str(exc))
            r.end()
            return [r]

        good = None
        revoked = None
        unknown_ca = None
        if inputs.known_good_cert_path:
            try:
                good = _load_cert(inputs.known_good_cert_path)
            except Exception as exc:
                results.append(self._err("Setup", "Load known-good certificate", str(exc)))
        if inputs.known_revoked_cert_path:
            try:
                revoked = _load_cert(inputs.known_revoked_cert_path)
            except Exception as exc:
                results.append(self._err("Setup", "Load known-revoked certificate", str(exc)))
        if inputs.unknown_ca_cert_path:
            try:
                unknown_ca = _load_cert(inputs.unknown_ca_cert_path)
            except Exception as exc:
                results.append(self._err("Setup", "Load unknown-CA certificate", str(exc)))

        # Choose sample cert for protocol/perf (prefer good -> revoked -> issuer self check)
        sample = good or revoked or issuer

        # Protocol tests (requires a leaf cert ideally)
        try:
            results.extend(run_protocol_tests(inputs.ocsp_url, issuer, sample))
        except Exception as exc:
            results.append(self._err("Protocol", "Run protocol tests", str(exc)))

        # Status tests
        try:
            results.extend(run_status_tests(inputs.ocsp_url, issuer, good, revoked, unknown_ca))
        except Exception as exc:
            results.append(self._err("Status", "Run status tests", str(exc)))

        # Security tests
        try:
            results.extend(run_security_tests(inputs.ocsp_url, issuer, good or sample, inputs.client_sign_cert_path, inputs.client_sign_key_path))
        except Exception as exc:
            results.append(self._err("Security", "Run security tests", str(exc)))

        # Performance tests
        try:
            results.extend(run_perf_tests(inputs.ocsp_url, issuer, sample, inputs.latency_samples, inputs.enable_load_test, inputs.load_concurrency, inputs.load_requests))
        except Exception as exc:
            results.append(self._err("Performance", "Run performance tests", str(exc)))

        # IKEv2 placeholders
        try:
            results.extend(run_ikev2_tests())
        except Exception as exc:
            results.append(self._err("IKEv2", "Run IKEv2 tests", str(exc)))

        return results

    @staticmethod
    def _err(category: str, name: str, msg: str) -> TestCaseResult:
        r = TestCaseResult(id=str(uuid.uuid4()), category=category, name=name, status=TestStatus.ERROR, message=msg)
        r.end()
        return r

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
from .tests_crl import run_crl_tests
from .tests_crl_comprehensive import run_crl_tests as run_crl_comprehensive_tests
from .tests_path_validation import run_path_validation_tests


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
    crl_override_url: Optional[str] = None
    trust_anchor_path: Optional[str] = None
    trust_anchor_type: str = "root"
    require_explicit_policy: bool = False
    inhibit_policy_mapping: bool = False


def _load_cert(path: str) -> x509.Certificate:
    if not path or not path.strip():
        raise ValueError("Certificate path is empty")
    
    if not os.path.exists(path):
        raise FileNotFoundError(f"Certificate file not found: {path}")
    
    try:
        with open(path, "rb") as f:
            data = f.read()
        
        if not data:
            raise ValueError("Certificate file is empty")
            
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            return x509.load_der_x509_certificate(data)
    except Exception as e:
        raise Exception(f"Failed to load certificate from {path}: {str(e)}")


class TestRunner:
    def run_all(self, inputs: TestInputs, test_categories: Optional[dict] = None) -> List[TestCaseResult]:
        results: List[TestCaseResult] = []

        # Validate inputs first
        if not inputs.ocsp_url or not inputs.ocsp_url.strip():
            r = TestCaseResult(id=str(uuid.uuid4()), category="Setup", name="Validate inputs", status=TestStatus.ERROR, message="OCSP URL is required")
            r.end()
            return [r]
        
        if not inputs.issuer_path or not inputs.issuer_path.strip():
            r = TestCaseResult(id=str(uuid.uuid4()), category="Setup", name="Validate inputs", status=TestStatus.ERROR, message="Issuer certificate path is required")
            r.end()
            return [r]

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
        if not test_categories or test_categories.get('ocsp_tests', True):
            try:
                results.extend(run_protocol_tests(inputs.ocsp_url, issuer, sample))
            except Exception as exc:
                results.append(self._err("Protocol", "Run protocol tests", str(exc)))

        # Status tests
        if not test_categories or test_categories.get('ocsp_tests', True):
            try:
                results.extend(run_status_tests(inputs.ocsp_url, issuer, good, revoked, unknown_ca))
            except Exception as exc:
                results.append(self._err("Status", "Run status tests", str(exc)))

        # Security tests
        if not test_categories or test_categories.get('ocsp_tests', True):
            try:
                results.extend(run_security_tests(inputs.ocsp_url, issuer, good or sample, inputs.client_sign_cert_path, inputs.client_sign_key_path))
            except Exception as exc:
                results.append(self._err("Security", "Run security tests", str(exc)))

        # Performance tests
        if not test_categories or test_categories.get('performance_tests', False):
            try:
                results.extend(run_perf_tests(inputs.ocsp_url, issuer, sample, inputs.latency_samples, inputs.enable_load_test, inputs.load_concurrency, inputs.load_requests))
            except Exception as exc:
                results.append(self._err("Performance", "Run performance tests", str(exc)))

        # CRL signature validation tests
        if not test_categories or test_categories.get('crl_tests', True):
            try:
                results.extend(run_crl_tests(inputs.ocsp_url, issuer, good, revoked))
            except Exception as exc:
                results.append(self._err("CRL", "Run CRL tests", str(exc)))

        # Comprehensive CRL tests
        if not test_categories or test_categories.get('crl_tests', True):
            try:
                results.extend(run_crl_comprehensive_tests(inputs.ocsp_url, issuer, good, revoked, inputs.crl_override_url))
            except Exception as exc:
                results.append(self._err("CRL", "Run comprehensive CRL tests", str(exc)))

        # IKEv2 placeholders
        if not test_categories or test_categories.get('ikev2_tests', False):
            try:
                results.extend(run_ikev2_tests())
            except Exception as exc:
                results.append(self._err("IKEv2", "Run IKEv2 tests", str(exc)))

        # Certificate Path Validation tests
        if not test_categories or test_categories.get('path_validation_tests', True):
            try:
                # Prepare test inputs for path validation
                path_validation_inputs = {
                    'ocsp_url': inputs.ocsp_url,
                    'issuer_path': inputs.issuer_path,
                    'good_cert_path': inputs.known_good_cert_path,
                    'revoked_cert_path': inputs.known_revoked_cert_path,
                    'unknown_ca_cert_path': inputs.unknown_ca_cert_path,
                    'crl_override_url': inputs.crl_override_url,
                    'client_cert_path': inputs.client_sign_cert_path,
                    'client_key_path': inputs.client_sign_key_path,
                    'trust_anchor_path': inputs.trust_anchor_path,
                    'trust_anchor_type': inputs.trust_anchor_type,
                    'require_explicit_policy': inputs.require_explicit_policy,
                    'inhibit_policy_mapping': inputs.inhibit_policy_mapping
                }
                results.extend(run_path_validation_tests(path_validation_inputs))
            except Exception as exc:
                results.append(self._err("Path Validation", "Run certificate path validation tests", str(exc)))

        return results

    @staticmethod
    def _err(category: str, name: str, msg: str) -> TestCaseResult:
        r = TestCaseResult(id=str(uuid.uuid4()), category=category, name=name, status=TestStatus.ERROR, message=msg)
        r.end()
        return r
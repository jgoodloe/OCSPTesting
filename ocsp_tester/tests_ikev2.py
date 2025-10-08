import uuid
from typing import List
from .models import TestCaseResult, TestStatus


def run_ikev2_tests() -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    r = TestCaseResult(id=str(uuid.uuid4()), category="IKEv2", name="OCSP Content extension (type 14) support", status=TestStatus.SKIP)
    r.message = "Requires IKEv2 stack/harness; not executable in this tool"
    r.end()
    results.append(r)

    r = TestCaseResult(id=str(uuid.uuid4()), category="IKEv2", name="CERTREQ with encoding 14 elicits CERT with OCSP", status=TestStatus.SKIP)
    r.message = "Requires IKEv2 negotiation environment"
    r.end()
    results.append(r)

    r = TestCaseResult(id=str(uuid.uuid4()), category="IKEv2", name="Trusted responder identification", status=TestCaseResult.__annotations__['status'].__args__[2])  # SKIP
    r.status = TestCaseResult.__annotations__['status'].__args__[2]  # Ensures SKIP without importing enum twice
    r.message = "Requires configured ocsp_signers/CA hashes in IKEv2 environment"
    r.end()
    results.append(r)

    r = TestCaseResult(id=str(uuid.uuid4()), category="IKEv2", name="Configuration mapping (request/reply/both)", status=TestCaseResult.__annotations__['status'].__args__[2])
    r.status = TestCaseResult.__annotations__['status'].__args__[2]
    r.message = "Validate via IKEv2 deployment testing; out of scope for this tool"
    r.end()
    results.append(r)

    return results

#!/usr/bin/env python3
"""Project smoke test, run by CI and by the release gate.

Checks, in order:
  1. Every Python file in the repository byte-compiles.
  2. Every top-level module imports cleanly (app.py only when tkinter
     is available, since it is the GUI entry point).
  3. The core certificate paths work: load the bundled sample CA and
     leaf certificate, verify the chain signature, and build and
     re-parse a DER OCSP request.

Exits non-zero on any failure so a workflow step fails loudly.
"""

import compileall
import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MODULES = [
    "comprehensive_ocsp_analyzer",
    "enhanced_ocsp_signer_extractor",
    "ocsp_check_example",
    "ocsp_demo",
    "ocsp_signature_analysis",
    "ocsp_signature_verifier",
    "ocsp_signer_extractor",
    "ocsp_tester",
    "test_crl_extraction",
    "test_dhs_ca4_enhancement",
    "test_dhs_ca4_trust_chain",
    "test_ocsp_fix",
    "test_ocsp_signer_validation",
]

SKIP_DIRS = re.compile(r"[\\/](\.git|\.github|__pycache__|venv|\.venv|auditenv)([\\/]|$)")


def check_compile() -> bool:
    print("== byte-compiling all Python files ==")
    ok = compileall.compile_dir(str(ROOT), quiet=1, force=True, rx=SKIP_DIRS)
    print("byte-compile:", "OK" if ok else "FAILED")
    return bool(ok)


def check_imports() -> bool:
    print("== importing modules ==")
    sys.path.insert(0, str(ROOT))
    modules = list(MODULES)
    try:
        import tkinter  # noqa: F401
        modules.append("app")
    except ImportError:
        print("SKIP app (tkinter not available in this environment)")
    ok = True
    for name in modules:
        try:
            importlib.import_module(name)
            print("OK  ", name)
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    return ok


def check_crypto_paths() -> bool:
    print("== exercising certificate / OCSP code paths ==")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_request

    ca = x509.load_pem_x509_certificate((ROOT / "sample_ca.pem").read_bytes())
    leaf = x509.load_pem_x509_certificate((ROOT / "sample_cert.pem").read_bytes())
    ca.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )
    print("OK   chain signature verification (sample CA -> sample cert)")

    request = OCSPRequestBuilder().add_certificate(leaf, ca, hashes.SHA1()).build()
    der = request.public_bytes(serialization.Encoding.DER)
    parsed = load_der_ocsp_request(der)
    assert parsed.serial_number == leaf.serial_number
    print(f"OK   OCSP request build/parse round-trip ({len(der)} bytes DER)")
    return True


def main() -> int:
    import cryptography

    print(f"python {sys.version.split()[0]}, cryptography {cryptography.__version__}")
    results = [check_compile(), check_imports(), check_crypto_paths()]
    if all(results):
        print("SMOKE TEST PASSED")
        return 0
    print("SMOKE TEST FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())

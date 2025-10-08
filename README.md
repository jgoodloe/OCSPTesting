## OCSP Server Test Suite (Windows-friendly)

This application runs a structured set of tests against an OCSP server and reports PASS/FAIL/SKIP/ERROR per test with traceable details and exportable results (JSON/CSV).

### Quick Start (Windows)
- Install Python 3.10+
- (Recommended) Create and activate a virtual environment
- pip install -r requirements.txt
- Run GUI: python app.py

### Inputs
- OCSP URL (e.g., http://host/ocsp)
- Issuer CA certificate (PEM/DER)
- Optional: known-good certificate, known-revoked certificate, unknown-CA certificate
- Optional: client signing cert/key for signed-request tests

### Exports
- JSON and CSV exports include a full matrix of results with timestamps and details.

### Notes
- Advanced checks (e.g., signed client requests, IKEv2 in-band OCSP) require additional setup. Tests that cannot be completed will be SKIP with a reason.

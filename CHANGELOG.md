# Changelog

All notable changes to this project are documented in this file.

## [v1.0.1] - 2026-11-08

### Security — updated cryptography dependency

- **Raised the `cryptography` pin from `>=42.0.0,<44.0.0` to `>=49.0.0,<51.0.0`.**
  The old ceiling held installs at cryptography 43.0.3, which has six published
  advisories. Several affect certificate chain validation — directly relevant to
  this tool's OCSP signature verification and trust chain building:
  - PYSEC-2026-3554 (fixed in 49.0.0): wildcard SANs escape CA name constraints
  - PYSEC-2026-3553 (fixed in 49.0.0): exponential blowup resolving chains with
    duplicate self-signed certificates (denial of service)
  - PYSEC-2026-35 (fixed in 46.0.6): DNS name constraints not validated against
    the presented peer name
  - PYSEC-2026-2141 (fixed in 46.0.5): EC public key loading accepts
    small-order subgroup points
  - PYSEC-2026-1284 / GHSA-537c-gmf6-5ccf (fixed in 44.0.1 / 48.0.1): security
    issues in the OpenSSL statically linked into cryptography wheels
- **Existing installs**: run `pip install -r requirements.txt --upgrade` to pick
  up the fixed version; the application code is unchanged and fully compatible.

### Fixed

- **`ocsp_signature_verifier.py` crashed on startup** with an
  `IndentationError` in `display_verification_results` (mis-indented
  overall-result block, present since before v1.0.0).

## [v1.0.0] - 2026-06-15

### Documentation — Windows install instructions reworked

- **Corrected the false claim that Git and OpenSSL are on the Microsoft Store.**
  Neither is published there. Windows installs now use [Scoop](https://scoop.sh)
  for Git and OpenSSL, with Python from the Microsoft Store.
- **Simplified the Quick Setup Guide (Windows)** into a lean, single-terminal
  flow: install Scoop → `scoop install git openssl` → install Python from the
  Store → **download the project ZIP** (Code → Download ZIP) → extract → open the
  folder in a terminal → create venv, install dependencies, and run. Removed the
  Administrator-PowerShell + Chocolatey bootstrap and the `cd`/`mkdir`/`git clone`
  steps.
- **Removed all Chocolatey references** in favor of Scoop across the setup and
  troubleshooting sections.
- **Marked Git as optional** — the download-ZIP workflow no longer requires Git
  to run the tool (only needed for `git clone` or contributing).
- **Added the Microsoft Visual C++ Redistributable note** for the manual slproweb
  OpenSSL installer (resolves `VCRUNTIME140.dll is missing` errors).
- **Verified Windows prerequisites are complete** against the code: the only
  third-party Python dependencies are `cryptography`, `requests`, and
  `asn1crypto` (all pinned in `requirements.txt`); plus the OpenSSL CLI, Python
  3.10+, and `tkinter` (bundled with Python).

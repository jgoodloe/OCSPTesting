import base64
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urljoin, quote

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    load_der_ocsp_response,
    OCSPResponseStatus,
)
from asn1crypto import ocsp as asn1_ocsp, algos as asn1_algos, core as asn1_core


@dataclass
class OCSPRequestSpec:
    cert: x509.Certificate
    issuer: x509.Certificate
    include_nonce: bool = True
    nonce_len: int = 32  # RFC 9654 recommends >=32
    hash_algo: hashes.HashAlgorithm = hashes.SHA1()


@dataclass
class OCSPResponseInfo:
    response_status: str
    cert_status: Optional[str]
    revocation_reason: Optional[str]
    revocation_time: Optional[str]
    this_update: Optional[str]
    next_update: Optional[str]
    produced_at: Optional[str]
    responder_id: Optional[str]
    version: Optional[str]
    signature_algorithm_oid: Optional[str]
    nonce_echoed: Optional[bool]
    raw_der: bytes
    latency_ms: int


def _build_request(spec: OCSPRequestSpec, nonce_bytes: Optional[bytes] = None) -> Tuple[bytes, Optional[bytes]]:
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(spec.cert, spec.issuer, spec.hash_algo)
    used_nonce = None
    if spec.include_nonce:
        used_nonce = nonce_bytes if nonce_bytes is not None else (base64.b16decode(base64.b16encode(b"x" * spec.nonce_len)))
        # cryptography has OCSPNonce helper via x509.OCSPNonce in add_extension
        builder = builder.add_extension(x509.OCSPNonce(used_nonce), critical=False)
    req = builder.build()
    return req.public_bytes(serialization.Encoding.DER), used_nonce


def _encode_get_path(der_request: bytes) -> str:
    b64 = base64.b64encode(der_request).decode("ascii")
    # RFC 6960 GET: base64-encoded, URL-escaped
    return quote(b64, safe="")


def send_ocsp_request(
    url: str,
    spec: OCSPRequestSpec,
    method: str = "POST",
    override_nonce: Optional[bytes] = None,
    timeout: int = 10,
    client_cert: Optional[Tuple[str, str]] = None,  # (cert_path, key_path) if server requires TLS client auth
) -> OCSPResponseInfo:
    der_req, used_nonce = _build_request(spec, override_nonce)

    headers = {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}
    start = time.perf_counter()
    if method.upper() == "GET":
        path = _encode_get_path(der_req)
        # Some servers require trailing slash join; use urljoin carefully
        url_final = url.rstrip("/") + "/" + path
        resp = requests.get(url_final, headers=headers, timeout=timeout, cert=client_cert)
    else:
        resp = requests.post(url, data=der_req, headers=headers, timeout=timeout, cert=client_cert)
    latency_ms = int((time.perf_counter() - start) * 1000)

    resp.raise_for_status()
    der_resp = resp.content

    # Parse high-level via cryptography
    ocsp_resp = load_der_ocsp_response(der_resp)
    status_name = ocsp_resp.response_status.name

    cert_status = None
    rev_reason = None
    rev_time = None
    this_upd = None
    next_upd = None
    if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL and ocsp_resp.responses:
        r0 = ocsp_resp.responses[0]
        cert_status = r0.cert_status.name
        if r0.revocation_reason is not None:
            rev_reason = r0.revocation_reason.name
        if r0.revocation_time is not None:
            rev_time = r0.revocation_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        if r0.this_update is not None:
            this_upd = r0.this_update.strftime("%Y-%m-%dT%H:%M:%SZ")
        if r0.next_update is not None:
            next_upd = r0.next_update.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Use asn1crypto to extract producedAt, responderID, version, signature OID and echoed Nonce
    produced_at = None
    responder_id = None
    version = None
    sig_oid = None
    nonce_echoed = None
    try:
        asn1 = asn1_ocsp.OCSPResponse.load(der_resp)
        if asn1["response_status"].native == "successful":
            basic = asn1["response_bytes"]["response"].parsed  # BasicOCSPResponse
            tbs = basic["tbs_response_data"]
            version = tbs["version"].native  # v1(0)
            produced_at = tbs["produced_at"].native.strftime("%Y-%m-%dT%H:%M:%SZ")
            rid = tbs["responder_id"].chosen
            responder_id = rid.native
            sig_oid = basic["signature_algorithm"]["algorithm"].dotted
            # Check nonce reflection in response extensions
            nonce_echoed = None
            if tbs["response_extensions"].native:
                for ext in tbs["response_extensions"]:
                    if ext["extn_id"].dotted == "1.3.6.1.5.5.7.48.1.2":
                        if used_nonce is None:
                            nonce_echoed = False
                        else:
                            try:
                                # extn_value is OCTET STRING containing the nonce bytes
                                echoed = ext["extn_value"].parsed.native
                                nonce_echoed = (echoed == used_nonce)
                            except Exception:
                                nonce_echoed = False
    except Exception:
        pass

    return OCSPResponseInfo(
        response_status=status_name,
        cert_status=cert_status,
        revocation_reason=rev_reason,
        revocation_time=rev_time,
        this_update=this_upd,
        next_update=next_upd,
        produced_at=produced_at,
        responder_id=str(responder_id) if responder_id is not None else None,
        version=str(version) if version is not None else None,
        signature_algorithm_oid=sig_oid,
        nonce_echoed=nonce_echoed,
        raw_der=der_resp,
        latency_ms=latency_ms,
    )

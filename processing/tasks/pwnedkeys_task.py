"""Task for checking certificates for private keys known to pwnedkeys.com."""

import logging
import re
import time
import traceback
import hashlib
from OpenSSL import crypto
from typing import Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger(__name__)

STATUS_OK = 200
STATUS_NOT_FOUND = 404
STATUS_TOO_MANY_REQUESTS = 429
MAX_DECODE_STEPS = 2  # number of how often the input cert should be base64 decoded if parsing errors occur


def retry_after(api_url: str, headers: dict[str, Any], seconds: int) -> dict[str, Any]:
    """Makes manual retry if api returns 429."""
    time.sleep(seconds)

    try:
        response = requests.get(api_url, headers=headers, timeout=5)
    except Exception as e:
        logger.error(traceback.format_exc())
        return {"error": {"code": "exception", "text": repr(e)}}

    if response.status_code == STATUS_OK:
        jws_response = response.json()
        protected_b64 = jws_response["protected"]
        payload_b64 = jws_response["payload"]
        signature_b64 = jws_response["signature"]
        return {
            "pwned": True,
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }
    elif response.status_code == STATUS_NOT_FOUND:
        return {"pwned": False}
    elif response.status_code == STATUS_TOO_MANY_REQUESTS:
        retry_header = response.headers.get("Retry-After")

        return {
            "error": {
                "code": response.status_code,
                "text": response.text,
                "retry_after": retry_header,
            }
        }
    else:
        return {"error": {"code": response.status_code, "text": response.text}}


def send_pwnedkeys_request(spki_hash: str) -> dict[str, Any]:
    """Sends request to pwnedkeys.com with given spki hash."""
    api_url = f"https://v1.pwnedkeys.com/{spki_hash}"

    s = requests.Session()
    retries = Retry(
        total=10,
        backoff_factor=2,  # 2s, 4s, 8s, 16s, ...
        status_forcelist=[429, 500, 502, 503, 504, 524],
        allowed_methods=frozenset(["GET", "POST"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))

    try:
        response = s.get(api_url)
    except Exception as e:
        logger.error(traceback.format_exc())
        return {"error": {"code": "exception", "text": repr(e)}}

    if response.status_code == STATUS_OK:
        jws_response = response.json()
        protected_b64 = jws_response["protected"]
        payload_b64 = jws_response["payload"]
        signature_b64 = jws_response["signature"]
        return {
            "pwned": True,
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }
    elif response.status_code == STATUS_NOT_FOUND:
        return {"pwned": False}
    elif response.status_code == STATUS_TOO_MANY_REQUESTS:
        retry_header: str = response.headers.get("Retry-After", "0")
        return retry_after(api_url, int(retry_header))
    else:
        return {"error": {"code": response.status_code, "text": response.text}}


def check_base64(input_str: str) -> bool:
    """Checks input for base64 string."""
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

    return base64_pattern.match(input_str) is not None


def compute_spki_hash(pem_format: str):
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_format)
        pub_key = cert.get_pubkey()
        pub_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, pub_key)

        spki_hash = hashlib.sha256(pub_key_der).hexdigest()
        return spki_hash

    except Exception as e:
        return {
            "error": {
                "code": "pyopenssl",
                "text": str(e),
            }
        }


def run(cert_data: dict[str, Any]) -> dict[str, Any] | None:
    """Perform pwnedkeys check on given certificate."""

    if "cert_data" not in cert_data:
        return {"error": {"code": "cert_data", "text": "no cert data provided"}}

    cert = cert_data.get("cert_data")
    base64_cert = (
        cert.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\r", "")
        .replace("\n", "")
    )

    if not check_base64(base64_cert):
        return {
            "error": {
                "code": "base64",
                "text": "certificate data is invalid base64 string",
            }
        }

    pem_format = (
        f"-----BEGIN CERTIFICATE-----\n{base64_cert}\n-----END CERTIFICATE-----"
    )

    spki_hash = compute_spki_hash(pem_format)
    request_result = send_pwnedkeys_request(spki_hash)
    return request_result

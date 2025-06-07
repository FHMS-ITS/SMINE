"""Utilities for input processing."""

import base64
from typing import Any, TypeVar

from processing import jc_parse_relaxed

MAX_INT = 2**63 - 1  # MongoDB can only handle up to 8-byte ints
MAX_B64DECODE_ITERATIONS = 10


def parse_certificate(cert_data: str) -> tuple[str, dict[str, Any], list[str]]:
    """
    Parses a certificate in either pem or der format to a dict, using the jc library.
    Raises CertificateParsingError.
    """
    try:  # noqa SIM105
        cert_data = (
            cert_data.replace("\n", "")
            .replace("\r", "")
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace(" ", "")
            .replace("[", "")
            .replace("]", "")
        )
    except Exception:  # noqa S110
        pass

    iterations = 0
    b64_cert_candidate = cert_data
    byte_cert_candidate = cert_data
    cert_data_history = []
    while iterations < MAX_B64DECODE_ITERATIONS:
        try:
            cert_data_history.append(b64_cert_candidate)
            byte_cert_candidate = base64.b64decode(b64_cert_candidate)
            byte_cert_candidate = (
                byte_cert_candidate.decode()
                .replace("\n", "")
                .replace("\r", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace(" ", "")
                .replace("[", "")
                .replace("]", "")
            )
            b64_cert_candidate = byte_cert_candidate
            cert_candidate = byte_cert_candidate
        except Exception:
            cert_candidate = byte_cert_candidate
            break
        iterations += 1

    ignored_errors = []

    def collect_errors(error) -> None:
        nonlocal ignored_errors
        ignored_errors.append(error)

    try:
        parse_result = jc_parse_relaxed(
            "x509_cert", cert_candidate, error_callback_fct=collect_errors
        )
    except Exception as jc_parsing_ex:
        raise jc_parsing_ex

    # parse returns a list with one entry for some reason
    if isinstance(parse_result, list):
        fields = parse_result[0]
    elif isinstance(parse_result, dict):  # just to be safe
        fields = parse_result
    else:
        raise ValueError(f"Weird parsing result type: {type(parse_result)}")

    cert_data = cert_data_history[-1]
    if isinstance(cert_data, bytes):
        try:
            cert_data = (
                cert_candidate.decode()
                .replace("\n", "")
                .replace("\r", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace(" ", "")
                .replace("[", "")
                .replace("]", "")
            )
        except Exception:
            cert_data = base64.b64encode(cert_candidate).decode()
    return cert_data, fields, ignored_errors


D = TypeVar("D", dict[str, Any], list[Any], int)


def fix_large_ints(data: D) -> D | str:
    """Converts ints that are larger than 8 byte into str for mongodb."""
    if isinstance(data, int):
        if abs(data) > MAX_INT:
            return str(data)
    elif isinstance(data, dict):
        for key, val in data.items():
            data[key] = fix_large_ints(val)
    elif isinstance(data, list):
        for i, val in enumerate(data):
            data[i] = fix_large_ints(val)

    return data

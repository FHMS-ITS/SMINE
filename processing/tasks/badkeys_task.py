"""Task for checking certificates for vulnerable keys with badkeys."""

from base64 import b64decode
from typing import Any, TypeVar

import badkeys  # type: ignore

D = TypeVar("D", dict[str, Any], list[Any], int)
MAX_INT = 2**63 - 1  # MongoDB can only handle up to 8-byte ints
MAX_DECODE_STEPS = 2


def fix_large_ints(data: D) -> D | str:
    """Converts ints that are larger than 8 byte into str for mongodb."""
    if isinstance(data, int):
        if data > MAX_INT:
            return str(data)
    elif isinstance(data, dict):
        for key, val in data.items():
            data[key] = fix_large_ints(val)
    elif isinstance(data, list):
        for i, val in enumerate(data):
            data[i] = fix_large_ints(val)

    return data


def run(cert_data: dict[str, Any]) -> dict[str, Any]:
    """Perform badkeys analysis on given certificate."""
    base64_cert: str = cert_data.get("cert_data", "")

    decode_counter = 0
    while True:
        decode_counter += 1

        if not isinstance(base64_cert, str):
            return {
                "error": {
                    "code": "input_type",
                    "text": f"Certificate data type is {type(base64_cert)!s}. But it has to be string",  # noqa: E501
                }
            }

        base64_cert = (
            base64_cert.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\n", "")
        )

        pem_format = (
            f"-----BEGIN CERTIFICATE-----{base64_cert}-----END CERTIFICATE-----"
        )

        result_data = badkeys.detectandcheck(pem_format)
        r_type = result_data.get("type")
        r_bits = result_data.get("bits")
        r_dict = result_data.get("results")
        r_spki = result_data.get("spkisha256")

        if "unparseable" in r_type:
            if (
                decode_counter < MAX_DECODE_STEPS
            ):  # and if max decode steps counter is not reached
                try:
                    base64_cert = b64decode(
                        base64_cert.encode()
                    ).decode()  # try to decode base64 cert once more
                except Exception as e:
                    return {
                        "error": {
                            "code": "b64_decode",
                            "text": f"Certificate could not be base64 decoded. {e!s}",
                        }
                    }

                if not isinstance(
                    base64_cert, str
                ):  # if it results in binary or something else, then break.
                    # Else continue and try again processing with openssl
                    return {
                        "error": {
                            "code": "input_type",
                            "text": f"Certificate data type is {type(base64_cert)!s}. But it has to be string",  # noqa: E501
                        }
                    }
                else:
                    continue
            break
        break

    return {
        "type": r_type,
        "bits": r_bits,
        "spki": r_spki,
        **({"results": fix_large_ints(r_dict)} if r_dict else {}),
    }

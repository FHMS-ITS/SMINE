"""Task for checking certificates RSA moduli for known factors"""

import logging
from typing import Any, Optional
from factordb.factordb import FactorDB

logger = logging.getLogger(__name__)


def query_factordb(modulus_decimal: int) -> Optional[dict[str, Any]]:
    """Query the Factordb API for the given modulus using FactorDB Python library."""

    try:
        # Connect to FactorDB
        fdb = FactorDB(modulus_decimal)
        fdb.connect()

        # Extract data
        status = fdb.get_status()
        return {"status": status}
    except Exception as e:
        # Return an error dictionary if any exception occurs
        return {
            "error": {
                "code": "FactorDBQueryError",
                "text": str(e),
            }
        }


def factor_key(modulus: str) -> dict[str, Any]:
    """Extract modulus, query Factordb, and append data to certificate."""

    try:
        # Remove colons from the modulus if present
        modulus_cleaned = modulus.replace(":", "").upper()

        try:
            modulus_decimal = int(modulus_cleaned, 16)
        except ValueError:
            # Return an error dictionary if the conversion fails
            return {
                "error": {
                    "code": "InvalidHexadecimal",
                    "text": "The modulus provided is not a valid hexadecimal string",
                }
            }

        # Query FactorDB
        factordb_response = query_factordb(modulus_decimal)
        return factordb_response

    except Exception as e:
        # General exception handling: return a structured error dictionary
        return {
            "error": {
                "code": "UnexpectedError",
                "text": str(e),
            }
        }


def run(cert_data: dict[str, Any]) -> dict[str, Any] | None:
    """Perform factordb check on given certificate."""

    if "cert_fields" not in cert_data:
        return {"error": {"code": "cert_fields", "text": "no cert fields provided"}}

    cert_fields = cert_data.get("cert_fields")

    try:
        rsa_modulus = cert_fields["tbs_certificate"]["subject_public_key_info"][
            "public_key"
        ]["modulus"]
        if not rsa_modulus:
            return {"error": {"code": "modulus", "text": "no modulus found"}}
    except Exception:
        return {"error": {"code": "modulus", "text": "no modulus found"}}

    factordb_result = factor_key(rsa_modulus)

    # FactorDB API error
    if "error" in factordb_result:
        if factordb_result["error"]["code"] == "FactorDBQueryError":
            logger.info(f"API error: {factordb_result['error_message']}")

    return {
        "factordb": factordb_result,
    }

"""Task for checking certificates for smime cab br compliance."""

import functools
import re
from typing import Any

# Cache publicsuffixlist.PublicSuffixList to avoid pkilint reloading it multiple times
import publicsuffixlist

publicsuffixlist.PublicSuffixList = functools.cache(publicsuffixlist.PublicSuffixList)

from pkilint import loader
from pkilint.cabf import smime
from pkilint.pkix import certificate
from pkilint.pkix.certificate import RFC5280Certificate
from pkilint.report import ReportGeneratorJson
from pkilint.validation import ValidationFindingSeverity


def check_base64(input_str: str) -> bool:
    """Checks input for base64 string."""
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

    return base64_pattern.match(input_str) is not None


def run_pkilint(cert: RFC5280Certificate) -> dict[str, Any]:
    validation_level, generation = smime.guess_validation_level_and_generation(cert)
    doc_validator = certificate.create_pkix_certificate_validator_container(
        smime.create_decoding_validators(),
        smime.create_subscriber_validators(validation_level, generation),
    )

    results = doc_validator.validate(cert.root)
    json_gen = ReportGeneratorJson(results, ValidationFindingSeverity.INFO)
    json_gen.generate()
    results_json = json_gen.report_context
    return {
        "certificate_type": f"{validation_level}-{generation}",
        "results": results_json,
    }


def run(cert_data: dict[str, Any]) -> dict[str, Any]:
    """Perform cab br check on certificate."""
    base64_cert: str = cert_data.get("cert_data", "")

    base64_cert = (
        base64_cert.replace("-----BEGIN CERTIFICATE-----", "")
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

    try:
        cert = loader._RFC5280_CERTIFICATE_LOADER.load_b64_document(base64_cert)
    except Exception as ex:
        return {
            "error": {
                "code": "linting",
                "text": f"Failed to load certificate: {ex}",
            }
        }

    try:
        result = run_pkilint(cert)
    except Exception as ex:
        return {
            "error": {
                "code": "linting",
                "text": repr(ex),
            }
        }

    for path in result["results"]:
        for description in path["finding_descriptions"]:
            if description["code"] == "base.unhandled_exception":
                result.update(
                    {
                        "error": {
                            "code": "validator",
                            "text": f"Unhandled exception occurred when executing validator "
                            f"{path['validator']} "
                            f"on node {path['node_path']}: {description['message']}",
                        }
                    }
                )
                return result

    return result

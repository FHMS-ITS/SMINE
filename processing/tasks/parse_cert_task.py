"""Parses certificates."""

from typing import Any

from processing.utils import fix_large_ints, parse_certificate


def run(cert_data: dict[str, Any]) -> dict[str, Any] | None:
    """Parses a certificate."""
    base64_cert: str = cert_data["cert_data"]

    try:
        _cert_data, parsed_fields, ignored_errors = parse_certificate(base64_cert)
        fix_large_ints(parsed_fields)
    except Exception as ex:
        return {"error": repr(ex)}
    else:
        task_result = {
            "cert_fields": parsed_fields,
        }

        if ignored_errors:
            task_result["jc_ignored_error"] = True

        extensions = parsed_fields.get("tbs_certificate", {}).get("extensions")
        if extensions:
            task_result["extensions"] = {
                ext["extn_id"]: {
                    "critical": ext["critical"],
                    "value": ext["extn_value"],
                }
                for ext in extensions
            }
        return task_result

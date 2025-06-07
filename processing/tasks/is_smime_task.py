"""Task for labeling certificates with is_smime."""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def run(cert_data: dict[str, Any]) -> dict[str, Any] | None:  # noqa
    """Check whether the given certificate matches the new conditions."""
    email_address_regex = "^[\\w\\!\\#\\$%&'\\*\\+\\/\\=\\?`\\{\\|\\}~\\^\\.\\-]+@([\\w\\-]+\\.)+[\\w\\-]+$"
    subj_email_address_found = False
    san_email_address_found = False
    eku_email_protection_found = False
    eku_any_extended_key_usage_found = False
    eku_extension_found = False
    ku_digital_signature_found = False
    ku_non_repudiation_found = False
    ku_key_encipherment_found = False
    ku_extension_found = False
    extensions_found = False

    if "cert_fields" not in cert_data:
        return None

    try:
        extensions = cert_data["cert_fields"]["tbs_certificate"]["extensions"]
        if extensions is None:
            logger.debug("Certificate has empty extensions field")
            extensions_found = False
        else:
            extensions_found = True
    except Exception:
        logger.debug("Certificate does not have extensions field")
        extensions_found = False

    # Search for extended_key_usage and subject_alt_name or subject email address
    if extensions_found:
        for extn in extensions:
            extn_id = extn.get("extn_id")

            # Check for extended_key_usage (EKU)
            if extn_id == "extended_key_usage":
                eku_extension_found = True
                extn_value = extn.get("extn_value", [])
                if "email_protection" in extn_value:
                    eku_email_protection_found = True
                    logger.debug("Certificate has email_protection in EKU")
                if "any_extended_key_usage" in extn_value:
                    eku_any_extended_key_usage_found = True
                    logger.debug("Certificate has any_extended_key_usage in EKU")

            # Check for key_usage (KU)
            if extn_id == "key_usage":
                ku_extension_found = True
                extn_value = extn.get("extn_value", [])
                if "digital_signature" in extn_value:
                    ku_digital_signature_found = True
                    logger.debug("Certificate has digital_signature in KU")
                if "non_repudiation" in extn_value:
                    ku_non_repudiation_found = True
                    logger.debug("Certificate has non_repudiation in KU")
                if "key_encipherment" in extn_value:
                    ku_key_encipherment_found = True
                    logger.debug("Certificate has key_encipherment in KU")

            # Check for email address in subject_alt_name
            if extn_id == "subject_alt_name":
                extn_value = extn.get("extn_value", [])
                if isinstance(extn_value, list):
                    extn_value = [v for v in extn_value if isinstance(v, str)]
                    for value in extn_value:
                        if re.match(email_address_regex, value):
                            san_email_address_found = True
                            logger.debug("Found email address in subject_alt_name")
                            break
                elif isinstance(extn_value, str):
                    if re.match(email_address_regex, extn_value):
                        san_email_address_found = True
                        logger.debug("Found email address in subject_alt_name")

    # Check for email address in subject field
    try:
        sub_email_address = cert_data["cert_fields"]["tbs_certificate"]["subject"].get(
            "email_address", ""
        )
        if isinstance(sub_email_address, list):
            sub_email_list = [v for v in sub_email_address if isinstance(v, str)]
            for value in sub_email_list:
                if re.match(email_address_regex, value):
                    subj_email_address_found = True
                    logger.debug("Found email address in subject field")
        elif isinstance(sub_email_address, str):
            if re.match(email_address_regex, sub_email_address):
                subj_email_address_found = True
                logger.debug("Found email address in subject field")
    except Exception:
        logger.debug("No email address found in subject field")

    # Condition 1: (email_protection or any_eku) and email_address and
    # (not ku_extension or digital_signature or non_repudiation or key_encipherment) # noqa ERA001
    if (
        (eku_email_protection_found or eku_any_extended_key_usage_found)
        and (subj_email_address_found or san_email_address_found)
        and (
            not ku_extension_found
            or ku_digital_signature_found
            or ku_non_repudiation_found
            or ku_key_encipherment_found
        )
    ):
        logger.debug(
            "Condition 1 matched: (email_protection or any_eku) and "
            "email_address and (not ku_extension or digital_signature "
            "or non_repudiation or key_encipherment)"
        )
        return {
            "condition": 1,
            "is_smime": True,
            "email_protection": eku_email_protection_found,
            "any_eku": eku_any_extended_key_usage_found,
            "digital_signature": ku_digital_signature_found,
            "non_repudiation": ku_non_repudiation_found,
            "key_encipherment": ku_key_encipherment_found,
            "subj_email": subj_email_address_found,
            "san_email": san_email_address_found,
            "eku_extension": eku_extension_found,
            "ku_extension": ku_extension_found,
            "extensions": extensions_found,
        }

    # Condition 2: Not eku_extension and email_address
    # and (not ku_extension or digital_signature or
    # non_repudiation or key_encipherment)
    if (
        not eku_extension_found
        and (subj_email_address_found or san_email_address_found)
        and (
            not ku_extension_found
            or ku_digital_signature_found
            or ku_non_repudiation_found
            or ku_key_encipherment_found
        )
    ):
        logger.debug(
            "Condition 2 matched: Not eku_extension and email_address "
            "and (not ku_extension or digital_signature or "
            "non_repudiation or key_encipherment)"
        )
        return {
            "condition": 2,
            "is_smime": True,
            "email_protection": eku_email_protection_found,
            "any_eku": eku_any_extended_key_usage_found,
            "digital_signature": ku_digital_signature_found,
            "non_repudiation": ku_non_repudiation_found,
            "key_encipherment": ku_key_encipherment_found,
            "subj_email": subj_email_address_found,
            "san_email": san_email_address_found,
            "eku_extension": eku_extension_found,
            "ku_extension": ku_extension_found,
            "extensions": extensions_found,
        }

    # Condition 3: (email_protection or any_eku) and not email_address
    # and (not ku_extension or digital_signature or non_repudiation or key_encipherment)
    if (
        (eku_email_protection_found or eku_any_extended_key_usage_found)
        and not subj_email_address_found
        and not san_email_address_found
        and (
            not ku_extension_found
            or ku_digital_signature_found
            or ku_non_repudiation_found
            or ku_key_encipherment_found
        )
    ):
        logger.debug(
            "Condition 3 matched: (email_protection or any_eku) and not email_address "
            "and (not ku_extension or digital_signature or "
            "non_repudiation or key_encipherment)"
        )
        return {
            "condition": 3,
            "is_smime": True,
            "email_protection": eku_email_protection_found,
            "any_eku": eku_any_extended_key_usage_found,
            "digital_signature": ku_digital_signature_found,
            "non_repudiation": ku_non_repudiation_found,
            "key_encipherment": ku_key_encipherment_found,
            "subj_email": subj_email_address_found,
            "san_email": san_email_address_found,
            "eku_extension": eku_extension_found,
            "ku_extension": ku_extension_found,
            "extensions": extensions_found,
        }

    # Condition 4: Not eku_extension and not email_address and
    # (not ku_extension or digital_signature or non_repudiation or key_encipherment) # noqa ERA001
    if (
        not eku_extension_found
        and not subj_email_address_found
        and not san_email_address_found
        and (
            not ku_extension_found
            or ku_digital_signature_found
            or ku_non_repudiation_found
            or ku_key_encipherment_found
        )
    ):
        logger.debug(
            "Condition 4 matched: Not eku_extension and not email_address and "
            "(not ku_extension or digital_signature or "
            "non_repudiation or key_encipherment)"
        )
        return {
            "condition": 4,
            "is_smime": True,
            "email_protection": eku_email_protection_found,
            "any_eku": eku_any_extended_key_usage_found,
            "digital_signature": ku_digital_signature_found,
            "non_repudiation": ku_non_repudiation_found,
            "key_encipherment": ku_key_encipherment_found,
            "subj_email": subj_email_address_found,
            "san_email": san_email_address_found,
            "eku_extension": eku_extension_found,
            "ku_extension": ku_extension_found,
            "extensions": extensions_found,
        }

    logger.debug("None of the conditions matched")
    return {
        "condition": 0,
        "is_smime": False,
        "email_protection": eku_email_protection_found,
        "any_eku": eku_any_extended_key_usage_found,
        "digital_signature": ku_digital_signature_found,
        "non_repudiation": ku_non_repudiation_found,
        "key_encipherment": ku_key_encipherment_found,
        "subj_email": subj_email_address_found,
        "san_email": san_email_address_found,
        "eku_extension": eku_extension_found,
        "ku_extension": ku_extension_found,
        "extensions": extensions_found,
    }

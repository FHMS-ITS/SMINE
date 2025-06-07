"""Task for labeling certificates with is_ca."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def run(cert_data: dict[str, Any]) -> bool | None:  # noqa
    if "cert_fields" not in cert_data:
        logger.debug("No cert data")
        return None

    try:
        extensions = cert_data["cert_fields"]["tbs_certificate"]["extensions"]
        if extensions is None:
            logger.debug("Certificate has empty extensions field")
            return None
    except Exception:
        logger.debug("Certificate does not have extensions")
        return None

    for extn in extensions:
        if extn.get("extn_id") == "basic_constraints":
            value = extn.get("extn_value")
            if value is None:
                logger.debug("No values in basic constraints extension")
                return None
            ca_flag = value.get("ca")
            if ca_flag is None:
                logger.debug("No CA value")
                return None
            elif ca_flag is True:
                logger.debug("CA field is set to true")
                return True
            elif ca_flag is False:
                logger.debug("CA field is set to false")
                return False
            else:
                logger.debug(f"CA field is set to {ca_flag}")
                return None

    logger.debug("Certificate does not have basic constraints extension")
    return None

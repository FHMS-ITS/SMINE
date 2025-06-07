"""
Task for reconstructing chain for a given certificate using
our smime-verifier project on github.
"""

import logging
import time
import os
from datetime import datetime
try:
    from datetime import UTC
except ImportError:
    from datetime import timezone
    UTC = timezone.utc  # For Python < 3.11 compatibility
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from smime_chain_verifier.cache.cache import Cache
from smime_chain_verifier.utils.cert import is_root
from smime_chain_verifier.utils.cert_parser import x509CertificateParser

logger = logging.getLogger(__name__)


def connect() -> Cache | None:
    """
    Attempts to establish a connection to the cache (Redis).
    Retries up to `max_attempts` times, using exponential backoff.

    :return: An instance of Cache if successful, otherwise None.
    """
    max_attempts = 3
    attempt = 0
    wait_time = 1

    server_to_connect = os.getenv("REDIS_HOST", "localhost")
    port_to_connect = 6379

    while attempt < max_attempts:
        try:
            cache = Cache(server_to_connect, port_to_connect)
            return cache
        except Exception as e:
            attempt += 1
            logger.warning(
                f"Attempt {attempt} to connect to cache failed: {e}, "
                f"retrying in {wait_time} seconds..."
            )
            if attempt < max_attempts:
                time.sleep(wait_time)
                wait_time *= 2  # Exponential backoff

    logger.error("Max attempts reached. Could not connect to the cache.")
    return None


def disconnect(cache: Cache | None) -> None:
    """
    Closes the connection to the cache.
    :param cache: The Cache instance to disconnect.
    """
    if cache is None:
        return

    try:
        if cache.redis:
            cache.redis.close()
    except Exception as close_error:
        logger.error(f"Error closing redis connection: {close_error}")

    try:
        if cache.redis and cache.redis.connection_pool:
            cache.redis.connection_pool.disconnect()
    except Exception as disconnect_error:
        logger.error(f"Error disconnecting redis connection pool: {disconnect_error}")


def get_cert_chains(cache: Cache, cert: x509.Certificate) -> dict[str, Any] | str:
    """
    Retrieves the certificate chains from the cache and converts them
    to PEM-encoded strings.

    :param cache: A Cache instance.
    :param cert: The x509.Certificate object to look up.
    :return: A dictionary with 'result' (list of lists of PEM strings)
    or 'error' if something fails.
    :raises: ValueError if Cache is None.
    """
    if cache is None:
        raise ValueError("Cache is not allowed to be None")

    try:
        chains = cache.get_cert_chains(cert)
        pem_chains = []

        for chain in chains:
            pem_chain = []
            for cert in chain:
                pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                pem_chain.append(pem)
            pem_chains.append(pem_chain)

        return {"result": pem_chains, "error": None}
    except Exception as error:
        return {
            "result": None,
            "error": f"Error: Unable to retrieve certificate chains: {error}",
        }


def get_historical_status(data: dict[str, Any], current_time: float) -> bool:
    """
    Checks if the certificate is 'historical' based on 'not_after' in the data.

    :param data: Dictionary containing certificate fields under data['cert_fields'].
    :param current_time: Current time as a timestamp (e.g., time.time() or
    datetime.now(timezone.utc).timestamp()).
    :return: 'True' if current_time > not_after, 'False' if within validity,
    or 'Unknown' if the field is missing or
             otherwise cannot be parsed.
    """
    historical = False
    try:
        not_after = data["cert_fields"]["tbs_certificate"]["validity"]["not_after"]
        if current_time > not_after:
            historical = True
    except Exception:
        historical = None
    return historical


def get_validation_result(
    cache: Cache, cert: x509.Certificate, data: dict[str, Any]
) -> dict[str, Any]:
    """
    Validates the certificate using the cache. Also checks if it's historical
    (current_time > not_after).

    :param cache: A Cache instance.
    :param cert: The x509.Certificate to validate.
    :param data: Dictionary containing certificate fields under data['cert_fields'].
    :return: A dictionary with validation results.
    :raises: ValueError if Cache is None.
    """
    if not cache:
        raise ValueError("Cache is not allowed to be None.")

    result_dict = {
        "validation_timestamp": None,
        "validation_result": None,
        "error": None,
        "historical": None,
    }

    current_time = datetime.now(UTC).timestamp()
    result_dict["validation_timestamp"] = current_time

    historical = get_historical_status(data, current_time)
    result_dict["historical"] = historical

    try:
        validation_result = cache.validate(cert)
        result_dict["validation_result"] = str(validation_result.result.name)
        result_dict["error"] = str(validation_result.error)
    except Exception as error:
        result_dict["validation_result"] = "invalid_cert"
        result_dict["error"] = str(error)

    return result_dict


def get_root_information(
    parser: x509CertificateParser, chains: list[list[str]]
) -> dict[str, str] | None:
    """
    Parses each chain, checks if the last certificate is a root certificate,
    and if so returns its data.

    :param parser: An x509CertificateParser instance.
    :param chains: A list of lists of PEM-encoded certificates.
    :return: A dictionary with root information or None if none found.
    """
    if not chains:
        return None

    for chain in chains:
        if not chain:
            continue
        try:
            root_pem = chain[-1]
            cert = parser.parse(root_pem)
            if is_root(cert):
                issuer = cert.issuer
                common_name = None
                organizational_unit_name = None
                organization_name = None

                for attribute in issuer:
                    oid = attribute.oid
                    if oid == x509.NameOID.COMMON_NAME:
                        common_name = attribute.value
                    elif oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                        organizational_unit_name = attribute.value
                    elif oid == x509.NameOID.ORGANIZATION_NAME:
                        organization_name = attribute.value

                return {
                    "pem": root_pem,
                    "common_name": common_name,
                    "organizational_unit_name": organizational_unit_name,
                    "organization_name": organization_name,
                }
        except Exception as e:
            logger.debug(f"Issue parsing cert or checking root: {e}", exc_info=True)

    return None


def get_origin(
    cache: Cache, parser: x509CertificateParser, root_information: dict[str, str]
) -> dict[str, Any] | str:
    """
    Retrieves the origin of the root certificate from the cache.

    :param cache: A Cache instance.
    :param parser: x509CertificateParser instance.
    :param root_information: Dictionary containing "pem" of the root certificate.
    :return: Dictionary with origin or an error string.
    :raises: ValueError if Cache is None.
    """
    if cache is None:
        raise ValueError("Error: Cache is allowed to be None.")
    if not root_information:
        return None
    try:
        pem = root_information.get("pem")
        cert = parser.parse(pem)
        cached_cert = cache.get_cached_cert(cert)
        return cached_cert.origin.create_dict_from_mask()
    except Exception as error:
        return f"Error receiving origin:{error}"


def run(data: dict[str, Any]) -> dict[str, Any] | str:
    """
    Main entry point for certificate checking.

    :param data: Dictionary that contains at least "cert_data".
    :return: Dictionary with certificate chain data and potential errors,
             or an error string if something fails early.
    """
    cache = connect()

    if not cache:
        return "Error: Not able to connect to the redis cache."

    parser = x509CertificateParser()

    try:
        cert_data = data.get("cert_data", "")
        cert = parser.parse(cert_data)
    except Exception as parsing_error:
        disconnect(cache)
        return f"Error parsing the certificate data: {parsing_error}"

    chains = get_cert_chains(cache, cert)
    validation_result = get_validation_result(cache, cert, data)
    if isinstance(chains, dict) and chains.get("result"):
        root_info = get_root_information(parser, chains["result"])
        origin_info = get_origin(cache, parser, root_info)
    else:
        root_info = None
        origin_info = None

    disconnect(cache)

    return {
        "chains": chains,
        "validation": validation_result,
        "root_info": root_info,
        "origin_info": origin_info,
    }

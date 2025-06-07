import argparse
import os
import json
from cryptography.x509 import Certificate
from smime_chain_verifier.cache.cache import Cache
from smime_chain_verifier.utils.cert import is_suitable_for_s_mime
from smime_chain_verifier.bundles.load_crt_bundles import load_crt_bundles
from smime_chain_verifier.logs.set_up_logs import logger
from typing import List
from concurrent.futures import ThreadPoolExecutor

cache = Cache(os.getenv("REDIS_HOSTNAME"))


def init_cache(hostname: str = "localhost", dirpath: str = "crt-bundles") -> None:
    """
    Initialize the cache and store certificate bundles and chains.
    """
    cache = Cache(hostname)
    cache.clear()
    logger.info("Successfully created and cleared cache instance\n")

    logger.info("----- Storing certificates from crt-bundles ------\n")
    _store_crt_bundles(cache, dirpath)
    logger.info("----- Finished storing certificates from crt-bundles ------\n")

    logger.info(
        "----- Attempts to download and store certificates via authority information access -----"
    )
    _store_cache_aia_certs(cache)
    logger.info(
        "----- Finished to download and store certificates via authority information access -----\n"
    )

    logger.info("----- Builds certificate chains -----")
    cache.build_cert_chains()
    logger.info("----- Finished building certificate chains -----\n")

    # TODO: This implementation is not needed any longer
    # logger.info('----- Builds implicit trust -----')
    # cache.build_implicit_trust()
    # logger.info('----- Finished building implicit trust -----\n')


# TODO: Remove this code not needed any longer
def _load_config(filepath: str) -> dict:
    """
    Loads the configuration from a JSON file.
    """
    try:
        with open(filepath) as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading configuration: {e}")
        return {}


def _store_certs(cache: Cache, certs: List[Certificate], origin: str) -> int:
    """
    Process and store certificates in the cache.

    For each certificate, this function checks if it is suitable for S/MIME.
    If so, it attempts to store it.

    Certificates that are already stored will not be duplicated.

    If a certificate already exists, the origin will be added if not present.

    Args:
        cache (Cache): The cache instance to store the certificates.
        certs (List[Certificate]): The list of certificates to process.
        origin (str): A crt bundle name, the source of the certificate.

    Returns:
        int: The number of certificates successfully stored.
    """
    stored_certificates = 0
    for cert in certs:
        if not is_suitable_for_s_mime(cert):
            logger.debug(f"Certificate {cert} is not suitable for S/MIME.")
            continue

        stored_origin = cache.get_origin(cert)
        stored_origin.set_bit(origin)

        if cache.store_cert(cert, None, stored_origin.calculate_bit_mask(), True):
            stored_certificates += 1
        else:
            logger.debug(f"Failed to store certificate:{cert}")

    return stored_certificates


def _store_crt_bundles(cache: Cache, dirpath: str = "crt-bundles") -> None:
    """
    Load certificate bundles and store them in the cache.
    Ensures trusted certificates are processed first.

    Args:
        cache (Cache): The cache object.
        dirpath (str): Directory path containing the certificate bundles and config.
    """
    crt_bundles = load_crt_bundles(dirpath)

    total_saves = 0

    for filename, certs in crt_bundles:
        successful_saves = _store_certs(cache, certs, filename)
        total_saves += successful_saves
        logger.info(
            f"We added {successful_saves} certificates in the cache based on: {filename}"
        )

    logger.info(
        f"In total {total_saves} certificates have been stored in the cache through the given crt-bundles."
    )


def _store_cache_aia_certs(cache: Cache, max_iterations: int = 10):
    """
    Load certificates via database access locations and store them in the cache.
    """
    total_saves = 0
    count_new_al = 0
    for iteration in range(max_iterations):
        # Get the difference between access locations of cached certificates and already cached access locations
        new_access_locations = (
            cache.get_access_locations_of_cached_certificates()
            - cache.get_cached_access_locations()
        )

        if not new_access_locations:
            break

        logger.debug(new_access_locations)
        count_new_al += len(new_access_locations)
        previous_cache_size = cache.size()

        with ThreadPoolExecutor() as executor:

            def process_access_location(access_location):
                cache.store_access_location(access_location)
                cache.store_cert_by_access_location(access_location)

            executor.map(process_access_location, new_access_locations)

        new_saves = cache.size() - previous_cache_size
        total_saves += new_saves
        logger.info(
            f"Iteration {iteration}: Found {len(new_access_locations)} new access_locations and added successfully {new_saves} new certificates to the cache."
        )

    logger.info(
        f"Successfully downloaded and stored {total_saves} new certificates from {count_new_al} aia extensions."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Initialize the cache with certificates."
    )

    cache = Cache("redis")

    _store_cache_aia_certs(cache)

    print("stored aia certs")

    cache.build_cert_chains()

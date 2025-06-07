from typing import List, Optional, Set, Union
from cryptography.x509 import Certificate
from redis import Redis
from smime_chain_verifier.cache.cached_certificate import CachedCertificate
from smime_chain_verifier.utils.cert import (
    get_cert_key,
    get_issuer_hash,
    get_subject_hash,
    get_access_locations,
    is_root,
    convert_to_pem,
)
from smime_chain_verifier.utils.request_cert import request_certificate
from smime_chain_verifier.utils.validation import (
    CertificateValidationResult,
    ValidationResult,
    validate_chain,
)
from smime_chain_verifier.logs.set_up_logs import logger
from smime_chain_verifier.bundles.crt_bundle_mask import CrtBundleMask


class Cache:
    """
    A class to manage caching of certificates and access locations using Redis.
    """

    KEY_ACCESS_LOCATIONS = "access_locations"

    def __init__(self, hostname="redis", port=6379):
        self.redis = Redis(hostname, port)

    def size(self) -> int:
        """
        Returns:
            int: The numbers of keys in the cache.
        """
        return self.redis.dbsize()

    def get_keys(self) -> List[str]:
        """
        Returns:
            List[str]: All keys in the database.
        """
        all_keys = self.redis.keys("*")
        return [key.decode("utf-8") for key in all_keys]

    def clear(self) -> int:
        """
        Clears all data from the Redis cache and returns the number of deleted entries.

        Returns:
            int: The number of keys that were deleted.
        """
        db_size = self.redis.dbsize()
        self.redis.flushdb()
        return db_size

    def exists(self, cert: Certificate) -> bool:
        """
        Checks if a given certificate exists in the Redis cache.

        Args:
            cert (Certificate): The certificate to check for existence.

        Returns:
            bool: True if the certificate exists in the Redis cache, False otherwise.
        """
        ca_key = get_cert_key(cert)
        return self.redis.exists(ca_key)

    def store_cert(
        self,
        cert: Certificate,
        chains: Optional[List[List[Certificate]]] = None,
        origin: Optional[Union[int, str]] = None,
        overwrite: bool = False,
    ) -> bool:
        """
        Stores a certificate in the Redis cache.

        Args:
            cert (Certificate): The certificate to store.
            chains (Optional[List[List[Certificate]]]): The certificate chains related to this certificate.
            origin: Optional value of the origin of the certificate either a crt bundle mask (int) or a crt bundle name (string).
            overwrite (bool): Whether to overwrite the certificate if it already exists in the cache.

        Returns:
            bool: True if the certificate was successfully stored, False otherwise.
        """
        ca_key = get_cert_key(cert)
        if not ca_key:
            logger.critical("No ca_key could be derived from the certificate.")
            return False

        if overwrite or not self.redis.exists(ca_key):
            cached_cert = CachedCertificate(cert, origin, chains)
            result = self.redis.set(ca_key, cached_cert.to_redis())
            if result:
                return True
            else:
                logger.critical(f"Failed to store certificate {cert} in Redis.")
                return False
        else:
            logger.debug(f"Certificate {ca_key} already exists and overwrite=False.")
            return False

    def store_cert_by_access_location(self, access_location: str) -> bool:
        """
        Retrieves and stores a certificate by its access location.

        Args:
            access_location (str): The access location of the certificate.

        Returns:
            bool: True if the certificate was successfully retrieved and stored, False otherwise.
        """
        try:
            cert = request_certificate(access_location)
        except Exception as error:
            logger.error(
                f"Unable to successfully request certificate from {access_location}: {error}"
            )
            return False

        return self.store_cert(cert)

    def __load_certs_by_key_pattern(
        self, pattern: str
    ) -> Optional[List[CachedCertificate]]:
        """
        Retrieve certificates from the cache that match the given key pattern.

        Args:
            pattern (str): The pattern used to match keys in the cache.

        Returns:
            Optional[List[CachedCertificate]]: A list of matching CachedCertificate objects, or None if no matches are found.
        """
        matching_keys = self.redis.keys(pattern)

        if not matching_keys:
            return None

        return [
            CachedCertificate.from_redis(self.redis.get(key).decode("utf-8"))
            for key in matching_keys
        ]

    def load_cas(self, cert: Certificate) -> Optional[List[CachedCertificate]]:
        """
        Loads cached certificates associated with the given certificate's issuer.

        Warning: This method might return the same CA Certificate (identical issuer and subject) twice.
        Because the fingerprint of the CA Certificate is different (e.g., other extensions, validity periods).

        Args:
            cert (Certificate): The certificate whose issuers need to be loaded.

        Returns:
            Optional[List[CachedCertificate]]: List of cached certificates, if found.
        """
        if is_root(cert):
            return None

        pattern = f"*:{get_issuer_hash(cert)}:*"
        return self.__load_certs_by_key_pattern(pattern)

    def load_issued_certs(self, cert: Certificate) -> Optional[List[CachedCertificate]]:
        """
        Load cached certificates issued to the given certificate's subject.

        Args:
            cert (Certificate): The certificate whose issued certificates need to be loaded.

        Returns:
            Optional[List[CachedCertificate]]: A list of cached certificates issued to the subject, or None if none are found.
        """
        pattern = f"*:*:{get_subject_hash(cert)}"
        return self.__load_certs_by_key_pattern(pattern)

    def store_access_location(self, access_location: str) -> None:
        """
        Stores an access location in the cache.

        Args:
            access_location (str): The access location to store.
        """
        self.redis.sadd(self.KEY_ACCESS_LOCATIONS, access_location)

    def is_access_location_cached(self, access_location: str) -> bool:
        """
        Checks if an access location exists in the cache.

        Args:
            access_location (str): The access location to check.

        Returns:
            bool: True if the access location exists, False otherwise.
        """
        return self.redis.sismember(self.KEY_ACCESS_LOCATIONS, access_location)

    def get_cached_access_locations(self) -> Set[str]:
        """
        Retrieves all stored access locations.

        Returns:
            Set[str]: A set of access locations.
        """
        access_locations_bytes = self.redis.smembers(self.KEY_ACCESS_LOCATIONS)
        return {
            access_location.decode("utf-8")
            for access_location in access_locations_bytes
        }

    def get_cached_cert(self, cert: Certificate) -> Optional[CachedCertificate]:
        """
        Retrieve a cached representation of the given certificate, if it exists.

        Args:
            cert (Certificate): The certificate to look up in the cache.

        Returns:
            Optional[CachedCertificate]: The cached representation of the certificate if found,
            otherwise None.
        """
        data = self.redis.get(get_cert_key(cert))
        if data:
            return CachedCertificate.from_redis(data.decode("utf-8"))
        return None

    def get_origin(self, cert: Certificate) -> CrtBundleMask:
        """
        Retrieve the stored bit mask for a given certificate key.

        Args:
            cert_key (str): The certificate key.

        Returns:
            int: The stored bit mask if available, otherwise 0.
        """
        cert_key = get_cert_key(cert)
        data = self.redis.get(cert_key)
        if data:
            cached_cert = CachedCertificate.from_redis(data.decode("utf-8"))
            return cached_cert.origin
        return CrtBundleMask()

    def get_cached_certs(self) -> List[CachedCertificate]:
        """
        Retrieves all cached certificates from the cache.

        Returns:
            List[CachedCertificate]: A list of all cached certificates.
        """
        cursor = 0
        certs = []

        while True:
            cursor, keys = self.redis.scan(cursor=cursor)
            for key in keys:
                if key.decode("utf-8") == self.KEY_ACCESS_LOCATIONS:
                    continue
                if self.redis.type(key) == b"string":
                    data = self.redis.get(key)
                else:
                    # not a valid key
                    continue
                if data:
                    cached_cert = CachedCertificate.from_redis(data.decode("utf-8"))
                    certs.append(cached_cert)
            if cursor == 0:
                break

        return certs

    def get_certs(self) -> List[Certificate]:
        """
        Retrieves all certificates from the cache.

        Returns:
            List[Certificate]: A list of all certificates stored in the cache.
        """
        return [item.cert for item in self.get_cached_certs()]

    def get_trusted_certs(self) -> List[Certificate]:
        """
        Retrieves all trusted certificates from the cache.

        Returns:
            List[Certificate]: A list of all trusted certificates stored in the cache.
        """
        return list({cert.cert for cert in self.get_cached_certs() if cert.is_trusted})

    def get_access_locations_of_cached_certificates(self) -> Set[str]:
        """
        Retrieves all access locations associated with cached certificates.

        Returns:
            List[str]: A list of access locations.
        """
        access_locations = set()
        for cert in self.get_certs():
            access_locations.update(get_access_locations(cert))
        return set(access_locations)

    def get_cert_chains(self, cert: Certificate) -> Optional[List[List[Certificate]]]:
        """
        Retrieves certificate chains associated with a given certificate.

        Args:
            cert (Certificate): The certificate whose chains need to be retrieved.

        Returns:
            List[Optional[List[Certificate]]]: A list of certificate chains.
        """
        chains = None
        cached_certs = self.load_cas(cert)
        if cached_certs:
            chains = []
            for cached_cert in cached_certs:
                for chain in cached_cert.chains:
                    chains.append(chain)
        return chains

    def build_cert_chains(self):
        """
        Builds the certificate chain of each cached certificate.
        All known and available CAs have to be cached.
        """
        for cached_cert in self.get_cached_certs():
            cert_key = get_cert_key(cached_cert.cert)
            logger.debug(f"Building cert chains for {cert_key}:")
            chains = self.__build_cert_chains(cached_cert.cert)
            for chain in chains:
                logger.debug(chain)
            successful = self.store_cert(
                cached_cert.cert, chains, cached_cert.origin.calculate_bit_mask(), True
            )
            if not successful:
                logger.critical(f"Failed to overwrite cached certificate: {cert_key}")

    def __build_cert_chains(
        self, cert: Certificate, max_iterations: int = 10
    ) -> List[List[Certificate]]:
        """
        Builds a chain of certificates starting from a given certificate.

        Args:
            cert (Certificate): The starting certificate.
            max_iterations (int): The maximum number of iterations to extend the chains. Defaults to 10.

        Returns:
            List[List[Certificate]]: A list of certificate chains.
        """
        if cert is None:
            raise ValueError("The input certificate cannot be None.")

        chains = [[cert]]
        for iteration in range(max_iterations):
            new_chains = self.__add_next_cas(chains, iteration)
            # Stop if no new chains are added.
            if chains == new_chains:
                break
            chains = new_chains

        return chains

    def __add_next_cas(
        self, chains: List[List[Certificate]], iteration: int
    ) -> List[List[Certificate]]:
        """
        Extends certificate chains by appending additional certificates
        from the cache based on the last certificate in each chain.

        Args:
            chains (List[Certificate]): A list of certificate chains, where
                each chain is a list of certificates.
            iteration (int): Current iteration to avoid unnecessary operations.

        Returns:
            List[Certificate]: A list of extended certificate chains.
        """
        if not chains:
            return []

        extended_chains = []

        for chain in chains:
            last_certificate = chain[-1]

            if iteration >= len(chain) or is_root(last_certificate):
                extended_chains.append(chain)
            else:
                next_cas = self.__get_unique_issuer(self.load_cas(last_certificate))

                if next_cas:
                    for next_ca in next_cas:
                        # Avoid recursive chaining A.issuer == B.subject and B.issuer == A.subject!
                        if not self.__is_present(chain, next_ca.cert):
                            extended_chains.append(chain + [next_ca.cert])
                else:
                    # If no cas were found, finalize the construction process.
                    extended_chains.append(chain)

        return extended_chains

    def __is_present(self, certs: List[Certificate], cert: Certificate):
        """
        Determine if a certificate with the same subject as the given certificate exists in the list.

        Args:
            certs (List[Certificate]): The list of certificates to search through.
            cert (Certificate): The certificate whose subject will be compared.

        Returns:
            bool: True if a certificate with the same subject is found, False otherwise.

        Note:
            Certificates may have the same subject but diff in other attributes.
            This method checks for presence based solely on the subject attribute.
        """
        for c in certs:
            # Certificates might have the same subject but differ in other attributes like issuer.
            if c.subject == cert.subject:
                return True
        return False

    def __get_unique_issuer(
        self, cas: List[CachedCertificate]
    ) -> List[CachedCertificate]:
        """
        Return a list of unique certificates based on their issuer.

        Args:
            cas (List[CachedCertificate]): The list of certificates to process.

        Returns:
            List[CachedCertificate]: A list containing only the first occurrence of a certificate
            per issuer.
        """
        if cas is None:
            return []

        seen_issuers = set()
        unique = []

        for item in cas:
            # If this issuer hasn't been seen before, include the certificate
            if item.cert.issuer not in seen_issuers:
                unique.append(item)
                seen_issuers.add(item.cert.issuer)

        return unique

    def build_implicit_trust(self, max_iterations: int = 10) -> None:
        """
        Establish implicit trust for certificates issued by trusted Certificate Authorities (CAs).

        If a CA is explicitly trusted, all certificates issued by that CA are implicitly trusted,
        provided they meet the following criteria:

        1. The certificate is valid (i.e., it has not expired and passes all required validation checks).
        2. The certificate is properly signed by the trusted CA.

        The process is iterative, allowing the trust relationships to propagate. During each iteration,
        the function identifies certificates that can be implicitly trusted based on their issuing CA
        and stores them as trusted certificates. The loop continues for a maximum number of iterations
        specified by `max_iterations` or until no new certificates can be implicitly trusted.

        Args:
            max_iterations (int): The maximum number of iterations to propagate implicit trust. Default is 10.

        Returns:
            None
        """
        previous_trusted_certs = len(self.get_trusted_certs())
        for iteration in range(max_iterations):
            trusted_certs: List[Certificate] = self.get_trusted_certs()

            issued_certs = set()
            for cert in trusted_certs:
                issued_certs.update(self.load_issued_certs(cert) or [])

            # Determine which certificates can be implicitly trusted
            certs_with_implicit_trust: Set[CachedCertificate] = {
                cert for cert in issued_certs if not cert.is_trusted
            }

            logger.info(
                f"Iteration {iteration}: Found {len(certs_with_implicit_trust)} certificates that can be trusted implicitly."
            )
            logger.debug([cert.cert.subject for cert in certs_with_implicit_trust])

            if not certs_with_implicit_trust:
                break

            for cert in certs_with_implicit_trust:
                success = self.store_cert(cert.cert, cert.chains, True, True)
                if not success:
                    logger.critical(
                        f"CRITICAL: Build implicit trust failed to overwrite {cert}."
                    )
        logger.info(
            f"Trusting now {len(self.get_trusted_certs())} instead {previous_trusted_certs} of total {len(self.get_certs())} certificates."
        )

    def is_trusted(self, cert: Certificate) -> bool:
        """
        Determines if a given certificate is trusted based on cached information.

            Args:
                cert: The certificate to check.
            Returns:
                True if the certificate is trusted, False otherwise.
        """
        cached_cert = self.get_cached_cert(cert)
        return cached_cert.is_trusted if cached_cert else False

    def validate(self, cert: Certificate) -> CertificateValidationResult:
        """
        Validates a certificate against its possible chains and aggregates the results.

            Args:
                cert: The certificate to validate.
            Returns:
                A CertificateValidationResult instance representing the aggregated validation outcome.
        """
        chains = self.get_cert_chains(cert)

        if not chains:
            return CertificateValidationResult(ValidationResult.INVALID_CNF, "")

        final_result = CertificateValidationResult(ValidationResult.INVALID_CNF, "")
        for chain in chains:
            if not chain:
                continue
            pem_chain = [convert_to_pem(c) for c in chain]
            result = validate_chain([convert_to_pem(cert)] + pem_chain)
            final_result.update(result)

        return final_result

import json
from typing import Optional, List, Union
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import serialization
from smime_chain_verifier.utils.cert_parser import x509CertificateParser
from smime_chain_verifier.utils.cert import is_root
from smime_chain_verifier.bundles.crt_bundle_mask import CrtBundleMask


class CachedCertificate:
    """
    Represents a cached certificate, possibly with its certificate chain.

    - Root certificates have `chain` set to an empty list.
    """

    def __init__(
        self,
        cert: Certificate,
        origin: Optional[Union[int, str]] = None,
        chains: Optional[List[List[Certificate]]] = None,
    ):
        """
        Initialize the CachedCertificate instance.

        :param cert: The main certificate object.
        :param origin: Optional initial value for the CrtBundleMask, either an int or a string.
        :param chains: A list of certificate chains, where each chain is a list of certificates.
        """
        # Validate argument types
        if not isinstance(cert, Certificate):
            raise TypeError(
                f"ERROR: cert must be an instance of x509.Certificate, got {type(cert).__name__}."
            )
        if chains is not None:
            if not isinstance(chains, list) or not all(
                isinstance(chain, list) for chain in chains
            ):
                raise TypeError(
                    "ERROR: chains must be a list of lists of Certificate objects."
                )
            for chain in chains:
                if not all(isinstance(cert_item, Certificate) for cert_item in chain):
                    raise TypeError(
                        "ERROR: Each chain must be a list of x509.Certificate objects."
                    )

        self.cert = cert
        self.origin = CrtBundleMask(initial_bitmask=origin)
        self.chains = chains or []
        self.is_root = is_root(cert)

    def to_redis(self) -> str:
        """
        Serializes the CachedCertificate instance into a JSON string for storage in Redis.

        :return: JSON string representation of the CachedCertificate.
        """
        data = {
            "is_root": self.is_root,
            "origin": self.origin.calculate_bit_mask(),
            "pem": self.cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        }
        if self.chains:
            data["chains"] = [
                [
                    cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                    for cert in chain
                ]
                for chain in self.chains
            ]
        return json.dumps(data)

    @classmethod
    def from_redis(cls, redis_data: str) -> "CachedCertificate":
        """
        Deserializes the CachedCertificate instance from a JSON string retrieved from Redis.

        :param redis_data: JSON string representation of the CachedCertificate.
        :return: An instance of CachedCertificate.
        """
        data = json.loads(redis_data)
        parser = x509CertificateParser()

        cert_pem = data["pem"].encode("utf-8")
        cert = parser.parse(cert_pem)

        chains = None
        if "chains" in data:
            chains = [
                [parser.parse(cert_pem.encode("utf-8")) for cert_pem in chain]
                for chain in data["chains"]
            ]

        origin = data.get("origin", 0)

        return cls(cert, origin, chains)

    def get_bit_mask(self) -> int:
        """
        Return the bit mask calculated by the `origin` attribute.

        Returns:
            int: The calculated bit mask.

        Raises:
            AttributeError: If `origin` does not have a `calculate_bit_mask` method.
        """
        if not hasattr(self.origin, "calculate_bit_mask"):
            raise AttributeError(
                "The 'origin' attribute must have a 'calculate_bit_mask' method."
            )

        return self.origin.calculate_bit_mask()

import base64
from typing import Union, List
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)
from cryptography.x509 import (
    load_der_x509_certificate,
    load_pem_x509_certificate,
    Certificate,
)
from smime_chain_verifier.utils.cert import is_malformed, format_to_pem


class CertificateParsingError(Exception):
    """Custom exception for errors during certificate parsing."""

    pass


class x509CertificateParser:
    def parse(self, cert_data: Union[str, bytes]) -> Certificate:
        """
        Parses a certificate in various formats (PEM, DER, PEM PKCS7, DER PKCS7).

        Args:
            cert (Union[str, bytes]): The certificate data as a string or bytes.

        Returns:
            Certificate: The parsed X509 certificate object.

        Raises:
            CertificateParsingError: If the certificate cannot be parsed or is malformed.
        """
        errors = []
        for binary in self._build_binary_representations(cert_data):
            for parser in [
                self._parse_pem_x509,
                self._parse_der_x509,
                self._parse_pem_pkcs7,
                self._parse_der_pkcs7,
            ]:
                try:
                    result = parser(binary)
                    if is_malformed(result):
                        raise CertificateParsingError("Malformed certificate.")
                    return result

                except Exception as error:
                    errors.append(error)

        raise CertificateParsingError(
            f"Unable to parse cert_data: {cert_data}. Encountered following errors: {errors}"
        )

    def _build_binary_representations(
        self, cert_data: Union[str, bytes]
    ) -> List[bytes]:
        """
        Returns a list of different possible binary representation of the given data.

        Args:
            cert (Union[str, bytes]): Certificate as string or bytes.

        Returns:
            List[bytes]: The certificate data in bytes.
        """
        representations = []
        if isinstance(cert_data, str):
            representations.append(cert_data.encode())
            representations.append(format_to_pem(cert_data))
            try:
                representations.append(base64.b64decode(cert_data))
            except Exception:
                pass
        if isinstance(cert_data, bytes):
            representations.append(cert_data)
        return representations

    def _parse_pem_x509(self, binary: bytes) -> Certificate:
        """
        Attempts to parse a certificate in PEM X509 format.
        """
        return load_pem_x509_certificate(binary)

    def _parse_der_x509(self, binary: bytes) -> Certificate:
        """
        Attempts to parse a certificate in DER X509 format.
        """
        return load_der_x509_certificate(binary)

    def _parse_pem_pkcs7(self, binary: bytes) -> Certificate:
        """
        Attempts to parse a certificate in PEM PKCS7 format.
        """
        p7certs = load_pem_pkcs7_certificates(binary)
        if not p7certs:
            raise CertificateParsingError("Empty PKCS7 certificate.")
        return p7certs[0]

    def _parse_der_pkcs7(self, binary: bytes) -> Certificate:
        """
        Attempts to parse a certificate in DER PKCS7 format.
        """
        p7certs = load_der_pkcs7_certificates(binary)
        if not p7certs:
            raise CertificateParsingError("Empty PKCS7 certificate.")
        return p7certs[0]


def parse_certificate(cert_path):
    """
    Loads an X.509 certificate from a PEM file

        :param
            cert_path: Path to the certificate file

        :return:
            An x509.Certificate object
    """
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    return x509CertificateParser().parse(cert_data)

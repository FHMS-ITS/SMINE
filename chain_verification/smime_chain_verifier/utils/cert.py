from cryptography.x509 import Certificate, Name, Extension, BasicConstraints
from cryptography.hazmat.primitives import hashes, serialization
from hashlib import sha1
from typing import Type, List

OID_AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1"
OID_CA_ISSUER = "1.3.6.1.5.5.7.48.2"
OID_EXTENDED_KEY_USAGE = "2.5.29.37"
OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"


def is_malformed(cert: Certificate) -> bool:
    """
    Checks if a certificate is malformed.

    A certificate is considered malformed if:
    1. Its issuer or subject is not a valid Name object or has an invalid string representation.
    2. It contains extensions that are not valid Extension objects.

    Args:
        cert (Certificate): The certificate to validate.

    Returns:
        bool: True if the certificate is malformed, False otherwise.
    """
    try:
        if (
            not isinstance(cert.issuer, Name)
            or not cert.issuer.rfc4514_string().strip()
        ):
            return True

        if (
            not isinstance(cert.subject, Name)
            or not cert.subject.rfc4514_string().strip()
        ):
            return True

        for ext in get_extensions(cert):
            if not isinstance(ext, Extension):
                return True

    except Exception:
        # If raised the certificate is malformed.
        return True

    return False


def is_root(cert: Certificate) -> bool:
    """
    Check if a certificate is a root certificate by ensuring it is self-signed.

    Args:
        cert (Certificate): The certificate to check.

    Returns:
        bool: True if the certificate is self-signed, False otherwise.
    """
    return cert.subject == cert.issuer


def is_root_strict(cert: Certificate) -> bool:
    """
    Check if a certificate is a root CA certificate.

    Conditions:
    1. The certificate must be self-signed (subject == issuer).
    2. The Basic Constraints extension must indicate that the certificate is a CA.

    Args:
        cert (Certificate): The certificate to check.

    Returns:
        bool: True if the certificate is a root CA certificate, False otherwise.
    """
    if cert.subject != cert.issuer:
        return False

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            BasicConstraints
        ).value
        return basic_constraints.ca
    except Exception:
        # The Basic Constraints extension is not found or another error occurred.
        return False


def get_cert_fingerprint(
    cert: Certificate, hash_algorithm: Type[hashes.HashAlgorithm] = hashes.SHA256
) -> str:
    """
    Compute the fingerprint of an x509 certificate using the specified hash algorithm.

    Args:
        cert (x509.Certificate): The certificate to fingerprint.
        hash_algorithm (Type[hashes.HashAlgorithm]): The hash algorithm to use (default: SHA256).

    Returns:
        str: The fingerprint of the certificate as a hexadecimal string.
    """
    if not isinstance(cert, Certificate):
        raise TypeError(
            f"Expected cert to be an x509.Certificate, got {type(cert).__name__}"
        )
    return cert.fingerprint(hash_algorithm()).hex()


def get_issuer_hash(cert: Certificate, hash_function=sha1) -> str:
    """
    Compute the hash of the issuer's RFC4514 string representation.

    Args:
        cert (x509.Certificate): The certificate whose issuer hash is needed.
        hash_function (callable): The hashing function to use (default: sha1).

    Returns:
        str: The hexadecimal hash of the issuer's RFC4514 string.
    """
    if not isinstance(cert, Certificate):
        raise TypeError(
            f"Expected cert to be an x509.Certificate, got {type(cert).__name__}"
        )
    issuer_string = cert.issuer.rfc4514_string()
    return hash_function(issuer_string.encode()).hexdigest()


def get_subject_hash(cert: Certificate, hash_function=sha1) -> str:
    """
    Compute the hash of the subject's RFC4514 string representation.

    Args:
        cert (x509.Certificate): The certificate whose subject hash is needed.
        hash_function (callable): The hashing function to use (default: sha1).

    Returns:
        str: The hexadecimal hash of the subject's RFC4514 string.
    """
    if not isinstance(cert, Certificate):
        raise TypeError(
            f"Expected cert to be an x509.Certificate, got {type(cert).__name__}"
        )
    subject_string = cert.subject.rfc4514_string()
    return hash_function(subject_string.encode()).hexdigest()


def get_cert_key(cert: Certificate) -> str:
    """
    Generate a unique key for a certificate by combining its fingerprint,
    subject hash, and issuer hash.

    Args:
        cert (Certificate): The certificate for which the key is generated.

    Returns:
        str: A string in the format "cert_hash:subject_hash:issuer_hash" if successful.

    Raises:
        ValueError: If the certificate's fingerprint, subject hash, or issuer hash cannot be generated.
    """
    cert_hash = get_cert_fingerprint(cert)
    subject_hash = get_subject_hash(cert)
    issuer_hash = get_issuer_hash(cert)

    if not cert_hash or not subject_hash:
        raise ValueError(
            "Failed to generate cert key: subject hash or cert fingerprint is missing."
        )

    return f"{cert_hash}:{subject_hash}:{issuer_hash}"


def get_access_locations(cert: Certificate) -> List[str]:
    """
    Extract access locations (URLs or other identifiers) from the Authority Information
    Access (AIA) extension in a certificate.

    Args:
        cert (Certificate): The x509 certificate.

    Returns:
        List[str]: A list of access locations related to the CA issuer.
    """
    for extension in get_extensions(cert):
        if extension.oid.dotted_string == OID_AUTHORITY_INFORMATION_ACCESS:
            # Ensure _descriptions exists
            if not hasattr(extension.value, "_descriptions"):
                return []

            return [
                description.access_location.value
                for description in extension.value._descriptions
                if description.access_method.dotted_string == OID_CA_ISSUER
            ]
    return []


def convert_to_pem(cert: Certificate):
    """Converts an x509.Certificate object to PEM format.

    Args:
        cert (x509.Certificate): The certificate to convert.

    Returns:
        bytes: The certificate in PEM format.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def format_to_pem(cert_data: str) -> bytes:
    """
    Converts a single-line base64 string to a valid PEM-formatted certificate in bytes.
    :param cert_data: The base64 encoded string of the certificate
    :return: PEM-formatted certificate as bytes
    """
    lines = [cert_data[i : i + 64] for i in range(0, len(cert_data), 64)]

    pem_certificate = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE-----\n"
    )
    return pem_certificate.encode("utf-8")


def is_suitable_for_s_mime(cert: Certificate):
    """
    Checks if the given X.509 certificate is suitable for S/MIME (email protection).

    The method verifies that when the certificate has an Extended Key Usage extension
    it also includes the email protection OID. False otherwise.

    Args:
        cert (Certificate): The X.509 certificate to evaluate.

    Returns:
        bool: True if the certificate is suitable for S/MIME, False otherwise.
    """
    for extension in get_extensions(cert):
        if extension.oid.dotted_string == OID_EXTENDED_KEY_USAGE:
            if OID_EMAIL_PROTECTION not in [
                oid.dotted_string for oid in extension.value._usages
            ]:
                return False

    return True


def get_extensions(cert: Certificate) -> List[Extension]:
    """
    A error safe method to retrieves the extensions from a given certificate.

    Args:
        cert (Certificate): The certificate object from which to extract extensions.

    Returns:
        List[Extension]: A list of extensions extracted from the certificate.
                         Returns an empty list if no extensions are found or an error occurs.
    """
    extensions = []
    try:
        extensions = cert.extensions
    except Exception:
        pass
    return extensions

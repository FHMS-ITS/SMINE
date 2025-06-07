from cryptography.x509 import Certificate
from cryptography.x509.verification import PolicyBuilder, Store
from smime_chain_verifier.logs.set_up_logs import logger
from smime_chain_verifier.utils.cert import is_root
from enum import Enum
from OpenSSL import crypto


class InvalidValidationResult(Exception):
    """Exception raised for invalid certificate validation results."""

    pass


class ValidationResult(Enum):
    INVALID_CERT = 1
    INVALID_CNF = 2
    INVALID_CF = 3
    VALID = 4


class CertificateValidationResult:
    """
    Represents the result of a certificate validation process.

    Attributes:
        result (ValidationResult): The validation result.
        error (str): Error message associated with the validation result.
    """

    def __init__(
        self,
        result: ValidationResult,
        error: str,
    ):
        self.result = result  # Use the passed ValidationResult value
        self.error = error  # Store the passed error string

    def update(self, new_result: "CertificateValidationResult"):
        """
        Updates the validation result if the new result has a higher severity.

        Args:
            new_result (CertificateValidationResult): The new validation result to compare.
        """
        if self.result.value < new_result.result.value:
            self.result = new_result.result
            self.error = new_result.error


class ValidationError(Exception):
    """Custom exception raised when validator creation fails."""

    pass


def x509_chain_validation_deprecated(chain: list[Certificate]) -> bool:
    """
    Validates a certificate chain and returns the validation result.

        :param
            chain: A list of certificates forming the chain, ordered from end-entity to root.

        :return
            CertificateValidationResult indicating the outcome of the validation.

        :raises
            ValidationError: Chain must include at least leaf and root certificates.
    """
    leaf = chain[0]
    intermediates = chain[1:-1]
    root = [chain[-1]]
    store = Store(root)
    builder = PolicyBuilder().store(store)
    verifier = builder.build_client_verifier()
    try:
        verifier.verify(leaf, intermediates)
        return True
    except Exception as error:
        logger.debug(f"Validation failed because of: {error}")
        return False


def validate_chain_deprecated(
    chain: list[Certificate], is_trusted: bool
) -> CertificateValidationResult:
    """
    Validates a certificate chain and returns the validation result.

        :param
            chain: A list of certificates forming the chain, ordered from end-entity to root.
            is_trusted: Indicates if the root certificate is trusted.

        :return
            CertificateValidationResult indicating the outcome of the validation.

        :raises
            ValidationError: Chain must include at least leaf and root certificates.
    """
    logger.debug(f"Validation of certificate chain:\n{chain}")
    if len(chain) < 2:
        logger.error("Error: Chain must include at least leaf and root certificates.")
        raise ValidationError(
            "Error: Chain must include at least leaf and root certificates."
        )
    if not is_root(chain[-1]):
        logger.debug("Validation failed: Not a root certificate.")
        return CertificateValidationResult(False, False, False)
    if x509_chain_validation_deprecated(chain):
        if is_trusted:
            logger.debug("Validation successful.")
            return CertificateValidationResult(True, True, True)
        else:
            logger.debug("Validation successful but untrusted root certificate.")
            return CertificateValidationResult(True, True, False)
    return CertificateValidationResult(True, False, False)


def validate_chain(chain: list) -> CertificateValidationResult:
    """
    Validates a certificate chain and returns the validation result.

        :param
            chain: A list of certificates forming the chain, ordered from end-entity to root.
            is_trusted: Indicates if the root certificate is trusted.

        :return
            ValidationResult indicating the outcome of the validation.

        :raises
            ValidationError: Chain must include at least leaf and root certificates.
    """
    logger.debug(f"Validation of certificate chain:\n{chain}")

    if len(chain) < 2:
        return CertificateValidationResult(
            ValidationResult.INVALID_CNF,
            "Chain must include at least a leaf and root certificate.",
        )

    try:
        leaf = crypto.load_certificate(crypto.FILETYPE_PEM, chain[0])

        store = crypto.X509Store()
        for pem in chain[1:]:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
            store.add_cert(cert)

        # Disable time checks
        store.set_flags(0x200000)

        ctx = crypto.X509StoreContext(store, leaf)

        ctx.verify_certificate()
        return CertificateValidationResult(ValidationResult.VALID, "")
    except crypto.X509StoreContextError as context_error:
        return CertificateValidationResult(ValidationResult.INVALID_CF, context_error)
    except Exception as error:
        return CertificateValidationResult(ValidationResult.INVALID_CF, error)

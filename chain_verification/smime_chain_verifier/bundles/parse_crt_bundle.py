from smime_chain_verifier.logs.set_up_logs import logger
from smime_chain_verifier.utils.cert_parser import x509CertificateParser
from typing import List
from cryptography.x509 import Certificate


def parse_crt_bundle(file_path: str) -> List[Certificate]:
    """
    Parses a CRT bundle file that contains multiple certificates concatenated together.

    Args:
        file_path (str): The path to the CRT bundle file.

    Returns:
        List[Certificate]: A list of Certificate objects parsed from the file.
    """
    parser = x509CertificateParser()
    certificates = []
    current_cert_lines = []
    inside_cert = False

    parsed_successful = 0
    parsing_errors = 0

    logger.info(f"Started to parse certificates from file: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            # Check for the beginning of a certificate
            if "-----BEGIN CERTIFICATE-----" in line:
                inside_cert = True
                current_cert_lines = [line]  # Start a new cert block
                continue

            # If we're inside a cert block, collect lines
            if inside_cert:
                current_cert_lines.append(line)
                # When we reach the end of the certificate, parse it
                if "-----END CERTIFICATE-----" in line:
                    pem_data = "".join(current_cert_lines).strip()
                    try:
                        cert = parser.parse(pem_data)
                        certificates.append(cert)
                        parsed_successful += 1
                    except Exception as error:
                        logger.error(
                            f"Error parsing certificate from {file_path}: {error}"
                        )
                        parsing_errors += 1
                    # Reset state for next certificate
                    inside_cert = False
                    current_cert_lines = []

    logger.info(
        f"Parsed {parsed_successful} of {parsed_successful + parsing_errors} certificates from {file_path} successfully."
    )

    return certificates

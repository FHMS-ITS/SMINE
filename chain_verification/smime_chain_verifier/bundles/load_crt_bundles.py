from cryptography.x509 import Certificate
from smime_chain_verifier.utils.files import get_files
from smime_chain_verifier.bundles.parse_crt_bundle import parse_crt_bundle
from smime_chain_verifier.logs.set_up_logs import logger
from typing import List, Tuple


def load_crt_bundles(
    dirpath: str = "crt-bundles",
) -> List[Tuple[str, List[Certificate]]]:
    """
    Load all certificate bundles from the specified directory.
    Returns a list of tuples containing the filename and the list of certificates.
    """
    crt_bundles = []
    for filename in get_files(dirpath, "*.crt"):
        try:
            file_path = f"{dirpath}/{filename}"
            certs = parse_crt_bundle(file_path)
            crt_bundles.append((filename, certs))
        except FileNotFoundError as e:
            logger.error(f"File not found: {filename}, Error: {e}")
        except Exception as e:
            logger.error(f"Error processing file {filename}: {e}")
    return crt_bundles

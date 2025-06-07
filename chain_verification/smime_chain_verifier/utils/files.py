from pathlib import Path
from typing import List


def get_files(folder_path: str, pattern: str) -> List[str]:
    """
    Retrieves the filenames of all files from the specified folder that match the given pattern.

    Args:
        folder_path (str): The path to the folder from which to retrieve files.
        pattern (str): The file pattern to match (e.g., '*.txt', '*.pem').

    Returns:
        List[str]: A list of filenames (without the full path) of the matching files.
    """
    folder = Path(folder_path)

    if not folder.exists():
        raise FileNotFoundError(f"The folder '{folder_path}' does not exist.")
    if not folder.is_dir():
        raise NotADirectoryError(f"The path '{folder_path}' is not a directory.")

    # Extract filenames (not full paths) of matching files
    matching_files = [file.name for file in folder.glob(pattern)]

    return matching_files


def extract_certificates(file_path):
    """
    Extracts all certificates from a file containing multiple PEM certificates.

    Args:
        file_path (str): Path to the file containing PEM certificates.

    Returns:
        list: A list of strings, where each string is a full PEM certificate block.
    """
    certs = []
    with open(file_path, "r") as file:
        cert_data = []
        inside_cert = False

        for line in file:
            if "-----BEGIN CERTIFICATE-----" in line:
                inside_cert = True
                cert_data = [line.strip()]
            elif "-----END CERTIFICATE-----" in line:
                cert_data.append(line.strip())
                certs.append("\n".join(cert_data))
                inside_cert = False
            elif inside_cert:
                cert_data.append(line.strip())

    return certs

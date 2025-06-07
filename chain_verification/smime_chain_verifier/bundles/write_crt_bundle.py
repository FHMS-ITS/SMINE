import json
import csv
import argparse
from typing import List, Union
from smime_chain_verifier.utils.cert_parser import x509CertificateParser
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import serialization


def read_certs_from_csv(input_file, pem_column_name) -> List[Certificate]:
    """Extracts PEM data from a CSV files files using a specified column name
       and writes it to a single CSV file.

    Args:
        input_fils (list): Input CSV file path.
        pem_column_name (str): The name of the column containing PEM data.
    """
    certs = []
    with open(input_file, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cert_data = row.get(pem_column_name)
            if cert_data:
                try:
                    certs.append(parser.parse(cert_data))
                except Exception as error:
                    # IMPORTANT !!!

                    # Reason for Losing Some CAs:
                    # We encounter the following error:
                    # ValueError: error parsing asn1 value: ParseError { kind: EncodedDefault, location: ["Certificate::tbs_cert", "TbsCertificate::raw_extensions", 0, "Extension::critical"] }

                    # This error occurs because the certificate's ASN.1 structure improperly includes the 'critical' field within the first extension of the tbsCertificate, even though it's set to its default value (False). According to the Distinguished Encoding Rules (DER), fields with default values must be omitted entirely from the encoding. While lenient tools like OpenSSL may accept such certificates, strict parsers like Python's cryptography library enforce DER compliance and thus raise parsing errors when encountering these improperly encoded fields.
                    print(
                        f'Failed to parse cert_data "{cert_data}" with the following error: {str(error)}'
                    )
    return certs


def read_certs_from_json(file_path) -> Union[List[Certificate], List[Exception]]:
    """Reads and parses certificates from a JSON file.

    Args:
        file_path (str): The path to the JSON file containing certificate data.

    Returns:
        tuple: A tuple containing a list of parsed certificates and the number of failed parses.
    """
    with open(file_path, "r") as file:
        data = json.load(file)
    parser = x509CertificateParser()
    certs = []
    errors = []
    for item in data:
        cert_data = item.get("cert_data")
        if cert_data:
            try:
                certs.append(parser.parse(cert_data))
            except Exception as error:
                # IMPORTANT !!!

                # Reason for Losing Some CAs:
                # We encounter the following error:
                # ValueError: error parsing asn1 value: ParseError { kind: EncodedDefault, location: ["Certificate::tbs_cert", "TbsCertificate::raw_extensions", 0, "Extension::critical"] }

                # This error occurs because the certificate's ASN.1 structure improperly includes the 'critical' field within the first extension of the tbsCertificate, even though it's set to its default value (False). According to the Distinguished Encoding Rules (DER), fields with default values must be omitted entirely from the encoding. While lenient tools like OpenSSL may accept such certificates, strict parsers like Python's cryptography library enforce DER compliance and thus raise parsing errors when encountering these improperly encoded fields.
                errors.append(
                    f'Failed to parse cert_data "{cert_data}" with the following error: {str(error)}'
                )
        else:
            raise Exception("No cert_data found in JSON object.")
    return certs, errors


def convert_to_pem(cert: Certificate):
    """Converts an x509.Certificate object to PEM format.

    Args:
        cert (x509.Certificate): The certificate to convert.

    Returns:
        bytes: The certificate in PEM format.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def write_pem_bundle(output_file, pem_list):
    """Writes a list of PEM-formatted certificates to a file.

    Args:
        output_file (str): The file path where the PEM certificates will be written.
        pem_list (list): A list of certificates in PEM format.
    """
    with open(output_file, "wb") as file:
        for pem in pem_list:
            if isinstance(pem, str):
                file.write(pem.encode("utf-8"))
            else:
                file.write(pem)
            file.write(b"\n")


def main(input_files, output_file):
    """Processes certificates from JSON and CSV files and outputs a PEM bundle.

    Args:
        input_files (list): List of input file paths (JSON or CSV).
        output_file (str): Path to the output file for the PEM bundle.
    """
    certs = []

    for file in input_files:
        try:
            if file.endswith(".json"):
                certs.extend(read_certs_from_json(file))
            elif file.endswith(".csv"):
                certs.extend(read_certs_from_csv(file))
            else:
                print(f"Unsupported file format: {file}. Skipping.")
        except Exception as e:
            print(f"Failed to process file {file} with error: {e}")

    pem_data = [convert_to_pem(ca) for ca in certs]

    write_pem_bundle(output_file, pem_data)
    print(f"PEM bundle written to {output_file}")


if __name__ == "__main__":
    # Example arrays for input and output files. If set, these override command-line arguments.
    input_files_array = [
        # Uncomment and provide file paths here if using arrays
        # "file1.csv", "file2.csv", "file3.csv"
    ]
    output_file = None

    if input_files_array and output_file:
        # Use predefined arrays for input and output
        main(input_files_array, output_file)
    else:
        # Use command-line arguments
        parser = argparse.ArgumentParser(
            description="Process certificates from CSV files and output PEM bundles."
        )
        parser.add_argument(
            "--input_files",
            nargs="+",
            required=True,
            help="List of paths to input CSV / JSON files.",
        )
        parser.add_argument("--output_file", required=True, help="Output file path.")
        parser.add_argument(
            "--pem_column_name",
            default="X.509 Certificate (PEM)",
            help='Optional column name for PEM data. Default is "X.509 Certificate (PEM)".',
        )
        args = parser.parse_args()

        # Parse command-line arguments
        main(args.input_files, args.output_file, args.pem_column_name)

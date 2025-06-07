from base64 import b64encode
from pathlib import Path
from time import time
import logging
import base64

logger = logging.getLogger()

MAX_B64DECODE_ITERATIONS = 10
CERTIFICATE_ATTRIBUTES_TO_DECODE = [
    "userCertificate;binary",
    "userCertificate",
    "userSMIMECertificate;binary",
    "userSMIMECertificate",
    "cACertificate;binary",
    "cACertificate",
    "crossCertificatePair;binary",
    "crossCertificatePair",
]


def make_hashable(obj):
    """Recursively converts a nested dict into a hashable structure."""
    if isinstance(obj, dict):
        # Convert the dict into a frozenset of key-value tuples
        return frozenset((key, make_hashable(value)) for key, value in obj.items())
    elif isinstance(obj, (list, tuple, set)):
        # Recursively handle other iterable types
        return tuple(make_hashable(item) for item in obj)
    else:
        # Return the object itself if it's not a dict or iterable
        return obj


def make_unhashable(obj):
    """Recursively converts a hashable structure back into a nested dict."""
    if isinstance(obj, frozenset):
        # Convert frozenset of key-value pairs back to a dictionary
        return {key: make_unhashable(value) for key, value in obj}
    elif isinstance(obj, tuple):
        # Recursively process elements in a tuple
        return [make_unhashable(item) for item in obj]
    else:
        # Return the object itself if it's not a frozenset or tuple
        return obj


def decode(ldap_response, save=True, attributes_to_decode=list()):
    """Decodes the downloaded LDAP entries"""
    logger.info("Decoding crawling results")
    decoded_response = []
    timestamp = time()
    not_in = set()
    for i, entry in enumerate(ldap_response):
        decoded_entry = {}
        # The distinguished name (dn) uniquely identifies an entry and describes its position in the directory information tree (dit).
        entry_dn = entry[0]
        # Each entry comes with a set of attributes.
        entry_attributes = entry[1]

        if not isinstance(entry_attributes, dict):
            logger.warning(
                f"Found attribut which is not dict, instead type: {type(entry_attributes)}"
            )
            continue

        # Encode and save certificates.
        if len(attributes_to_decode) == 0:
            attributes_to_decode = CERTIFICATE_ATTRIBUTES_TO_DECODE
        attributes_to_decode_lower = [attr.lower() for attr in attributes_to_decode]
        for entry_attribute, entry_value in entry_attributes.items():
            attribute_name_lower = entry_attribute.lower()
            if (
                attribute_name_lower in attributes_to_decode_lower
                or attribute_name_lower.endswith(";binary")
            ):
                if attribute_name_lower not in attributes_to_decode_lower:
                    not_in.add(entry_attribute)
                certificates = []
                for cert in entry_value:
                    cert = b64encode(cert)
                    certificates.append(cert)
                if save:
                    save_certificates(timestamp, i, entry_value)
                entry_attributes[entry_attribute] = certificates

        # UTF-8 decode byte-string attributes.
        entry_attributes = decode_dict(entry_attributes)
        entry_attributes = normalize_attribute_values(entry_attributes)
        # Build decoded response.
        decoded_entry["dn"] = entry_dn
        decoded_entry["attributes"] = entry_attributes
        decoded_response.append(decoded_entry)
    if len(not_in):
        logger.warning("Found binary attributes not in list: %s", not_in)
    return decoded_response


def decode_dict(dict, encoding="utf=8"):
    for key, value in dict.items():
        if isinstance(value, (list, tuple)):
            decoded_value = []
            for item in value:
                if isinstance(item, bytes):
                    try:
                        decoded_value.append(item.decode(encoding))
                    except Exception:
                        logger.exception(
                            f"Error occured while decoding bytes for {key}: {item}"
                        )
                        try:
                            decoded_value.append(
                                b64encode(item).decode("utf-8")
                            )  # Fallback: Use base64
                        except Exception:
                            # This should never happen
                            logger.exception(
                                f"Error occured while b64encoding bytes for {key}."
                            )
                else:
                    # not a byte string
                    decoded_value.append(item)
                dict[key] = decoded_value
        elif isinstance(value, bytes):
            try:
                dict[key] = value.decode("utf-8")
            except Exception:
                logger.exception(
                    f"Error occured while decoding bytes for {key}: {value}"
                )
                try:
                    dict[key] = b64encode(value).decode("utf-8")  # Fallback: Use base64
                except Exception:
                    # This should never happen
                    logger.exception(
                        f"Error occured while b64encoding bytes for {key}."
                    )
    return dict


def normalize_attribute_values(dict):
    for key, value in dict.items():
        if isinstance(value, (list, tuple)):
            normalized_value_list = []
            for item in value:
                try:
                    normalized_value_list.append(format_certificate(item))
                except Exception:
                    normalized_value_list.append(item)

                dict[key] = normalized_value_list
        elif isinstance(value, bytes):
            try:
                normalized_value = format_certificate(value)
            except Exception:
                normalized_value = value

            dict[key] = normalized_value

    return dict


def format_certificate(cert_data: str):
    """
    Certificates on LDAP servers may be stored in various encodings.
    This function attempts to convert a certificate to a base64-encoded format.
    Raises CertificateParsingError.
    """

    try:  # noqa SIM105
        cert_data = (
            cert_data.replace("\n", "")
            .replace("\r", "")
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace(" ", "")
            .replace("[", "")
            .replace("]", "")
        )
    except Exception:  # noqa S110
        pass

    iterations = 0
    b64_cert_candidate = cert_data
    byte_cert_candidate = cert_data
    cert_data_history = []
    while iterations < MAX_B64DECODE_ITERATIONS:
        try:
            cert_data_history.append(b64_cert_candidate)
            byte_cert_candidate = base64.b64decode(b64_cert_candidate.encode())
            byte_cert_candidate = (
                byte_cert_candidate.decode()
                .replace("\n", "")
                .replace("\r", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace(" ", "")
                .replace("[", "")
                .replace("]", "")
            )
            b64_cert_candidate = byte_cert_candidate
            cert_candidate = byte_cert_candidate
        except Exception:
            cert_candidate = byte_cert_candidate
            break
        iterations += 1

    cert_data = cert_data_history[-1]
    if isinstance(cert_data, bytes):
        try:
            cert_data = (
                cert_candidate.decode()
                .replace("\n", "")
                .replace("\r", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace(" ", "")
                .replace("[", "")
                .replace("]", "")
            )
        except Exception:
            cert_data = base64.b64encode(cert_candidate).decode()

    return cert_data


def save_certificates(id, i, certificates):
    path = "certs/" + str(id) + "/"
    check_dir(path)
    for i2, cert in enumerate(certificates):
        print(path + str(i) + "_" + str(i2) + ".cer")
        with open(path + str(i) + "_" + str(i2) + ".cer", "wb") as file:
            file.write(cert)


def check_dir(path):
    Path(f"./{path}").mkdir(parents=True, exist_ok=True)

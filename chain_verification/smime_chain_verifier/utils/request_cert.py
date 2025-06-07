from cryptography.x509 import Certificate
from urllib.parse import unquote, urlparse
from ldap3 import ALL, Connection, Server
from typing import Optional, Union
import requests
from smime_chain_verifier.utils.cert_parser import x509CertificateParser
from typing import cast

LDAP_DEFAULT_SCOPE = "SUBTREE"
LDAP_DEFAULT_PORT = 389
LDAP_DEFAULT_CA_CERT_ATTRIBUTE = "cACertificate"


class CertificateSearchError(Exception):
    """Custom exception for LDAP certificate search errors."""

    pass


class LDAPCertificateSearch:
    def __init__(self, ldap_url: str):
        """
        Initialize the LDAPCertificateSearch with an LDAP URL.

        Args:
            ldap_url (str): The LDAP URL to search certificates.

        Raises:
            ValueError: If the LDAP URL is invalid or missing.
        """
        if not ldap_url:
            raise ValueError("LDAP URL is mandatory and cannot be None")

        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.dn: Optional[str] = None
        self.attribute: Optional[str] = None
        self.scope: Optional[str] = None
        self.filter: Optional[str] = None

        self._parse_ldap_url(ldap_url)

    def _parse_ldap_url(self, ldap_url: str) -> None:
        """
        Parse the LDAP URL and extract its components.

        Args:
            ldap_url (str): The LDAP URL to parse.

        Raises:
            ValueError: If the URL format is invalid or missing components.
        """
        try:
            parsed_url = urlparse(ldap_url)
            if not parsed_url.netloc:
                raise ValueError("No host defined in the LDAP URL.")

            # Extract host and port
            host, port = (parsed_url.netloc.split(":") + [None])[:2]
            self.host = f"{parsed_url.scheme}://{host}"
            self.port = int(port) if port else LDAP_DEFAULT_PORT

            # Extract DN and filter
            path = unquote(parsed_url.path.lstrip("/"))
            self.filter, self.dn = path.split(",", 1)

            # Extract query parts for attributes and scope
            query_parts = (parsed_url.query.split("?") + [None] * 3)[:3]
            self.attribute = query_parts[0]
            if not self.attribute:
                self.attribute = LDAP_DEFAULT_CA_CERT_ATTRIBUTE
            if query_parts[1] is not None:
                self._parse_scope(query_parts[1])
            else:
                self.scope = LDAP_DEFAULT_SCOPE
        except Exception as e:
            raise ValueError(f"Failed to parse LDAP URL: {e}") from e

    def _parse_scope(self, scope: str) -> None:
        """
        Parse the LDAP scope string and map it to a valid LDAP scope.

        Args:
            scope (str): The scope string ("base", "one", "sub").

        """
        scope_map = {"base": "BASE", "one": "LEVEL", "sub": "SUBTREE"}
        self.scope = scope_map.get(scope, "BASE")

    def search_certificate(self) -> Optional[str]:
        """
        Search for a certificate in the LDAP directory.

        Returns:
            Optional[str]: The certificate value if found, otherwise None.

        Raises:
            CertificateSearchError: If the search fails due to invalid setup, connection issues,
                                     or other errors.
        """
        if not self.host or not self.dn:
            raise CertificateSearchError(
                "Invalid setup for search: Host or DN is missing."
            )

        try:
            # Set up LDAP server and connection
            server = Server(self.host, self.port, get_info=ALL, connect_timeout=10)
            conn = Connection(server, receive_timeout=10)
            conn.bind()

            # Perform the search
            conn.search(self.dn, f"({self.filter})", attributes=["*"])
            certificate = conn.entries[0][self.attribute] if conn.entries else None
            conn.unbind()

            return certificate.value if certificate else None
        except ValueError as ve:
            raise CertificateSearchError(f"Invalid search parameters: {ve}") from ve
        except ConnectionError as ce:
            raise CertificateSearchError(
                f"Connection to LDAP server failed: {ce}"
            ) from ce
        except Exception as e:
            raise CertificateSearchError(
                f"Failed to load certificate from LDAP server: {e}"
            ) from e


def fetch_certificate_via_ldap(access_location: str) -> bytes:
    """
    Fetch a certificate from an LDAP access location.

    Args:
        access_location (str): The LDAP URL.

    Returns:
        bytes: The certificate data in bytes.
    """
    return LDAPCertificateSearch(access_location).search_certificate()


def fetch_certificate_via_http(access_location: str) -> bytes:
    """
    Fetch a certificate from an HTTP or HTTPS access location.

    Args:
        access_location (str): The HTTP/HTTPS URL.

    Returns:
        bytes: The certificate data in bytes.

    Raises:
        ValueError: If the request fails or the response content is empty.
    """
    try:
        response = requests.get(access_location, timeout=10)
        response.raise_for_status()  # Ensure the HTTP request was successful
        if not response.content:
            raise ValueError("HTTP response content is empty")
        return response.content
    except requests.exceptions.RequestException as e:
        raise ValueError(f"Failed to fetch certificate via HTTP: {e}")


def request_certificate(access_location: str) -> Certificate:
    """
    Request a certificate from a given access location.

    Args:
        access_location (str): The access location URL.

    Returns:
        Certificate: The parsed x509 Certificate.

    Raises:
        ValueError: If the access method is unknown or the certificate cannot be fetched.
        CertificateParsingError: If the cert_data cannot be parsed.
    """
    if access_location.startswith("ldap"):
        cert_data: Union[bytes, None] = fetch_certificate_via_ldap(access_location)
    elif access_location.startswith(("http", "https")):
        cert_data = fetch_certificate_via_http(access_location)
    else:
        raise ValueError(f"Unknown access method for location: {access_location}")

    if not cert_data:
        raise ValueError("Certificate not found or is empty")

    return cast(Certificate, x509CertificateParser().parse(cert_data))

import unittest
from unittest.mock import MagicMock
from cryptography.x509 import Name, BasicConstraints, ObjectIdentifier
from smime_chain_verifier.utils.cert import *
from smime_chain_verifier.utils.cert_parser import x509CertificateParser


class TestCertificateFunctions(unittest.TestCase):
    def setUp(self):
        # Mock a malformed certificate (invalid subject and issuer)
        self.malformed_cert = MagicMock()
        self.malformed_cert.subject = MagicMock(spec=Name)
        self.malformed_cert.issuer = MagicMock(spec=Name)
        self.malformed_cert.subject.rfc4514_string.side_effect = ValueError(
            "Malformed subject"
        )
        self.malformed_cert.issuer.rfc4514_string.side_effect = ValueError(
            "Malformed issuer"
        )

        # Mock a valid root certificate
        self.root_cert = MagicMock()
        self.root_cert.subject = MagicMock(spec=Name)
        self.root_cert.issuer = self.root_cert.subject
        self.root_cert.subject.rfc4514_string.return_value = (
            "CN=Test, O=Test Org, L=Test City, ST=Test State, C=US"
        )
        self.root_cert.extensions.get_extension_for_class.return_value = MagicMock(
            value=BasicConstraints(ca=True, path_length=None)
        )

        # Mock a non-root certificate (subject != issuer, CA flag)
        self.non_root_cert = MagicMock()
        self.non_root_cert.subject = MagicMock(spec=Name)
        self.non_root_cert.issuer = MagicMock(spec=Name)
        self.non_root_cert.subject.rfc4514_string.return_value = (
            "CN=Test Subject, O=Test Org"
        )
        self.non_root_cert.issuer.rfc4514_string.return_value = (
            "CN=Test Issuer, O=Test Org"
        )
        self.root_cert.extensions.get_extension_for_class.return_value = MagicMock(
            value=BasicConstraints(ca=True, path_length=None)
        )

        # Valid test certificate.
        self.pem = """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUfKEPFRxQ0Fo3IR5/lvDDNF6Wfe4wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDExMjMxNDU4MDdaFw0yNTEx
MjMxNDU4MDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCnC+XUjZ6PKb+Z81a7A8G2OM5fhMVCELkzE3p2BOsF
7vJbl7xcu2X6eCc/HIzml7Qv3AZJFQ2rI5nu86gx4vf+xwDcBmmS4tJOUC0mBbZf
77TIb7mhzHAWcfRO6+VwWHpFINbNUFCzsZUkNMz8XCgct+fx1L7EU6FTqzuU5xUB
KgHVKJuGCypGZ0jrkTzGhRnAj9kkyDJhdlJOX7noFB9o7hfPAbxQOfRkM4gfmoMs
8Jngz88xR7tf3B1ksANuA4Op560ohQu9inXi1suBvdol8ms+GOScoGagDZLrVCzL
BQIVKTHJgMLPMo4qCfbu6+uJso8O/d88epT8STwajxX/AgMBAAGjUzBRMB0GA1Ud
DgQWBBTZ7P5yH2HXPVnDmx5JvzAJymF9zjAfBgNVHSMEGDAWgBTZ7P5yH2HXPVnD
mx5JvzAJymF9zjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCl
86fZ/khd90N1e0e71NiP++lKGY/M+jznkVyxXxwNdgyozhQS7xDR+X6s7ydOe+kp
ld6F60MJPKo+oXMfnSMsVMdDE1g+ymQWGBUDJwcWPjN8/pilBPFjwEzG9c+NDrZH
t7shqk0ub0r7s+Rr1et5lPky+ohofQSypbYrEYniZxpAgMbmeoautVkgmf/Vfmi1
mKU0skZo6qgaSz5nZCKTCwIpRNySZOp0PYC513pHx0iTMuS985+jSxVicHs5M7P9
M9WLt603JdPRyx4mWErjR4en936hNtx+/4MKJmahSoIELdG2m9Z9Nu+GJEyi9VWN
eTXk0w/Q52qpts/mrzL+
-----END CERTIFICATE-----"""
        self.valid_cert = x509CertificateParser().parse(self.pem)

        self.pem_email_protection = """-----BEGIN CERTIFICATE-----
MIIFmjCCBIKgAwIBAgIQB0DCltBnHjXokTlVdE0eCDANBgkqhkiG9w0BAQsFADBlM
QswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d
3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb
3QgRzIwHhcNMjQxMTIwMDAwMDAwWhcNMzQxMTE5MjM1OTU5WjBNMQswCQYDVQQGE
wJVUzEaMBgGA1UEChMRU1JJIEludGVybmF0aW9uYWwxIjAgBgNVBAMTGVNSSSBJb
nRlcm5hdGlvbmFsIENBIC0gRzUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKA
oICAQC9XLdA7JuSxwktht+3Nita0z/+dPd/352kj02aq7HW2ZM8oHYj5EeIvv6Kx
J16wd6AQYQux+tGJal3uD79Hy8Jl4/JJ6ezhB75IS+ZqII/DYyEC62nozlXXVn0I
T/kz/00D5Zidx6APl+tBOBhx57ReSR5+ZQMZPMKp0boqYINxSZi4dLAqrV3bOa9H
iGaYbC/TTb9AXPz46PZCiRMxFMfZgKFPT4/Ugnr4n/lNLkPVBKWc3Yo09mqG8QKU
DyhszKd2gAjM7ffmKPhMFLruziRmOkUxNWhZJmsWGnS4h6OuGoDDKWNnSHeZ7Hb9
6f4dG7cj1rVG9w4rWQpf7eC034v0rL9m1TT1qrvgZIzyXthJTVSbCbPJwrzYk2uz
v5goXr5wpm4rw+cuXmAKvqY8F8z2DESMfOibQzKR1Db9xgSCn1STBOK7+tLjv7t5
F9vsprzh0lEsabXuKau0xvsyj4L1EUq0thfin/9mEKJQCOANa7f+tt3gOkv5kcJc
+a+0V9d9zLMENEd2EiUQWi3kifvESGUiI8xkqjb7EznRGP9toXo8v1JDQQlyZPNn
hXRyVMgro087u/hI+F7nN0EqOAD2zKUwVWtDIgeTnfGpw+1h/WZMhckgFgnUWX99
nvijjE9KYu8FPmnt0TjpOfb1+shOkio0G/WrVWNM8FRpwLWcQIDAQABo4IBXDCCA
VgwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUX8G+mPxUFtoy757kJOkQ5
/EOXkYwHwYDVR0jBBgwFoAUzsNKuZlV8rjbYL+pfr1WtZc2p9YwDgYDVR0PAQH/B
AQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMEBggrBgEFBQcDAjB5BggrBgEFBQcBA
QRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrB
gEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzd
XJlZElEUm9vdEcyLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5ka
WdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290RzIuY3JsMBEGA1UdIAQKM
AgwBgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAhDOM3m4EVuJmv3ilOTwDjuWog
5fMqdyDhlKkAMAixEWAxtt1FQjt+F5fZ0gAGWMNEbOmHEMJJi+CXx4QnJ0BMySUz
TKp23q6mKLu78eSpiF2P76Tcv3noXPIUWdBmbO1/Z8wIbnhq6sY+sBRjuNfgcfC0
EcmTSPUWuS6BwSvL8BdQFITEUl2qZknH0Urfra5ap20aJeUbwh/Kp/A4Mn4l9yOv
HMCB6VyDM774pvI9xdcYD6zKSk2MWyjFy0PtiH26AuI35jCOAPPpGE73ubk4KEn5
5gAAB9lP6z/hr80r8fEqWRHFi0Wa/mR5zp7usnXnhW15+0rj2yErnycPIeFDw==
-----END CERTIFICATE-----
"""
        self.valid_cert_email_protection = x509CertificateParser().parse(
            self.pem_email_protection
        )

    def test_is_malformed_valid_certificate(self):
        self.assertFalse(is_malformed(self.root_cert))

    def test_is_malformed_malformed_certificate(self):
        self.assertTrue(is_malformed(self.malformed_cert))

    def test_is_root_valid_root_certificate(self):
        self.assertTrue(is_root(self.root_cert))

    def test_is_root_non_root_certificate(self):
        self.assertFalse(is_root(self.non_root_cert))

    def test_get_access_locations(self):
        mock_cert = MagicMock()

        mock_extension = MagicMock()
        mock_extension.oid = ObjectIdentifier(OID_AUTHORITY_INFORMATION_ACCESS)

        mock_description_1 = MagicMock()
        mock_description_1.access_method.dotted_string = OID_CA_ISSUER
        mock_description_1.access_location.value = "http://example.com/ca"

        mock_description_2 = MagicMock()
        mock_description_2.access_method.dotted_string = "invalid"
        mock_description_2.access_location.value = "http://example.com/other"

        mock_extension.value._descriptions = [mock_description_1, mock_description_2]

        mock_cert.extensions = [mock_extension]

        access_locations = get_access_locations(mock_cert)
        self.assertEqual(access_locations, ["http://example.com/ca"])

    def test_get_access_locations_no_extensions(self):
        mock_cert = MagicMock()
        mock_cert.extensions = []
        access_location = get_access_locations(mock_cert)
        self.assertEqual(access_location, [])

    def test_get_cert_key(self):
        actual_key = get_cert_key(self.valid_cert)
        expected_fingerprint = (
            "0cfced9c09e46a2a0da46a1ea7ffb01bf326513fe2e1d753c0570a65b3c27af9"
        )
        expected_hash = "5207cad0c8a498433d5615309cafa09504217e56"
        expected_value = f"{expected_fingerprint}:{expected_hash}:{expected_hash}"
        self.assertEqual(actual_key, expected_value)
        # test invalid input
        with self.assertRaises(TypeError):
            get_cert_key(self.pem)

    def test_is_suitable_for_smime(self):
        self.assertTrue(is_suitable_for_s_mime(self.valid_cert))
        self.assertTrue(is_suitable_for_s_mime(self.valid_cert_email_protection))
        mock_cert = MagicMock()
        # A mocked certificate without extensions.
        self.assertTrue(mock_cert)
        mock_extension = MagicMock()
        mock_extension.oid.dotted_string = OID_EXTENDED_KEY_USAGE
        mock_extension.value._usages = [MagicMock(dotted_string="abcde")]
        mock_cert.extensions = [mock_extension]
        self.assertFalse(is_suitable_for_s_mime(mock_cert))


if __name__ == "__main__":
    unittest.main()

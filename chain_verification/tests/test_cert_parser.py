import unittest
from cryptography import x509
from smime_chain_verifier.utils.cert_parser import (
    x509CertificateParser,
    CertificateParsingError,
)
from cryptography.hazmat.primitives import serialization


class TestX509CertificateParser(unittest.TestCase):
    # Issuer of the generated test certificate.
    ISSUER = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"

    def setUp(self):
        # Self signed test certificate generated via openssl.
        self.pem_cert = """-----BEGIN CERTIFICATE-----
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
        self.der_cert = x509.load_pem_x509_certificate(
            self.pem_cert.encode()
        ).public_bytes(encoding=serialization.Encoding.DER)
        self.invalid_cert = "Not a certificate"
        self.parser = x509CertificateParser()

    def test_parse_pem_certificate(self):
        cert = self.parser.parse(self.pem_cert)
        self.assertIsInstance(cert, x509.Certificate)
        self.assertEqual(cert.issuer.rfc4514_string(), self.ISSUER)

    def test_parse_der_certificate(self):
        cert = self.parser.parse(self.der_cert)
        self.assertIsInstance(cert, x509.Certificate)
        self.assertEqual(cert.issuer.rfc4514_string(), self.ISSUER)

    def test_parse_invalid_certificate(self):
        with self.assertRaises(CertificateParsingError):
            self.parser.parse(self.invalid_cert)

    def test_random_ca_cert_data(self):
        critical_pem = """-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIMErsBAAAAAABJ4/FwMA0GCSqGSIb3DQEBCwUAMCUxCzAJBgNVBAYTAkNOMRYwFAYDVQQDDA0wOTI2X2FkbWluX0NBMCAXDTIzMDkyNjEwMjMyNFoYDzIwNTMwOTE4MTAyMzI0WjAlMQswCQYDVQQGEwJDTjEWMBQGA1UEAwwNMDkyNl9hZG1pbl9DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKBpJ3+4/v3UrTWvwWoc9gzIRBjMDitRI+uzOAieT2e2+SxVpJKfYzad03tLceqm04dQ89kE8MzKA8/uIZhIMFfApRaXAOzGqYpjAkkAJmSdvJ0YjPLIuxTqAF50S6NYJXChKv9QSrruNW4cZYLd8jxw3LiEfBVWhN1iF9fTpg/E48tNmc4YAFW9bsdbeYrlb/12vGUjbM0lkHLYqDishKJgqakvudI3DO3ua7E5ByvcJdYM1Jr3j2UjzP2Gu5teQRXIabC52+rP1qjcEeIKmKd+xIL3/Zki6kHwR8j1vTcs1CtrZdHOjOwedsy+YfbQhk5eWMVQDp2d+M+ZPquMSNsCAwEAAaNFMEMwDgYDVR0PAQEABAQDAgCGMA8GA1UdEwEBAAQFMAMBAf8wIAYDVR0OAQEABBYEFD4QjZCnKsowAmfRw/ntcJ4WQm8HMA0GCSqGSIb3DQEBCwUAA4IBAQCJ4DlHKuiJmSWLXVclpBVbucE2xwkBA7yMXI4XcobdYf+RewHC9JNUqnsB9uJ4lpMFBNM81WA72tTT23jiYpazHMIlURRNDpV5wsSN4/GL0dPAoGJPS7wPec9mbI/gmWObFZXrAUPnoaI60k2h75rooECXquG4A+hSt3qG6eP5kqcPTFX1MzQKIctGQhK2HXOAko+TsFpQO/63ImfNJuENSOKeyLzsum1i2DbD1woF9L6yAaUsDgcVU3w1fc5udDi9tCIqLWU2YNEU7y8tAWMDbZwqBPAyEKsx5vmEXn9lvypXkUZHd8VCEvL8bmlwdMhKBfe8svagKWT01CPW85MA
-----END CERTIFICATE-----"""
        with self.assertRaises(CertificateParsingError):
            self.parser.parse(critical_pem)


if __name__ == "__main__":
    unittest.main()

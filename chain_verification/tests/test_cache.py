import unittest
from unittest.mock import MagicMock, patch
from cryptography.x509 import Certificate
from smime_chain_verifier.cache.cache import Cache
from smime_chain_verifier.utils.cert_parser import x509CertificateParser


class TestCache(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_cert = MagicMock(Certificate)
        # Self signed test certificate generated via openssl.
        self.pem_a = """-----BEGIN CERTIFICATE-----
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
        self.cert_a = x509CertificateParser().parse(self.pem_a)
        # Random cert from mozilla-intermediate-bundle.cert
        self.pem_b = """-----BEGIN CERTIFICATE-----
MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ
cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5
blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm
B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw
0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG
KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW
dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow
CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1
59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t
6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI
8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1
upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS
yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/
-----END CERTIFICATE-----"""
        self.cert_b = x509CertificateParser().parse(self.pem_b)
        self.cache = Cache("localhost",port=16379)
        self.cache.clear()

    def tearDown(self) -> None:
        self.cache.clear()

    def test_store_and_load_cert(self):
        self.cache.store_cert(self.cert_a)
        result = self.cache.get_cached_cert(self.cert_a)
        self.assertEqual(result.cert, self.cert_a)

    def test_load_cert_not_found(self):
        result = self.cache.get_cached_cert(self.cert_a)
        self.assertIsNone(result)

    def test_store_access_location(self):
        access_location = "http://example.com/cert.pem"
        self.cache.store_access_location(access_location)
        self.assertTrue(self.cache.is_access_location_cached(access_location))

    def test_get_cached_access_locations(self):
        access_location_a = "http://example.a.com/cert.pem"
        access_location_b = "http://example.b.com/cert.pem"
        self.cache.store_access_location(access_location_a)
        self.cache.store_access_location(access_location_a)
        self.cache.store_access_location(access_location_b)
        result = self.cache.get_cached_access_locations()
        self.assertEqual(sorted(result), sorted({access_location_a, access_location_b}))

    def test_get_access_locations_of_cached_certificates(self):
        self.cache.store_cert(self.cert_b)
        result = self.cache.get_access_locations_of_cached_certificates()
        expected_result = {"http://crt.rootca1.amazontrust.com/rootca1.cer"}
        self.assertEqual(result, expected_result)

    @patch("smime_chain_verifier.cache.cache.is_root")
    def test_load_cas(self, mock_is_root):
        self.cache.store_cert(self.cert_a)
        # Simulate a non-root certificate with ca in cache.
        mock_is_root.return_value = False
        result = self.cache.load_cas(self.cert_a)
        self.assertEqual(result[0].cert, self.cert_a)

    def test_load_cas_root_cert(self):
        self.cache.store_cert(self.cert_a)
        self.assertIsNone(self.cache.load_cas(self.cert_a))

    def test_load_cas_not_found(self):
        self.assertIsNone(self.cache.load_cas(self.cert_b))

    def test_get_certs(self):
        self.cache.store_cert(self.cert_a)
        self.cache.store_cert(self.cert_b)
        result = self.cache.get_certs()
        self.assertIn(self.cert_a, result)
        self.assertIn(self.cert_b, result)
        self.assertEqual(len(result), 2)

    @patch("smime_chain_verifier.cache.cache.request_certificate")
    def test_store_cert_by_access_location_success(self, mock_request_certificate):
        mock_request_certificate.return_value = self.cert_a
        access_location = "http://example.com/cert.pem"
        self.cache.store_cert_by_access_location(access_location)
        mock_request_certificate.assert_called_once_with(access_location)
        result = self.cache.get_certs()[0]
        self.assertEqual(result, self.cert_a)

    @patch.object(Cache, "get_cached_cert")
    def test_is_trusted_cert_is_trusted(self, mock_get_cached_cert):
        mock_cached_cert = MagicMock()
        mock_cached_cert.is_trusted = True
        mock_get_cached_cert.return_value = mock_cached_cert

        result = self.cache.is_trusted(self.mock_cert)
        mock_get_cached_cert.assert_called_once_with(self.mock_cert)
        self.assertTrue(result)

    @patch.object(Cache, "get_cached_cert")
    def test_is_trusted_cert_is_not_trusted(self, mock_get_cached_cert):
        mock_cached_cert = MagicMock()
        mock_cached_cert.is_trusted = False
        mock_get_cached_cert.return_value = mock_cached_cert

        result = self.cache.is_trusted(self.mock_cert)

        mock_get_cached_cert.assert_called_once_with(self.mock_cert)
        self.assertFalse(result)

    @patch.object(Cache, "get_cached_cert")
    def test_is_trusted_cert_not_in_cache(self, mock_get_cached_cert):
        mock_get_cached_cert.return_value = None

        result = self.cache.is_trusted(self.mock_cert)

        mock_get_cached_cert.assert_called_once_with(self.mock_cert)
        self.assertFalse(result)

    def test_build_and_get_cert_chains(self):
        self.cache.store_cert(self.cert_b)
        # Download and cache intermediate cert of self.cert_b
        access_location = list(
            self.cache.get_access_locations_of_cached_certificates()
        )[0]
        expected_access_location = "http://crt.rootca1.amazontrust.com/rootca1.cer"
        self.assertEqual(access_location, expected_access_location)
        result = self.cache.store_cert_by_access_location(access_location)
        self.assertTrue(result)
        self.assertEqual(self.cache.size(), 2)
        # Build certificates
        self.cache.build_cert_chains()
        cached_certs = self.cache.get_cached_certs()
        for cached_cert in cached_certs:
            if cached_cert.cert.subject == self.cert_b.subject:
                # Assert cert b chains
                chains_of_b = cached_cert.chains
                self.assertEqual(len(cached_cert.chains), 1)
                self.assertEqual(len(cached_cert.chains[0]), 2)
            else:
                # Assert intermediate of cert b chains
                self.assertEqual(len(cached_cert.chains), 1)
                self.assertEqual(len(cached_cert.chains[0]), 1)

        # Test get cert chains of cert b
        mocked_cert = MagicMock(Certificate)
        with patch("smime_chain_verifier.cache.cache.is_root") as mock_is_root:
            with patch(
                "smime_chain_verifier.cache.cache.get_issuer_hash"
            ) as mock_get_issuer_hash:
                mock_is_root.return_value = False
                # subject_hash(self.cert_b) = 5607a7bb97d4adcacbf4fecf7d4f365056a57028
                mock_get_issuer_hash.return_value = (
                    "5607a7bb97d4adcacbf4fecf7d4f365056a57028"
                )
                chains = self.cache.get_cert_chains(mocked_cert)
                self.assertEqual(chains, chains_of_b)


if __name__ == "__main__":
    unittest.main()

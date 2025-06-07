import unittest
from redis import Redis
from smime_chain_verifier.cache.cached_certificate import CachedCertificate
from smime_chain_verifier.utils.cert_parser import x509CertificateParser


class TestCachedCertificate(unittest.TestCase):
    def setUp(self):
        # Self signed test certificate generated via openssl.
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
        self.cert = x509CertificateParser().parse(self.pem)
        self.chains = [[self.cert, self.cert], [self.cert]]
        self.cached_cert = CachedCertificate(self.cert, "mozilla", self.chains)
        self.redis = Redis(host="localhost")

    def test_init(self):
        self.assertEqual(self.cached_cert.cert, self.cert)
        self.assertEqual(
            self.cached_cert.origin.create_dict_from_mask(),
            {
                "mozilla": 1,
                "microsoft": 0,
                "macOS": 0,
                "chrome": 0,
                "cencys": 0,
                "ccadb": 0,
                "smine": 0,
            },
        )
        self.assertEqual(self.cached_cert.chains, self.chains)
        self.assertTrue(self.cached_cert.is_root)

    def test_invalid_init(self):
        with self.assertRaises(TypeError):
            CachedCertificate(self.pem, "mozilla", None)
        with self.assertRaises(TypeError):
            CachedCertificate(self.cert, "mozilla", [self.cert])
        with self.assertRaises(TypeError):
            CachedCertificate(self.cert, "mozilla", [[self.pem]])

    def test_to_redis(self):
        key = "test_cert"
        self.redis.set(key, self.cached_cert.to_redis())
        result = CachedCertificate.from_redis(self.redis.get(key).decode())
        self.assertEqual(result.cert, self.cached_cert.cert)
        self.assertEqual(
            result.origin.create_dict_from_mask(),
            self.cached_cert.origin.create_dict_from_mask(),
        )
        self.assertEqual(result.is_root, self.cached_cert.is_root)
        self.assertEqual(result.chains, self.cached_cert.chains)


if __name__ == "__main__":
    unittest.main()

import unittest
from smime_chain_verifier.cache.cache import Cache
from smime_chain_verifier.utils.cert_parser import x509CertificateParser
from smime_chain_verifier.utils.cert import is_root
from smime_chain_verifier.bundles.load_crt_bundles import load_crt_bundles
from smime_chain_verifier.cache.init_cache import (
    _load_config,
    _store_crt_bundles,
    _store_cache_aia_certs,
)


class TestInitCache(unittest.TestCase):
    def setUp(self) -> None:
        self.mozilla_intermediate_pem = """-----BEGIN CERTIFICATE-----
MIIIRzCCBi+gAwIBAgIIBHlvYTIsFqIwDQYJKoZIhvcNAQELBQAwgawxCzAJBgNV
BAYTAkVVMUMwQQYDVQQHEzpNYWRyaWQgKHNlZSBjdXJyZW50IGFkZHJlc3MgYXQg
d3d3LmNhbWVyZmlybWEuY29tL2FkZHJlc3MpMRIwEAYDVQQFEwlBODI3NDMyODcx
GzAZBgNVBAoTEkFDIENhbWVyZmlybWEgUy5BLjEnMCUGA1UEAxMeR2xvYmFsIENo
YW1iZXJzaWduIFJvb3QgLSAyMDA4MB4XDTE1MTExNzA5MjU1NloXDTM3MTEyMTA5
MjU1NlowgasxCzAJBgNVBAYTAkVTMRswGQYDVQQKDBJBQyBDYW1lcmZpcm1hIFMu
QS4xEjAQBgNVBAUTCUE4Mjc0MzI4NzFDMEEGA1UEBww6TWFkcmlkIChzZWUgY3Vy
cmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTEmMCQG
A1UEAwwdQUMgQ2FtZXJmaXJtYSBQb3J0dWdhbCAtIDIwMTUwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDaKgpFvqOOjala5PnTmVey0q3lyi8RfWnFJUFi
TOwlxo1YhkBXaEwp8LGRTCNnc/2r0pzZomF4XmWlg9YSsJ4ASY+Lr29w8m/UHIuf
vk3u16Y+SUOwkMoGk+sbZBQ2kCyUWTrUu4sjKpQ+1sgJa4n5QObAP6ZCv31UNdCo
/W7e3FDo1Ps5EqHetlUxTYGV4fuosSURI4zVytilJfjTZ3e00Gr5ONREwPvIqU8L
16geZETpMv2AC0Q7I/9zTtRDw0LEZCu6vG9D+ayOHLLPE/QC+euyE5vtYljerR/3
HGu1itmh1tZs1nUmCntAGrfIvByMIBXg4x7cqIqyk8LKa/RWxFUu8vtN0ue+AZZF
vm6J7CywyYvLQ24txS7PS4N1/63ZdRUT0WLOAgn5IQLMRPB8DbtbZnIz7Ef5gXiZ
R2AjULcrxPV5aqPVziKODScvDVuvJhLvdDF8KiJ+txRWe05MWGOOjVDfhhXgbzE3
j68cnqbKN87RwHIHwtGJE7TpAzj4ZvGQDMoMXBui6lh8Fa81N+BcePk4vmOjxCaR
9rWvPaaGvblA0XlBdxFK7+nGOHFg1jPvK9TK+piEhcPcP10wRnB5O8q+4Iw99uTM
UY+uPq4vaN9rMHCvAjO5qIRIyLkJlyxnwykPnGPoOMmajckx4OP/b2zKW8OrT4Pu
GRpiXQIDAQABo4ICajCCAmYwEgYDVR0TAQH/BAgwBgEB/wIBAzAdBgNVHQ4EFgQU
IGmabGRRm+JMYMrj6FjCheckDXowgeEGA1UdIwSB2TCB1oAUuQnKnB7b02w6a67t
VPFbkwY1Ll6hgbKkga8wgawxCzAJBgNVBAYTAkVVMUMwQQYDVQQHEzpNYWRyaWQg
KHNlZSBjdXJyZW50IGFkZHJlc3MgYXQgd3d3LmNhbWVyZmlybWEuY29tL2FkZHJl
c3MpMRIwEAYDVQQFEwlBODI3NDMyODcxGzAZBgNVBAoTEkFDIENhbWVyZmlybWEg
Uy5BLjEnMCUGA1UEAxMeR2xvYmFsIENoYW1iZXJzaWduIFJvb3QgLSAyMDA4ggkA
yc3T6dV9I84wfQYIKwYBBQUHAQEEcTBvMEUGCCsGAQUFBzAChjlodHRwOi8vd3d3
LmNhbWVyZmlybWEuY29tL2NlcnRzL3Jvb3RfY2hhbWJlcnNpZ24tMjAwOC5jcnQw
JgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLmNhbWVyZmlybWEuY29tMA4GA1UdDwEB
/wQEAwIBBjA+BgNVHSAENzA1MDMGBFUdIAAwKzApBggrBgEFBQcCARYdaHR0cHM6
Ly9wb2xpY3kuY2FtZXJmaXJtYS5jb20wfgYDVR0fBHcwdTA4oDagNIYyaHR0cDov
L2NybC5jYW1lcmZpcm1hLmNvbS9jaGFtYmVyc2lnbnJvb3QtMjAwOC5jcmwwOaA3
oDWGM2h0dHA6Ly9jcmwxLmNhbWVyZmlybWEuY29tL2NoYW1iZXJzaWducm9vdC0y
MDA4LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAu0GATqbLQ+Q/QL/XwDlvZ6BOitu8
vFlkA6NtWuX4TiTLcxHWqk17s2j0ud5Qx4rcOatVsgcTPtevSz/XrI8gTDkLTo2z
lTQpKQFUaqG0Rw6R0EwLoPUjeKKJiU1FDr5/pZ3sIL+DWux4CjYiyzq7XIlvDHUe
Mc4PXKPavRjox+IrOJgeL3Y3iSscKb5MrmcZGsU6bCaKOxkeTUFoHIChWZVLtEvi
XbKGexu/qj7unexLIdj2uHfQyiWJlpzEfPrzkDZEvZ+nVb89I27vbY/SY6vau0l+
dyZ3hovkramxYSbCKmWSR+ksbYclObEv8jLugGTXnny9bogudHlqK/OvDyy6iXEA
xtY6qAok679dwa252e5DBUTnuO1yF56csZzibfFCsCA4beel7ii8umKdENzTbd69
s94eFm4sUnUoNoeNzq864vDcT2ODmxzhsIHWF1m9YNDkn1NfU7wpFEjGw6LrmtYJ
QbSd6IDqJ0CpR/rctjBic+iLdo03qaZevQFjhZZ7V72VX+REkVawoJP5bb+QAYIf
ERjQIlsz4Ejto3x2UfmnPqWyBNjPd/po2NddI5YQ55Jb7lzSNTx8qErEDPzutTWp
PRF8gtsTIQoMYNUaiKMqLz02vIa883WK6NahlBI4Uy/FE5DHmWkcZU56CYA4rqrv
XZJt2zyxCI5FPKw=
-----END CERTIFICATE-----"""
        self.mozilla_intermediate_cert = x509CertificateParser().parse(
            self.mozilla_intermediate_pem
        )
        self.cache = Cache("localhost",port=16379)

    def tearDown(self) -> None:
        self.cache.clear()

    def test_load_config(self):
        result = _load_config("tests/assets/test-crt-bundles/crt-bundles.config.json")
        self.assertDictEqual(
            result,
            {
                "03_test_bundle.crt": True,
                "02_test_bundle.crt": False,
                "01_test_bundle.crt": True,
            },
        )

    def test_load_crt_bundles(self):
        result = load_crt_bundles("tests/assets/test-crt-bundles/")
        self.assertEqual(len(result), 5)

    def test_store_crt_bundles(self):
        _store_crt_bundles(self.cache, "tests/assets/test-crt-bundles/")
        cached_certs = self.cache.get_cached_certs()
        self.assertEqual(len(cached_certs), 4)
        root_certs = [cert for cert in cached_certs if cert.is_root]
        self.assertEqual(len(root_certs), 1)

    def test_store_cache_aia_certs(self):
        self.cache.store_cert(self.mozilla_intermediate_cert)
        _store_cache_aia_certs(self.cache)
        self.assertGreater(len(self.cache.get_cached_certs()), 1)
        self.cache.build_cert_chains()
        cached_intermediate = self.cache.get_cached_cert(self.mozilla_intermediate_cert)
        trusted_root_cert = cached_intermediate.chains[0][-1]
        self.assertTrue(is_root(trusted_root_cert))


if __name__ == "__main__":
    unittest.main()

#! /usr/bin/env python3

# ECC-Key Analysis on S/MIME certificates
#
# Required pip installs (based on a default python installation):
# galois cryptograpy ijson jc
#
# The Python crypto library do not support key validation for all found ECC keys.
# For the unsupported curves we implemented our own validation functions according to
# NIST SP 800-56A: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/nist.sp.800-56Ar3.pdf (Page 56).
# The script is intended for usage with our collected S/MIME certificate set.
# It does not cover all possible errors, but all relevant errors that appear for our cert set.
#
# The script iterates through all certificates in the given json file.
#
# 1. First, we try to load this certificate with the python cryptographic library
# (x509.load_pem_x509_certificate()). There are quite some certs that cannot be loaded, e.g. usage
# of not supported characters in some x.509 fields. If this is the case, we parse those certs with
# our patched jc (jc_parse_relaxed()), identify the used curve, and use our own key validations
# functions.
# 2. For the certs that are successfully parsed, we try to validate the public key with the function
# public_key(). Not all public keys in our cert set are supported; for the unsupported ones, we
# parse the certs with jc_parse_relaxed() and identify the used curve and use our own key validation.
#
# The script will collect and store the following data for further manual inspection
# - explicit.json Certificates with explicit curves that don't match a defined curve
# - exceptionPubKey.json Certificates that raise an uncaught exception during load
# - keyInvalid.json Certificates with an invalid key
# - invalidCertsNames.log Issuer, Subject and Curve of certificates with invalid keys


import functools
from pprint import pprint

import ujson as json
from collections import Counter

from bson.json_util import _json_convert
from cryptography import x509
from cryptography import hazmat
from datetime import datetime
import base64
import galois
import io
import itertools
from multiprocessing import Pool

from analysis.utils.cache import get_cache_name, JsonCacheManager
from analysis.utils.jc import jc_parse_relaxed


import logging
import sys
import os

from analysis.utils.aggregate import get_batch_ids, aggregate_batch

logger = logging.getLogger(__name__)
logging.getLogger("pymongo").setLevel(logging.WARNING)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(process)d [%(levelname)5s] %(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(stream=sys.stdout),
    ],
)

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)

def run_and_save_batch(args: tuple, **kwargs):
    result = aggregate_batch(*args, **kwargs)
    i = args[0]
    filename = f"ec_certs_{i:03d}.json"
    if result:
        print("Saving batch", i, "to", filename, flush=True)
        with open(os.path.join(CERTS_DIR, filename), "w") as file:
            json.dump(_json_convert(result), file)


def save_ec_certs(refresh: bool = False) -> None:
    if not refresh and os.path.isdir(CERTS_DIR):
        return

    os.makedirs(CERTS_DIR, exist_ok=True)

    pipeline = [
        {
            "$match": {
                "cert_fields.tbs_certificate.subject_public_key_info.algorithm.algorithm": "ec"
            }
        },
        {"$match": {"is_smime.is_smime": True}},
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {
            "$project": {
                "chain": {"$arrayElemAt": ["$chain.chain", 0]},
                "cert_data": 1,
                "_id": 1,
            }
        },
    ]

    PROCESSES = int(os.getenv("BATCHWISE_PROCS", "80"))
    BATCH_SIZE = int(os.getenv("BATCHWISE_SIZE", "1000000"))

    batches = get_batch_ids(collection_name="certificates", batch_size=BATCH_SIZE)
    aggregate_func = functools.partial(
        run_and_save_batch, collection_name="certificates", pipeline=pipeline
    )
    with Pool(PROCESSES, maxtasksperchild=1) as pool:
        for i, result in enumerate(pool.imap_unordered(aggregate_func, batches)):
            print(i)


def check(
    certs_file: str,
) -> tuple[Counter, Counter, Counter, Counter, Counter, Counter, list, list, list, str]:
    print(f"Starting {certs_file}", flush=True)
    # Set for counting ECC curves (valid and invalid), per curve
    curveCount = Counter()
    # Counter for invalid ECC keys, per curve
    invalidCount = Counter()
    # Set for counting certificate chains of invalid ECC keys
    invalidChainCount = Counter()
    # Set for counting certificates per Issuer CA
    invalidCACount = Counter()
    # Set for counting certificates per reason for key invalidity
    invalidReasonCount = Counter()
    # Set for counting key parsing errors.
    parseErrors = Counter()
    # Set for storing certificates with explicit curve parameters
    explicit = []
    # Set for certificates with public keys that could not be parsed. < 10 in our cert set, these will be ignored for analysis
    exceptionPubKey = []
    # Set of certificates with invalid keys
    keyInvalid = []
    # Additional list for invalid Keys which stores curve, Issuer and Subject
    invalidCertNames = io.StringIO()

    # Function for dumping a cert as a file for further debugging
    def writeCert(fname, certdata):
        cert = (
            b"-----BEGIN CERTIFICATE-----\n"
            + str.encode(certdata)
            + b"\n-----END CERTIFICATE-----"
        )
        with open(fname, "w") as f:
            f.write(cert.decode())

    # Function is called for every invalid ECC Key: Checks state of the cert and logs relevant data.
    def logInvalid(cert, certItem, curveName):
        e_publicly_trusted = (
            certItem["chain"]["origin_info"]["mozilla"] == 1
            or certItem["chain"]["origin_info"]["macOS"] == 1
            or certItem["chain"]["origin_info"]["microsoft"] == 1
            or certItem["chain"]["origin_info"]["chrome"] == 1
        )
        e_validation_result = certItem["chain"]["validation"]["validation_result"]
        e_historical = certItem["chain"]["validation"]["historical"]

        if (
            e_publicly_trusted == True
            and e_validation_result == "VALID"
            and e_historical == True
        ):
            invalidChainCount["Trusted + expired"] += 1
        elif (
            e_publicly_trusted == True
            and e_validation_result == "VALID"
            and e_historical == False
        ):
            invalidChainCount["Trusted + not expired"] += 1
        elif (
            e_publicly_trusted == False
            and e_validation_result == "VALID"
            and e_historical == True
        ):
            invalidChainCount["Valid + expired"] += 1
        elif (
            e_publicly_trusted == False
            and e_validation_result == "VALID"
            and e_historical == False
        ):
            invalidChainCount["Valid + expired"] += 1
        elif e_validation_result != "VALID" and e_historical == True:
            invalidChainCount["Non-validatable + expired"] += 1
        elif e_validation_result != "VALID" and e_historical == False:
            invalidChainCount["Non-validatable + not expired"] += 1
        else:
            invalidChainCount["W/O Category"] += 1

        # Add invalid cert to set of invalid
        invalidCount[curveName] += 1

        # Decimal cannot be serialized in json, convert to string
        certItem["chain"]["validation"]["validation_timestamp"] = str(
            certItem["chain"]["validation"]["validation_timestamp"]
        )
        keyInvalid.append(certItem)
        invalidCertNames.write(str(certItem["_id"]["$oid"]))
        invalidCertNames.write("\n")
        invalidCertNames.write(curveName)
        invalidCertNames.write("\n")
        invalidCertNames.write(str(cert.subject))
        invalidCertNames.write("\n")
        invalidCertNames.write(str(cert.issuer))
        invalidCertNames.write("\n\n")
        invalidCACount[curveName + str(cert.issuer)] += 1

    # Key Validation Function for SM2
    def sm2keyval(x, y):
        prime = int.from_bytes(
            bytes.fromhex(
                "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"
            ),
            "big",
        )
        a = int.from_bytes(
            bytes.fromhex(
                "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"
            ),
            "big",
        )
        b = int.from_bytes(
            bytes.fromhex(
                "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"
            ),
            "big",
        )
        n = int.from_bytes(
            bytes.fromhex(
                "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"
            ),
            "big",
        )
        xQ = int.from_bytes(x, "big")
        yQ = int.from_bytes(y, "big")

        # 1. Not infinity
        if (xQ == 0) and (yQ == 0):
            invalidReasonCount["sm2_infinity"] += 1
            return False
        # 2. In range
        if (xQ >= prime) or (yQ >= prime):
            invalidReasonCount["sm2_YX_NotInRange"] += 1
            return False
        # 3. Verify that Q is on the curve
        if pow(yQ, 2) % prime != ((pow(xQ, 3) + a * xQ + b) % prime):
            invalidReasonCount["sm2_NotOnCurve"] += 1
            return False
        # 4. Compute nQ = not required, cofactor == 1

        return True

    # Key Validation Function for c2pnb163v1
    def c2pnb163v1keyval(x, y):
        m = 163
        a = int.from_bytes(
            bytes.fromhex("072546b5435234a422e0789675f432c89435de5242"), "big"
        )
        b = int.from_bytes(
            bytes.fromhex("00c9517d06d5240d3cff38c74b20b6cd4d6f9dd4d9"), "big"
        )
        n = int.from_bytes(
            bytes.fromhex("0400000000000000000001e60fc8821cc74daeafc1"), "big"
        )

        xQ = int.from_bytes(x, "big")
        yQ = int.from_bytes(y, "big")

        GF = galois.GF(2**m, irreducible_poly="x^163 +  x^8 +  x^2 +  x^1 + 1")

        # 1. Not infinity
        if (xQ == 0) and (yQ == 0):
            return False
        # 2. in range
        if (xQ.bit_length() > 163) or (yQ.bit_length() > 163):
            return False
        # 3. Verify that Q is on the curve
        gfx = GF(xQ)
        gfy = GF(yQ)
        gfa = GF(a)
        gfb = GF(b)
        if (gfy * gfy + gfx * gfy) != (gfx * gfx * gfx + gfa * gfx * gfx + gfb):
            return False
        # 4. Compute nQ = not required, cofactor == 1

        return True

    def run(certs: list[dict]):
        ##########################################################
        for certItem in certs:
            # Constructs valid PEM Cert for cryptography library
            cert = (
                b"-----BEGIN CERTIFICATE-----\n"
                + str.encode(certItem["cert_data"])
                + b"\n-----END CERTIFICATE-----"
            )
            try:
                # Load Pem cert
                cert = x509.load_pem_x509_certificate(cert)
            except Exception as X:
                # Some SM2 certs with chinese characters which cannot be parsed by library -> Parse with adapted 'jc'
                certdec = base64.b64decode(certItem["cert_data"])
                parse = jc_parse_relaxed("x509_cert", certdec)
                if (
                    parse[0]["tbs_certificate"]["subject_public_key_info"]["algorithm"][
                        "parameters"
                    ]
                    == "1.2.156.10197.1.301"
                ):
                    # Found SM2 OID in pubkey key
                    curveCount["SM2-Curve"] += 1
                    pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "public_key"
                    ].replace(":", "")
                    if (len(pubkey) != 130) or (pubkey[0:2] != "04"):
                        print(str(certItem["_id"]["$oid"]))
                        print(
                            "SM2 unparsed: ERROR: Did not found an uncompressed key with expected length!"
                        )
                    else:
                        x = bytes.fromhex(pubkey[2:66])
                        y = bytes.fromhex(pubkey[66:130])
                        valid = sm2keyval(x, y)
                        if valid == False:
                            # Key validation failed
                            logInvalid(cert, certItem, "SM2")
                elif (
                    parse[0]["tbs_certificate"]["subject_public_key_info"]["algorithm"][
                        "parameters"
                    ]
                    == "secp256r1"
                ):
                    # Some of these certs use secp256r1 in this field
                    curveCount["secp256r1"] += 1
                    # Get pub key and try key validation
                    pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "public_key"
                    ].replace(":", "")
                    if (len(pubkey) != 130) or (pubkey[0:2] != "04"):
                        print(str(certItem["_id"]["$oid"]))
                        print(
                            "ERROR: Did not found an secp256r1 uncompressed key with expected length!"
                        )
                    else:
                        x = bytes.fromhex(pubkey[2:66])
                        y = bytes.fromhex(pubkey[66:130])
                        curvep256 = hazmat.primitives.asymmetric.ec.SECP256R1()
                        try:
                            # Key Validation
                            pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                int.from_bytes(x, "big"),
                                int.from_bytes(y, "big"),
                                curvep256,
                            )
                            pubkey = pubnum.public_key()
                        except Exception as Y:
                            # Key validation failed!
                            logInvalid(cert, certItem, "secp256r1")
                            print("Exception pubKey Validation:")
                            print(Y)
                elif (
                    parse[0]["tbs_certificate"]["subject_public_key_info"]["algorithm"][
                        "parameters"
                    ]
                    == "brainpoolp256r1"
                ):
                    # Some of these certs use brainpoolp256r1 in this field
                    curveCount["brainpoolP256r1"] += 1
                    # Get pub key and try key validation
                    pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "public_key"
                    ].replace(":", "")
                    if (len(pubkey) != 130) or (pubkey[0:2] != "04"):
                        print(str(certItem["_id"]["$oid"]))
                        print(
                            "ERROR: Did not found an secp256r1 uncompressed key with expected length!"
                        )
                    else:
                        x = bytes.fromhex(pubkey[2:66])
                        y = bytes.fromhex(pubkey[66:130])
                        curvebp256 = hazmat.primitives.asymmetric.ec.BrainpoolP256R1()
                        try:
                            # Key Validation
                            pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                int.from_bytes(x, "big"),
                                int.from_bytes(y, "big"),
                                curvebp256,
                            )
                            pubkey = pubnum.public_key()
                        except Exception as Y:
                            # Key validation failed!
                            print(str(certItem["_id"]["$oid"]))
                            logInvalid(cert, certItem, "brainpoolP256r1")
                            print("Exception pubKey Validation:")
                            print(Y)
                elif (
                    parse[0]["tbs_certificate"]["subject_public_key_info"]["algorithm"][
                        "parameters"
                    ]
                    == "secp384r1"
                ):
                    # Some of these certs use secp384r1 in this field
                    curveCount["secp384r1"] += 1
                    # Get pub key and try key validation
                    pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "public_key"
                    ].replace(":", "")
                    if (len(pubkey) != 194) or (pubkey[0:2] != "04"):
                        print(str(certItem["_id"]["$oid"]))
                        print(
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "public_key"
                            ]
                        )
                        print(
                            "ERROR: Did not found an secp384r1 uncompressed key with expected length!"
                        )
                    else:
                        x = bytes.fromhex(pubkey[2:98])
                        y = bytes.fromhex(pubkey[98:194])
                        curvep384 = hazmat.primitives.asymmetric.ec.SECP384R1()
                        try:
                            # Key Validation
                            pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                int.from_bytes(x, "big"),
                                int.from_bytes(y, "big"),
                                curvep384,
                            )
                            pubkey = pubnum.public_key()
                        except Exception as Y:
                            # Key validation failed!
                            logInvalid(cert, certItem, "secp384r1")
                            print("Exception pubKey Validation:")
                            print(Y)
                else:
                    print("Exception LoadCert in Cert id: " + str(certItem["_id"]))
                    print(X)
                    print(
                        parse[0]["tbs_certificate"]["subject_public_key_info"][
                            "algorithm"
                        ]["parameters"]
                    )
                    writeCert(
                        "./Failload_Check-OID_" + str(certItem["_id"]["$oid"]) + ".crt",
                        certItem["cert_data"],
                    )
                continue
            try:
                # Certificates was parsed. Try to load the key. Loading with cryptography includes the key validation!
                pubKey = cert.public_key()
            except Exception as X:
                # Load raises an exception. Normally that means the curve is not supported by the cryptography library. Determine the curve and do the key validation on our own.
                if (
                    ("Curve 1.2.156.10197.1.301 is not supported" in str(X))
                    or ("Curve 1.2.156.10197.1.301.1 is not supported" in str(X))
                    or ("Curve 1.2.156.197.1.301 is not supported" in str(X))
                ):
                    # SM2 certificates in the wild use three different OIDs, we look for all these OIDs.
                    # Add SM2 curve to set of curves
                    curveCount["SM2-Curve"] += 1

                    certdec = base64.b64decode(certItem["cert_data"])
                    parse = jc_parse_relaxed("x509_cert", certdec)
                    pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "public_key"
                    ].replace(":", "")
                    if (pubkey[0:2] == "02") or (pubkey[0:2] == "03"):
                        # We found some 13 compressed keys for the SM2 curve. We ignored them since they could not be parsed with the cryptography library.
                        parseErrors["sm2_notParsable"] += 1
                    elif (pubkey[0:2] != "04") or len(pubkey) != 130:
                        # We found some keys with a wrong number of bytes (e.g, one missing byte) -> key cannot be parsed or checked and will be ignored.
                        parseErrors["sm2_notParsable"] += 1
                    else:
                        # Public Key can be parsed
                        x = bytes.fromhex(pubkey[2:66])
                        y = bytes.fromhex(pubkey[66:130])
                        valid = sm2keyval(x, y)
                        if valid == False:
                            # Key validation failed!
                            logInvalid(cert, certItem, "SM2")
                elif "Curve 1.2.840.10045.3.0.1 is not supported" in str(X):
                    # Add c2pnb163v1 curve to set of curves
                    curveCount["c2pnb163v1"] += 1
                    certdec = base64.b64decode(certItem["cert_data"])
                    parse = jc_parse_relaxed("x509_cert", certdec)
                    pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "public_key"
                    ].replace(":", "")
                    c2pnb163bytes = "{'algorithm': 'ec', 'parameters': 'c2pnb163v1'}"
                    if c2pnb163bytes in str(
                        parse[0]["tbs_certificate"]["subject_public_key_info"][
                            "algorithm"
                        ]
                    ):
                        pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                            "public_key"
                        ].replace(":", "")
                        if (len(pubkey) == 86) and (pubkey[0:2] == "04"):
                            x = bytes.fromhex(pubkey[2:44])
                            y = bytes.fromhex(pubkey[44:86])
                            valid = c2pnb163v1keyval(x, y)
                            if valid == False:
                                # Key validation failed!
                                logInvalid(cert, certItem, "c2pnb163v1")
                        elif (len(pubkey) == 44) and (
                            (pubkey[0:2] == "02") or (pubkey[0:2] == "03")
                        ):
                            # We found some 12 compressed keys for the deprecated curve c2pnb163v1. We ignored them since they could not be parsed with the cryptography library.
                            parseErrors["c2pnb163v1_notParsable"] += 1
                        else:
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "c2pnb163v1: ERROR: Did not found an uncompressed key with expected length!"
                            )
                    else:
                        print(str(certItem["_id"]["$oid"]))
                        print(
                            "Failure: c2pnb163v1 Certificate found, but no c2pnb163v1 subjectPublicKeyInfo algorithm!"
                        )
                elif (
                    "ECDSA keys with explicit parameters are unsupported at this time"
                    in str(X)
                ):
                    # Explicit curve is found. In our set the explicit curves are standard curves but encoded explicitly. Check which curve is used and do the key validation on our own.
                    certdec = base64.b64decode(certItem["cert_data"])
                    # DER encoded P192 parameter as explicit curve
                    p192bytes = bytes.fromhex(
                        "3081b0020101302406072a8648ce3d0101021900fffffffffffffffffffffffffffffffeffffffffffffffff30340418fffffffffffffffffffffffffffffffefffffffffffffffc041864210519e59c80e70fa7e9ab72243049feb8deecc146b9b1043104188da80eb03090f67cbf20eb43a18800f4ff0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811021900ffffffffffffffffffffffff99def836146bc9b1b4d22831020101"
                    )
                    # DER encoded P256 parameter as explicit curve
                    p256bytes = bytes.fromhex(
                        "302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff30440420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101"
                    )
                    # DER encoded P256 parameter - with seed - as explicit curve
                    p256seedbytes = bytes.fromhex(
                        "302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101"
                    )
                    # DER encoded brainpool256r1 parameter as explicit curve
                    bp256bytes = bytes.fromhex(
                        "302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101"
                    )
                    bp512curve = "{'a': '78:30:a3:31:8b:60:3b:89:e2:32:71:45:ac:23:4c:c5:94:cb:dd:8d:3d:f9:16:10:a8:34:41:ca:ea:98:63:bc:2d:ed:5d:5a:a8:25:3a:a1:0a:2e:f1:c9:8b:9a:c8:b5:7f:11:17:a7:2b:f2:c7:b9:e7:c1:ac:4d:77:fc:94:ca', 'b': '3d:f9:16:10:a8:34:41:ca:ea:98:63:bc:2d:ed:5d:5a:a8:25:3a:a1:0a:2e:f1:c9:8b:9a:c8:b5:7f:11:17:a7:2b:f2:c7:b9:e7:c1:ac:4d:77:fc:94:ca:dc:08:3e:67:98:40:50:b7:5e:ba:e5:dd:28:09:bd:63:80:16:f7:23', 'seed': None}"
                    bp512field = "{'field_type': 'prime_field', 'parameters': 8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947}"
                    parse = jc_parse_relaxed("x509_cert", certdec)

                    # Check if we find an explicit curve in the certificate
                    if certdec.find(p192bytes) != -1:
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit-P192"] += 1
                        pos = certdec.find(p192bytes) + len(p192bytes)
                        # Check for correct 66 Bytes with uncompressed key form
                        if (certdec[pos : pos + 4].hex()) != "03320004":
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "Explicit-P192 with not recognized public key point (should be uncompressed (04) x and y):"
                            )
                            print(certdec[pos : pos + 52].hex())
                        else:
                            x = certdec[pos + 4 : pos + 28]
                            y = certdec[pos + 28 : pos + 52]
                            curvep192 = hazmat.primitives.asymmetric.ec.SECP192R1()
                            try:
                                # Key Validation
                                pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                    int.from_bytes(x, "big"),
                                    int.from_bytes(y, "big"),
                                    curvep192,
                                )
                                pubkey = pubnum.public_key()
                            except Exception as Y:
                                # Key validation failed!
                                print(str(certItem["_id"]["$oid"]))
                                logInvalid(cert, certItem, "explicit-P192")
                                print("Exception pubKey Validation:")
                                print(Y)
                    elif certdec.find(p256bytes) != -1:
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit-P256"] += 1
                        pos = certdec.find(p256bytes) + len(p256bytes)
                        # Check for correct 66 Bytes with uncompressed key form
                        if (certdec[pos : pos + 4].hex()) != "03420004":
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "Explicit-P256 with not recognized public key point (should be uncompressed (04) x and y):"
                            )
                            print(certdec[pos : pos + 68].hex())
                        else:
                            x = certdec[pos + 4 : pos + 36]
                            y = certdec[pos + 36 : pos + 68]
                            curvep256 = hazmat.primitives.asymmetric.ec.SECP256R1()
                            try:
                                # Key Validation
                                pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                    int.from_bytes(x, "big"),
                                    int.from_bytes(y, "big"),
                                    curvep256,
                                )
                                pubkey = pubnum.public_key()
                            except Exception as Y:
                                # Key validation failed!
                                print(str(certItem["_id"]["$oid"]))
                                logInvalid(cert, certItem, "explicit-P256")
                                print("Exception pubKey Validation:")
                                print(Y)
                    elif certdec.find(p256seedbytes) != -1:
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit-P256"] += 1
                        pos = certdec.find(p256seedbytes) + len(p256seedbytes)
                        # Check for correct 66 Bytes with uncompressed key form
                        if (certdec[pos : pos + 4].hex()) != "03420004":
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "Explicit-P256 with not recognized public key point (should be uncompressed (04) x and y):"
                            )
                            print(certdec[pos : pos + 68].hex())
                        else:
                            x = certdec[pos + 4 : pos + 36]
                            y = certdec[pos + 36 : pos + 68]
                            curvep256 = hazmat.primitives.asymmetric.ec.SECP256R1()
                            try:
                                # Key Validation
                                pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                    int.from_bytes(x, "big"),
                                    int.from_bytes(y, "big"),
                                    curvep256,
                                )
                                pubkey = pubnum.public_key()
                            except Exception as Y:
                                # Key validation failed!
                                logInvalid(cert, certItem, "explicitP256-seed")
                                print("Exception pubKey Validation:")
                                print(Y)
                    elif certdec.find(bp256bytes) != -1:
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit-brainpoolP256r1"] += 1
                        pos = certdec.find(bp256bytes) + len(p256bytes)
                        # Check for correct 66 Bytes with uncompressed key form
                        if (certdec[pos : pos + 4].hex()) != "03420004":
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "Explicit-BP256R1 with not recognized public key point (should be uncompressed (04) x and y):"
                            )
                            print(certdec[pos : pos + 68].hex())
                        else:
                            x = certdec[pos + 4 : pos + 36]
                            y = certdec[pos + 36 : pos + 68]
                            curvebp256 = (
                                hazmat.primitives.asymmetric.ec.BrainpoolP256R1()
                            )
                            try:
                                # Key Validation
                                pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                    int.from_bytes(x, "big"),
                                    int.from_bytes(y, "big"),
                                    curvebp256,
                                )
                                pubkey = pubnum.public_key()
                            except Exception as Y:
                                # Key validation failed!
                                print(str(certItem["_id"]["$oid"]))
                                logInvalid(cert, certItem, "explicit-BP256")
                                print("Exception pubKey Validation:")
                                print(Y)
                    elif (
                        bp512curve
                        in str(
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["curve"]
                        )
                    ) and (
                        bp512field
                        in str(
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["field_id"]
                        )
                    ):
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit-brainpoolP512r1"] += 1
                        pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                            "public_key"
                        ].replace(":", "")
                        if (len(pubkey) != 258) or (pubkey[0:2] != "04"):
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "ERROR: Did not found an explicit-BP512 uncompressed key with expected length!"
                            )
                        else:
                            x = bytes.fromhex(pubkey[2:130])
                            y = bytes.fromhex(pubkey[130:258])
                            curvebp512 = (
                                hazmat.primitives.asymmetric.ec.BrainpoolP512R1()
                            )
                            try:
                                # Key Validation
                                pubnum = hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
                                    int.from_bytes(x, "big"),
                                    int.from_bytes(y, "big"),
                                    curvebp512,
                                )
                                pubkey = pubnum.public_key()
                            except Exception as Y:
                                # Key validation failed!
                                print(str(certItem["_id"]["$oid"]))
                                logInvalid(cert, certItem, "explicit-BP512")
                                print("Exception pubKey Validation:")
                                print(Y)
                    # SM2-explicit check for a, b, base point, order and modulus
                    elif (
                        (
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["curve"]["a"]
                            == "ff:ff:ff:fe:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff:ff:fc"
                        )
                        and (
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["curve"]["b"]
                            == "28:e9:fa:9e:9d:9f:5e:34:4d:5a:9e:4b:cf:65:09:a7:f3:97:89:f5:15:ab:8f:92:dd:bc:bd:41:4d:94:0e:93"
                        )
                        and (
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["base"]
                            == "04:32:c4:ae:2c:1f:19:81:19:5f:99:04:46:6a:39:c9:94:8f:e3:0b:bf:f2:66:0b:e1:71:5a:45:89:33:4c:74:c7:bc:37:36:a2:f4:f6:77:9c:59:bd:ce:e3:6b:69:21:53:d0:a9:87:7c:c6:2a:47:40:02:df:32:e5:21:39:f0:a0"
                        )
                        and (
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["order"]
                            == 115792089210356248756420345214020892766061623724957744567843809356293439045923
                        )
                        and (
                            parse[0]["tbs_certificate"]["subject_public_key_info"][
                                "algorithm"
                            ]["parameters"]["field_id"]["parameters"]
                            == 115792089210356248756420345214020892766250353991924191454421193933289684991999
                        )
                    ):
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit-SM2"] += 1
                        pubkey = parse[0]["tbs_certificate"]["subject_public_key_info"][
                            "public_key"
                        ].replace(":", "")
                        if (len(pubkey) != 130) or (pubkey[0:2] != "04"):
                            print(str(certItem["_id"]["$oid"]))
                            print(
                                "ERROR SM2 faulty OID: Did not found an uncompressed key with expected length!"
                            )
                        else:
                            x = bytes.fromhex(pubkey[2:66])
                            y = bytes.fromhex(pubkey[66:130])
                            valid = sm2keyval(x, y)
                            if valid == False:
                                # Key validation failed!
                                logInvalid(cert, certItem, "SM2")
                    else:
                        # Add explicit parameter curve to set of curves
                        curveCount["explicit"] += 1
                        explicit.append(certItem)

                elif "Invalid key" in str(X):
                    # A standard curve was found, but the key validation failed! Get the curve manually and log it.
                    certdec = base64.b64decode(certItem["cert_data"])
                    parse = jc_parse_relaxed("x509_cert", certdec)
                    curve = parse[0]["tbs_certificate"]["subject_public_key_info"][
                        "algorithm"
                    ]["parameters"]
                    curveCount[curve] += 1
                    logInvalid(cert, certItem, curve)
                    invalidReasonCount[curve + "_LibraryFailed"] += 1

                else:
                    exceptionPubKey.append(certItem)
                    print(
                        "Further exception during pubKey loading from Cert in Cert id: "
                        + str(certItem["_id"])
                    )
                    print(X)
                    print("\n")

                continue

            # Add curve to set of curves
            curveCount[pubKey.curve.name] += 1

    with open(certs_file, "rb") as f:
        certs = json.load(f)
    run(certs)
    return (
        curveCount,
        invalidCount,
        invalidChainCount,
        invalidCACount,
        invalidReasonCount,
        parseErrors,
        explicit,
        exceptionPubKey,
        keyInvalid,
        invalidCertNames.getvalue(),
    )


try:
    from itertools import batched
except ImportError:

    def batched(iterable, n, *, strict=False):
        # batched('ABCDEFG', 3) → ABC DEF G
        if n < 1:
            raise ValueError("n must be at least one")
        iterator = iter(iterable)
        while batch := tuple(itertools.islice(iterator, n)):
            if strict and len(batch) != n:
                raise ValueError("batched(): incomplete batch")
            yield batch


def parallel_checks(
    cert_dir_path: str, refresh: bool = True
) -> tuple[Counter, Counter, Counter, Counter, Counter, Counter, list, list, list, str]:
    """
    Run the ECC certificate checks in parallel using multiprocessing.
    """
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    start = datetime.now()
    json_cache.start_timer()
    print("## Start of ECC cert check ##\n")
    print(start)

    cert_files = [
        os.path.join(cert_dir_path, f)
        for f in os.listdir(cert_dir_path)
        if f.endswith(".json")
    ]
    print(f"Found {len(cert_files)} files in {cert_dir_path}")
    processes = min(len(cert_files), MAX_PROCS)
    print(f"Starting {processes} processes")
    results = []
    with Pool(processes, maxtasksperchild=1) as pool:
        for i, res in enumerate(pool.imap_unordered(check, cert_files)):
            results.append(res)
            print(f"{i}/{len(cert_files)}")

    print("Combining")

    # Combine results from all processes
    curveCount = Counter()
    invalidCount = Counter()
    invalidChainCount = Counter()
    invalidCACount = Counter()
    invalidReasonCount = Counter()
    parseErrors = Counter()
    explicit = []
    exceptionPubKey = []
    keyInvalid = []
    invalidCertNames = io.StringIO()

    for (
        _curveCount,
        _invalidCount,
        _invalidChainCount,
        _invalidCACount,
        _invalidReasonCount,
        _parseErrors,
        _explicit,
        _exceptionPubKey,
        _keyInvalid,
        _invalidCertNamesValue,
    ) in results:
        curveCount.update(_curveCount)
        invalidCount.update(_invalidCount)
        invalidChainCount.update(_invalidChainCount)
        invalidCACount.update(_invalidCACount)
        invalidReasonCount.update(_invalidReasonCount)
        parseErrors.update(_parseErrors)
        explicit.extend(_explicit)
        exceptionPubKey.extend(_exceptionPubKey)
        keyInvalid.extend(_keyInvalid)
        invalidCertNames.write(_invalidCertNamesValue)

    end = datetime.now()
    diff = end - start

    print("\n## End of ECC cert check ##")
    print(end)
    print("Duration: ")
    print(diff)

    res = [
        curveCount,
        invalidCount,
        invalidChainCount,
        invalidCACount,
        invalidReasonCount,
        parseErrors,
        explicit,
        exceptionPubKey,
        keyInvalid,
        invalidCertNames.getvalue(),
    ]
    json_cache.save(cache_name, res)
    return res


def print_results(
    res: tuple[
        Counter, Counter, Counter, Counter, Counter, Counter, list, list, list, str
    ],
):
    (
        curveCount,
        invalidCount,
        invalidChainCount,
        invalidCACount,
        invalidReasonCount,
        parseErrors,
        explicit,
        exceptionPubKey,
        keyInvalid,
        invalidCertNamesValue,
    ) = res
    if WRITE_EXCEPTION_FILES:
        # Dump exceptions-files:
        with open("explicit.json", "w") as f:
            try:
                json.dump(explicit, f)
            except Exception as Y:
                print("failure: explicit dump invalid")
                print(Y)
                print(len(explicit))
        with open("exceptionPubKey.json", "w") as f:
            try:
                json.dump(exceptionPubKey, f)
            except Exception as Y:
                print("failure: exceptionPubKey dump invalid")
                print(Y)
                print(len(exceptionPubKey))
        with open("keyInvalid.json", "w") as f:
            try:
                json.dump(keyInvalid, f)
            except Exception as Y:
                print("failure: keyInvalid dump invalid")
                print(Y)
                print(len(keyInvalid))
        with open("invalidCertsNames.log", "w") as f:
            try:
                f.write(invalidCertNamesValue)
            except Exception as Y:
                print("failure: dump invalidCertNames")
                print(Y)

    print(
        f"Number of explicit curves that could not be assigned to a defined curve: {len(explicit)}"
    )
    print(f"Number of further exceptions in load PubKey: {len(exceptionPubKey)}")
    print("Number of parsed certificates with curves: ")
    pprint(dict(curveCount))
    print()

    print("##### Invalid public ECC Keys: #####")
    print(f"Number of key Validation errors: {len(keyInvalid)}")
    pprint(dict(invalidCount))
    print()

    print("Invalid certs categorized by chain:")
    pprint(dict(invalidChainCount))
    print()

    print("Invalid certs categorized by CA and curve:")
    pprint(dict(invalidCACount))
    print("Invalid certs categorized by reason for invalidity:")
    print()

    pprint(dict(invalidReasonCount))
    print()

    print("Public keys that could not be parsed:")
    pprint(dict(parseErrors))


WRITE_EXCEPTION_FILES = False
CERTS_DIR = os.path.join("assets", "ec_certs")
MAX_PROCS = 80
if __name__ == "__main__":
    refresh = len(sys.argv) > 1 and sys.argv[1] == "refresh"
    certs = save_ec_certs(refresh=refresh)
    print("Loaded certs")
    res = parallel_checks(CERTS_DIR, refresh=refresh)
    print_results(res)

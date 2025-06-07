# Processing

These scripts automate various tasks related to S/MIME certificate processing and verification. 

They were run automatically while importing certificates into the MongoDB database.

`run.py` provides a command-line interface to execute them manually for testing purposes.

## Usage
Use the `run.py` script to run all processing tasks. 
It accepts JSON input from standard input or a file, and outputs the results in JSON format.
```shell
cat assets/example_cert.json | python run.py certs > results.json
cat assets/example_host.json | python run.py hosts
```

For convenience, you can also input raw data without the need to create a JSON object:
```shell
echo "MIIDdzCCAl+gAwIBAgIEbQ0f..." | python run.py certs
echo "23.115.93.66" | python run.py hosts
```

Using the argument `certs` will run all tasks related to certificates (see below), while `hosts` will run tasks related to hosts.

[\_\_init\_\_.py](__init__.py) contains modifications 
- to the `jc` library to suppress errors and allow parsing of non-conforming certificates.
- to the `badkeys` library to handle exceptions.
- to the `pkilint` library to resolve OIDs in the output and handle exceptions.
We used the `pkilint` library at commit [5b9b884](https://github.com/digicert/pkilint/tree/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e)
and applied a few minor modifications to it, which are included in the file [pkilint.patch](pkilint.patch).
## Tasks

### Certificates
#### [parse_cert_task.py](tasks/parse_cert_task.py)
First task, parses the certificate to JSON using the `jc` library.

#### [badkeys_task.py](tasks/badkeys_task.py)
Uses the `badkeys` library to check if a certificate's public key is compromised.

#### [cert_chains_task.py](tasks/cert_chains_task.py)
Uses our `smime-chain-verifier` tool to verify the certificate chain of a given S/MIME certificate.
Depends on the redis cache being available and populated with CA certificates.

#### [is_ca_task.py](tasks/is_ca_task.py)
Labels the certificate as a Certificate Authority based on the basic_constraints extension.

#### [is_smime_task.py](tasks/is_smime_task.py)
Labels a certificate as an S/MIME certificate as described in the S/MINE paper.

#### [lint_smime_cert_task.py](tasks/lint_smime_cert_task.py)
Uses the `pkilint` library to lint S/MIME certificates, checking for common issues and compliance with standards.

#### [pwnedkeys_task.py](tasks/pwnedkeys_task.py)
Uses the `pwnedkeys` library to check if a certificate's public key has been compromised in known data breaches.

#### [factordb_task.py](tasks/factordb_task.py)
Uses the `factordb` library to check if a certificate's public key is listed in the FactorDB, a database of factored RSA keys.

### Hosts

#### [geoip_task.py](tasks/geoip_task.py)
Uses the `geoip2` library to determine the geographical location of an IP address associated with a host.
Requires the `GeoLite2-Country` database (can be downloaded at https://dev.maxmind.com/geoip/geoip2/geolite2/) to be available in the `processing` directory.

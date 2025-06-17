# S/MINE: Collecting and Analyzing S/MIME Certificates at Scale

Welcome to the S/MINE artifacts repository! This repository provides the resources needed to examine and reproduce our work.

## Abstract
We report on the first broad analysis of real-world S/MIME certificates for digitally signing and encrypting emails. 
We collected more than 41 million unique X.509 certificates from public address books, i.e., LDAP servers, 
of which 38 million fulfill the requirements for use with S/MIME in email clients. 
Despite the surprisingly complex construction of trust chains for S/MIME certificates, 
we could build chains for a large subset of certificates and show which are trusted in widely used applications. 
Our results show that many of those S/MIME certificates are issued by non-publicly trusted CAs.

Our analysis of the cryptographic keys, certificate attributes, and new regulations, i.e., the CA/Browser Forum's S/MIME Baseline Requirements, 
shows that the S/MIME PKI is generally heading in the right direction. 
Most certificates using compromised or weak key material have expired, weak cryptographic algorithms are being phased out, 
and CAs are generally issuing more secure certificates. 
However, the underlying RFCs and email clients should be more stringent about what is considered an S/MIME certificate. 
Additionally, CAs should improve the distribution of certificate chains to improve user experience and security.

## Contents
This repository consists of the following subdirectories:
- [**Server IPs**](server_ips): Contains the IP addresses of the servers discovered by our zmap scans on ports 389 and 636 as well as the IP addresses of the servers from which we collected certificates.
- [**LDAP Crawler**](ldap_crawler): Our tool for crawling LDAP servers to collect S/MIME certificates.
- [**Processing**](processing): Scripts used to parse and process the collected certificates.
- [**Chain Verification**](chain_verification): Tool that reconstructs and verifies the certificate chains, used in processing.
- [**Analysis**](analysis): Scripts for analyzing the collected certificates and generating statistics.


Each subdirectory contains a `README.md` file with more detailed information about its contents and usage.

## Usage
To use the tools and scripts in this repository, you will need to have Python >=3.10 installed along with the required dependencies.
We recommend using a virtual environment to manage dependencies.

```shell
apt install libsasl2-dev python-dev-is-python3 libldap2-dev libssl-dev
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=$(pwd)
```

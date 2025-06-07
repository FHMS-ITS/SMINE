# Certificate Crawler

This folder contains the LDAP crawler, which downloads X.509 certificates from LDAP servers and stores them in JSON format.

LDAP servers are used, among other purposes, to distribute S/MIME certificates to PKI participants.  
Downloading an S/MIME certificate from an LDAP server usually requires a specific LDAP search request for the entry (e.g., a specific `cn` such as `cn="John Doe"`).  
This requires prior knowledge of the name to be queried.  
However, if you want to download certificates from an LDAP server **without** explicitly knowing the DNs of the entries, this may be challenging.

Many servers allow wildcard searches like `cn="John*"` so that the full `cn` does not need to be specified.  
However, if the search query returns more results than the LDAP server’s configured size limit allows, an LDAP `SizeLimitExceeded` response is returned.

The LDAP crawler iterates over the alphabet and sends sequential LDAP wildcard search requests, using the `SizeLimitExceeded` response as an indicator to further narrow the search query.

For example, assuming an LDAP server allows wildcard searches, the crawler might start with `cn="a*"`.  
If the LDAP server returns results, the crawler proceeds to the next letter: `cn="b*"`.  
If a query returns more results than the server’s size limit allows, it will typically return a `SizeLimitExceeded` response.  
The crawler then refines the search by recursively appending another letter to the search string, e.g., `cn="ba*"`.  
This continues until the search query is specific enough that actual results are returned instead of a size limit response.

---

## Usage

Install requirements:

```shell
pip install -r requirements.txt
```

## Run the Crawler

Execute the crawler for a given IP address and port (389 and/or 636).  
Also specify an output directory where the results should be written::

```shell
python crawler.py <ip>,<port>[,<port>] <crawling results output directory>
# eg.:
python crawler.py 127.0.0.1,636,389 /crawls
```

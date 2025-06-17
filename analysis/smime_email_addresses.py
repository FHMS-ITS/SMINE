import logging
import sys
import os
from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import aggregate_certs_batchwise
from analysis.utils.cache import JsonCacheManager, get_cache_name
import re
from collections import Counter

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_tranco_list():
    with open("assets/tranco-VQ2QN.csv") as fp:
        domains_list = fp.readlines()

    new_domains = set()
    for domain in domains_list:
        rank, domain = domain.split(",")
        domain = domain.strip()
        new_domains.add(domain.lower())
    return new_domains


def count_tranco(counted_email_list, certs_with_email, freemail_domains):
    tranco_domains = get_tranco_list()

    cert_domain_count = Counter()
    for cert in certs_with_email:
        cert_domain_count.update(
            list({email.split("@")[1].lower() for email in cert})
        )  # extract domains

    total_non_unique_email_addrs = 0
    tranco_counter = 0
    tranco_certs_counter = 0
    tranco_nonfree_counter = 0
    tranco_nonfree_certs_counter = 0

    for domain, count in counted_email_list.items():
        total_non_unique_email_addrs += count
        if domain in tranco_domains:
            tranco_counter += count
            if domain not in freemail_domains:
                tranco_nonfree_counter += 1
    for domain, count in cert_domain_count.items():
        if domain in tranco_domains:
            tranco_certs_counter += count
            if domain not in freemail_domains:
                tranco_nonfree_certs_counter += 1
    print(f"Total Email Address (non-unqiue): {total_non_unique_email_addrs:,}")
    print(
        f"Total Tranco Addresses:\t\t\t{tranco_counter:,}/{total_non_unique_email_addrs:,} ({tranco_counter / total_non_unique_email_addrs:.2%})"
    )
    print(
        f"Certs with at least one tranco address:\t{tranco_certs_counter:,}/{len(certs_with_email):,} ({tranco_certs_counter / len(certs_with_email):.2%})"
    )

    print(
        f"Total Tranco Addresses (non-free):\t\t\t{tranco_nonfree_counter:,}/{total_non_unique_email_addrs:,} ({tranco_nonfree_counter / total_non_unique_email_addrs:.2%})"
    )
    print(
        f"Certs with at least one tranco address (non-free):\t{tranco_nonfree_certs_counter:,}/{len(certs_with_email):,} ({tranco_nonfree_certs_counter / len(certs_with_email):.2%})"
    )

    intersection = tranco_domains.intersection(set(cert_domain_count.keys()))
    print(f"Tranco Domains with at least one cert:\t\t\t{len(intersection):,}")


def process_addresses(result):
    """Takes the mongodb result (list of documents with a set of unqiue email addresses per cert)
    and reads all email addresses per document, makes them lower case and add them to list (not a set).
    Then the domains are extracted and their occurence are counted."""

    all_email_addresses_cleaned = []
    all_domains_list = []

    email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    email_regex = re.compile(
        r"^[\w\!#\$%&'\*\+\/\=\?`\{\|\}~\^\.\-]+@([\w\-]+\.)+[\w\-]+$"
    )
    certs_with_email = []
    for entry in result:
        # get list of strings/possible emails addresses per document
        e_addresses_list = entry.get("allemails")
        cert_addresses = [
            addr.lower()
            for addr in e_addresses_list
            if isinstance(addr, str) and email_regex.match(addr)
        ]
        all_email_addresses_cleaned.extend(cert_addresses)  # extract email addresses
        if len(cert_addresses) > 0:
            certs_with_email.append(cert_addresses)

    for email_addr in all_email_addresses_cleaned:
        _, domain = email_addr.split("@")
        all_domains_list.append(domain.lower())  # extract domains

    all_domains_counted = Counter(all_domains_list)  # count domains occurence
    print(f"Certs that contain at least one email address: {len(certs_with_email):,}")
    print(f"unique domains in total: {len(set(all_domains_list)):,}")
    return all_domains_counted, certs_with_email


def count_freemail_domains(
    counted_email_list: Counter, certs_with_email, freemail_domains
):
    """Loads a list of freemail domains (https://gist.github.com/okutbay/5b4974b70673dfdcc21c517632c1f984).
    Takes the counted email address domains as list and looks up the domains in the domain list.
    The freemail domains are counted in total."""

    print("Per unique emails")
    print(f"Rank\t{'Domain':20}\t{'E-Mails':9}\tFree Mail")
    for i, domain_count in enumerate(counted_email_list.most_common(20)):
        print(
            f"{i + 1:4}\t{domain_count[0]:20}\t{domain_count[1]:9,}\t{domain_count[0] in freemail_domains}"
        )
    only_once = 0
    for domain, count in counted_email_list.items():
        if count == 1:
            only_once += 1

    cert_domain_count = Counter()
    for cert in certs_with_email:
        cert_domain_count.update(
            list({email.split("@")[1].lower() for email in cert})
        )  # extract domains

    print("Per cert with unique domains")
    print(f"Rank\t{'Domain':20}\t{'E-Mails':9}\tFree Mail")
    for i, domain_count in enumerate(cert_domain_count.most_common(20)):
        print(
            f"{i + 1:4}\t{domain_count[0]:20}\t{domain_count[1]:9,}\t{domain_count[0] in freemail_domains}"
        )

    total_non_unique_email_addrs = 0
    free_mail_counter = 0
    free_mail_certs_counter = 0

    for domain, count in counted_email_list.items():
        total_non_unique_email_addrs += count  # count all domains
        if domain in freemail_domains:  # count freemail domains
            free_mail_counter += count

    for domain, count in cert_domain_count.items():
        if domain in freemail_domains:  # count freemail domains
            free_mail_certs_counter += count

    print(
        f"Total Freemail Addresses:\t\t\t{free_mail_counter:,}/{total_non_unique_email_addrs:,} ({free_mail_counter / total_non_unique_email_addrs:.2%})"
    )
    print(
        f"Certs with at least one freemail address:\t{free_mail_certs_counter:,}/{len(certs_with_email):,} ({free_mail_certs_counter / len(certs_with_email):.2%})"
    )
    print(f"Domains only in one certificate: {only_once:,}")


def get_email_addresses(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "S/MIME certificate email domains"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment, "loaded")
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$project": {
                "_id": 0,
                "allemails": {
                    "$setUnion": [
                        {
                            "$filter": {
                                "input": {
                                    "$cond": [
                                        {
                                            "$isArray": "$cert_fields.tbs_certificate.subject.email_address"
                                        },
                                        "$cert_fields.tbs_certificate.subject.email_address",
                                        [
                                            {
                                                "$cond": [
                                                    {
                                                        "$ne": [
                                                            "$cert_fields.tbs_certificate.subject.email_address",
                                                            None,
                                                        ]
                                                    },
                                                    "$cert_fields.tbs_certificate.subject.email_address",
                                                    None,
                                                ]
                                            }
                                        ],
                                    ]
                                },
                                "as": "item",
                                "cond": {"$ne": ["$$item", None]},
                            }
                        },
                        {
                            "$filter": {
                                "input": {
                                    "$cond": [
                                        {
                                            "$isArray": "$extensions.subject_alt_name.value"
                                        },
                                        "$extensions.subject_alt_name.value",
                                        [
                                            {
                                                "$cond": [
                                                    {
                                                        "$ne": [
                                                            "$extensions.subject_alt_name.value",
                                                            None,
                                                        ]
                                                    },
                                                    "$extensions.subject_alt_name.value",
                                                    None,
                                                ]
                                            }
                                        ],
                                    ]
                                },
                                "as": "item",
                                "cond": {"$ne": ["$$item", None]},
                            }
                        },
                    ]
                },
            }
        },
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)

    json_cache.save(cache_name, result, comment=comment)
    return result


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)
    refresh_flag = False

    if len(sys.argv) > 2:
        print("Usage: %s [refresh]", sys.argv[0])
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == "refresh":
            refresh_flag = True

    result = get_email_addresses(refresh=refresh_flag)

    with open("assets/freemail_domains.txt", "r") as fp:
        freemail_domains = {line.strip().lower() for line in fp}

    all_domains_counted, certs_with_email = process_addresses(result)
    count_tranco(all_domains_counted, certs_with_email, freemail_domains)
    count_freemail_domains(all_domains_counted, certs_with_email, freemail_domains)

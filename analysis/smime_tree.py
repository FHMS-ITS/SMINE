import logging
from analysis.utils.log import set_up_logging
import os
import sys

from analysis.utils.aggregate import aggregate_certs, aggregate_certs_batchwise
from analysis.utils.cache import JsonCacheManager, get_cache_name

logger = logging.getLogger()
CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_total_certs_count(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Number of total certificates"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"{result.get('count'):,} (100%)")
        return result.get("count")

    pipeline = [{"$sort": {"_id": 1}}, {"$count": "totalDocuments"}]

    result1 = aggregate_certs(pipeline=pipeline)
    totalCerts = result1[0].get("totalDocuments")

    json_cache.save(cache_name, {"count": totalCerts}, comment=comment)
    print(comment)
    print(f"{totalCerts:,} (100%)")
    return totalCerts


def get_key_usage_count(total_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = (
        "no ku_ext or digital-signature or non-repudiation or key-encipherment / ow"
    )
    if not refresh and (result := json_cache.load(cache_name)):
        ku_count = result.get("ku_count")
        print(f"### {comment}:")
        print(f"{ku_count:,} ({round((ku_count / total_count) * 100, 2)}%)")
        print("### otherwise (total - ku_count):")
        print(
            f"{(total_count - ku_count):,} ({round(((total_count - ku_count) / total_count) * 100, 2)}%)"
        )
        return ku_count

    pipeline = [
        {
            "$match": {
                "$or": [
                    {"is_smime.ku_extension": False},
                    {"is_smime.digital_signature": True},
                    {"is_smime.non_repudiation": True},
                    {"is_smime.key_encipherment": True},
                ]
            }
        },
        {"$count": "count"},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    ku_count = sum(r.get("count") for r in result)
    json_cache.save(
        cache_name,
        {"ku_count": ku_count, "ow_count": total_count - ku_count},
        comment=comment,
    )
    print(f"### {comment}:")
    print(f"{ku_count:,} ({round((ku_count / total_count) * 100, 2)}%)")
    print("### otherwise (total - ku_count):")
    print(
        f"{(total_count - ku_count):,} ({round(((total_count - ku_count) / total_count) * 100, 2)}%)"
    )
    return ku_count


def get_extended_key_usage_count(ku_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "(no ku_ext or digital-signature or non-repudiation or key-encipherment) and eku_ext/no eku_ext"
    if not refresh and (result := json_cache.load(cache_name)):
        eku_count = result.get("eku_count")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku:"
        )
        print(f"{eku_count:,} ({round((eku_count / ku_count) * 100, 2)}%)")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and no eku:"
        )
        print(
            f"{(ku_count - eku_count):,} ({round(((ku_count - eku_count) / ku_count) * 100, 2)}%)"
        )
        return eku_count, ku_count - eku_count

    pipeline = [
        {
            "$match": {
                "$and": [
                    {"is_smime.eku_extension": True},
                    {
                        "$or": [
                            {"is_smime.ku_extension": False},
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                            {"is_smime.key_encipherment": True},
                        ]
                    },
                ]
            }
        },
        {"$count": "count"},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    eku_count = sum(r.get("count") for r in result)
    json_cache.save(
        cache_name,
        {"eku_count": eku_count, "no_eku_count": ku_count - eku_count},
        comment=comment,
    )
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku:"
    )
    print(f"{eku_count:,} ({round((eku_count / ku_count) * 100, 2)}%)")
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and no eku:"
    )
    print(
        f"{(ku_count - eku_count):,} ({round(((ku_count - eku_count) / ku_count) * 100, 2)}%)"
    )
    return eku_count, ku_count - eku_count


def get_no_eku_and_email_count(no_eku_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "(No ku or digital_signature or non_repudiation or key_encipherment) and no eku and email/no email"
    if not refresh and (result := json_cache.load(cache_name)):
        email_count = result.get("email_count")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and no eku and email:"
        )
        print(f"{email_count:,} ({round((email_count / no_eku_count) * 100, 2)}%)")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and no eku and no email:"
        )
        print(
            f"{(no_eku_count - email_count):,} ({round(((no_eku_count - email_count) / no_eku_count) * 100, 2)}%)"
        )
        return

    pipeline = [
        {
            "$match": {
                "$and": [
                    {"is_smime.eku_extension": False},
                    {
                        "$or": [
                            {"is_smime.ku_extension": False},
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                            {"is_smime.key_encipherment": True},
                        ]
                    },
                    {
                        "$or": [
                            {"is_smime.san_email": True},
                            {"is_smime.subj_email": True},
                        ]
                    },
                ]
            }
        },
        {"$count": "count"},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    email_count = sum(r.get("count") for r in result)
    json_cache.save(
        cache_name,
        {"email_count": email_count, "no_email_count": no_eku_count - email_count},
        comment=comment,
    )
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and no eku and email:"
    )
    print(f"{email_count:,} ({round((email_count / no_eku_count) * 100, 2)}%)")
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and no eku and no email:"
    )
    print(
        f"{(no_eku_count - email_count):,} ({round(((no_eku_count - email_count) / no_eku_count) * 100, 2)}%)"
    )


def get_eku_and_ep_or_any_count(eku_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "(No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku)/no"
    if not refresh and (result := json_cache.load(cache_name)):
        ep_or_any_count = result.get("ep_or_any_count")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku):"
        )
        print(f"{ep_or_any_count:,} ({round((ep_or_any_count / eku_count) * 100, 2)}%)")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and no (email_protection or any_eku):"
        )
        print(
            f"{(eku_count - ep_or_any_count):,} ({round(((eku_count - ep_or_any_count) / eku_count) * 100, 2)}%)"
        )
        return ep_or_any_count

    pipeline = [
        {
            "$match": {
                "$and": [
                    {"is_smime.eku_extension": True},
                    {
                        "$or": [
                            {"is_smime.ku_extension": False},
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                            {"is_smime.key_encipherment": True},
                        ]
                    },
                    {
                        "$or": [
                            {"is_smime.email_protection": True},
                            {"is_smime.any_eku": True},
                        ]
                    },
                ]
            }
        },
        {"$count": "count"},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    ep_or_any_count = sum(r.get("count") for r in result)
    json_cache.save(
        cache_name,
        {
            "ep_or_any_count": ep_or_any_count,
            "no_ep_or_any_count": eku_count - ep_or_any_count,
        },
        comment=comment,
    )
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku):"
    )
    print(f"{ep_or_any_count:,} ({round((ep_or_any_count / eku_count) * 100, 2)}%)")
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and no (email_protection or any_eku):"
    )
    print(
        f"{(eku_count - ep_or_any_count):,} ({round(((eku_count - ep_or_any_count) / eku_count) * 100, 2)}%)"
    )
    return ep_or_any_count


def get_ep_or_any_and_email_count(ep_or_any_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "(No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku) and no/email"
    if not refresh and (result := json_cache.load(cache_name)):
        ep_or_any_and_email_count = result.get("ep_or_any_and_email_count")
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku) and email:"
        )
        print(
            f"{ep_or_any_and_email_count:,} ({round((ep_or_any_and_email_count / ep_or_any_count) * 100, 2)}%)"
        )
        print(
            "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku) and no email:"
        )
        print(
            f"{(ep_or_any_count - ep_or_any_and_email_count):,} ({round(((ep_or_any_count - ep_or_any_and_email_count) / ep_or_any_count) * 100, 2)}%)"
        )
        return

    pipeline = [
        {
            "$match": {
                "$and": [
                    {"is_smime.eku_extension": True},
                    {
                        "$or": [
                            {"is_smime.ku_extension": False},
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                            {"is_smime.key_encipherment": True},
                        ]
                    },
                    {
                        "$or": [
                            {"is_smime.email_protection": True},
                            {"is_smime.any_eku": True},
                        ]
                    },
                    {
                        "$or": [
                            {"is_smime.san_email": True},
                            {"is_smime.subj_email": True},
                        ]
                    },
                ]
            }
        },
        {"$count": "count"},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    ep_or_any_and_email_count = sum(r.get("count") for r in result)
    json_cache.save(
        cache_name,
        {
            "ep_or_any_and_email_count": ep_or_any_and_email_count,
            "no_ep_or_any_and_email_count": ep_or_any_count - ep_or_any_and_email_count,
        },
        comment=comment,
    )
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku) and email:"
    )
    print(
        f"{ep_or_any_and_email_count:,} ({round((ep_or_any_and_email_count / ep_or_any_count) * 100, 2)}%)"
    )
    print(
        "### (No ku or digital_signature or non_repudiation or key_encipherment) and eku and (email_protection or any_eku) and no email:"
    )
    print(
        f"{(ep_or_any_count - ep_or_any_and_email_count):,} ({round(((ep_or_any_count - ep_or_any_and_email_count) / ep_or_any_count) * 100, 2)}%)"
    )


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)
    refresh_flag = False

    if len(sys.argv) > 2:
        print("Usage: %s [refresh]", sys.argv[0])
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == "refresh":
            refresh_flag = True

    print("\n###############################")
    cert_count = get_total_certs_count(refresh=refresh_flag)

    print("\n###############################")
    ku_count = get_key_usage_count(cert_count, refresh=refresh_flag)

    print("\n###############################")
    eku_count, no_eku_count = get_extended_key_usage_count(
        ku_count, refresh=refresh_flag
    )

    print("\n###############################")
    get_no_eku_and_email_count(no_eku_count, refresh=refresh_flag)

    print("\n###############################")
    ep_or_any_count = get_eku_and_ep_or_any_count(eku_count, refresh=refresh_flag)

    print("\n###############################")
    get_ep_or_any_and_email_count(ep_or_any_count, refresh=refresh_flag)

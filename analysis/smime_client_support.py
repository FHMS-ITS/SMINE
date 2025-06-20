import logging
from analysis.utils.log import set_up_logging
import os
import sys

from analysis.utils.aggregate import aggregate_certs_batchwise
from analysis.utils.cache import JsonCacheManager, get_cache_name

logger = logging.getLogger()
CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_total_certs_count(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Number of total certificates"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"{result.get('count'):,} (100\\%)")
        return result.get("count")

    pipeline = [{"$sort": {"_id": 1}}, {"$count": "count"}]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)

    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(f"{number_of_certs:,} (100\\%)")
    return number_of_certs


def get_email_no_ku_no_eku(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and no ku and no eku"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {"$match": {"is_smime.ku_extension": False}},
        {"$match": {"is_smime.eku_extension": False}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_ku_all_no_eku(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and ku=all and no eku"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.eku_extension": False}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_no_key_enc_eku_ep(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and no key enc and eku=ep"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": False},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.email_protection": True}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_no_key_enc_no_eku(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and no key enc and no eku"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": False},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.eku_extension": False}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_no_email_ku_all_eku_ep(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "no email and ku=all and eku=ep"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$and": [{"is_smime.subj_email": False}, {"is_smime.san_email": False}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.email_protection": True}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_ku_all_eku_ep(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and ku=all and eku=ep"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.email_protection": True}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_ku_all_eku_any(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and ku=all and eku=any"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.any_eku": True},
                    {"is_smime.email_protection": False},
                ]
            }
        },
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_no_ku_eku_any(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and no ku and eku=any"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {"$match": {"is_smime.ku_extension": False}},
        {
            "$match": {
                "$and": [
                    {"is_smime.any_eku": True},
                    {"is_smime.email_protection": False},
                ]
            }
        },
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_no_ku_eku_ep(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and no ku and eku=ep"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {"$match": {"is_smime.ku_extension": False}},
        {"$match": {"is_smime.email_protection": True}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_no_key_enc_eku_any(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and no key encipherment and eku=any"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": False},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.email_protection": False},
                    {"is_smime.any_eku": True},
                ]
            }
        },
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_only_key_enc_eku_ep(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and only key encipherment and eku=ep"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$and": [
                            {"is_smime.digital_signature": False},
                            {"is_smime.non_repudiation": False},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.email_protection": True}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_only_key_enc_eku_any(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and only key encipherment and eku=any"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$and": [
                            {"is_smime.digital_signature": False},
                            {"is_smime.non_repudiation": False},
                        ]
                    },
                ]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.email_protection": False},
                    {"is_smime.any_eku": True},
                ]
            }
        },
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_email_only_key_enc_no_eku(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "email and only key encipherment and no eku"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$or": [{"is_smime.subj_email": True}, {"is_smime.san_email": True}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$and": [
                            {"is_smime.digital_signature": False},
                            {"is_smime.non_repudiation": False},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.eku_extension": False}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_no_email_ku_all_eku_any(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "no email and ku=all and eku=any"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$and": [{"is_smime.subj_email": False}, {"is_smime.san_email": False}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.any_eku": True},
                    {"is_smime.email_protection": False},
                ]
            }
        },
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
    )


def get_no_email_ku_all_no_eku(total_certs_count, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "no email and ku=all and no eku"
    if not refresh and (result := json_cache.load(cache_name)):
        count = result.get("count")
        print(comment)
        print(f"{count:,} ({round((count / total_certs_count) * 100, 2)}\\%)")
        return

    pipeline = [
        {
            "$match": {
                "$and": [{"is_smime.subj_email": False}, {"is_smime.san_email": False}]
            }
        },
        {
            "$match": {
                "$and": [
                    {"is_smime.key_encipherment": True},
                    {
                        "$or": [
                            {"is_smime.digital_signature": True},
                            {"is_smime.non_repudiation": True},
                        ]
                    },
                ]
            }
        },
        {"$match": {"is_smime.eku_extension": False}},
        {"$count": "count"},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    number_of_certs = sum(r.get("count", 0) for r in result)
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(
        f"{number_of_certs:,} ({round((number_of_certs / total_certs_count) * 100, 2)}\\%)"
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
    total_certs_count = get_total_certs_count(refresh=refresh_flag)

    print("\n###############################")
    get_email_ku_all_eku_ep(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_ku_all_eku_any(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_ku_all_no_eku(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_no_ku_eku_ep(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_no_ku_eku_any(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_no_ku_no_eku(total_certs_count, refresh=refresh_flag)

    # Encryption Certificates
    print("\nEncryption Certificates:")
    print("\n###############################")
    get_email_only_key_enc_eku_ep(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_only_key_enc_eku_any(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_only_key_enc_no_eku(total_certs_count, refresh=refresh_flag)

    # Signing Certificates
    print("\nSigning Certificates:")
    print("\n###############################")
    get_email_no_key_enc_eku_ep(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_no_key_enc_eku_any(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_email_no_key_enc_no_eku(total_certs_count, refresh=refresh_flag)

    # General Purpose (no Email)
    print("\nGeneral Purpose (No Email)")
    print("\n###############################")
    get_no_email_ku_all_eku_ep(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_no_email_ku_all_eku_any(total_certs_count, refresh=refresh_flag)

    print("\n###############################")
    get_no_email_ku_all_no_eku(total_certs_count, refresh=refresh_flag)

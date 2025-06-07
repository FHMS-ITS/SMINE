import logging
from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import aggregate_certs
from analysis.utils.cache import JsonCacheManager, get_cache_name
import os
import sys
import json

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_total_rsa_keys_smime(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Number of total RSA keys"
    if not refresh and (result := json_cache.load(cache_name)):
        total_keys = result.get("count_rsa_keys")
        print(comment)
        print(total_keys)
        return total_keys

    pipeline = [
        {
            "$match": {
                "cert_fields.tbs_certificate.subject_public_key_info.algorithm.algorithm": "rsa"
            }
        },
        {"$match": {"is_smime.is_smime": True}},
        {"$count": "total_rsa_keys"},
    ]

    result = aggregate_certs(pipeline=pipeline)
    count_rsa_keys = result[0].get("total_rsa_keys")
    print(comment)
    print(f"{count_rsa_keys:,}")
    json_cache.save(cache_name, {"count_rsa_keys": count_rsa_keys}, comment=comment)
    return count_rsa_keys


def get_factordb_status_smime(total_rsa_keys: int, refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Factordb status codes for S/MIME certificates"
    if not refresh and (result := json_cache.load(cache_name, all=True)):
        print(comment)
        print(result.get("latex_str"))
        return

    pipeline = [
        {
            "$match": {
                "cert_fields.tbs_certificate.subject_public_key_info.algorithm.algorithm": "rsa"
            }
        },
        {"$match": {"is_smime.is_smime": True}},
        {
            "$group": {
                "_id": {"status": "$factordb.status", "error": "$factordb.error_type"},
                "total": {"$sum": 1},
            }
        },
    ]

    result = aggregate_certs(pipeline=pipeline)
    latex_str_list = ["factordb status & \\# \\\\"]
    for entry in result:
        e_status = entry.get("_id").get("status")
        # e_error = entry.get("_id").get("error")
        e_total = entry.get("total")
        latex_str_list.append(
            f"{e_status} & {e_total:,} ({round((e_total / total_rsa_keys) * 100, 2):,})\\\\"
        )
    latex_str = "\n".join(latex_str_list)
    print(latex_str)
    json_cache.save(cache_name, result, latex_str=latex_str, comment=comment)


def categorize_entries(result_dict):
    total_pwned = 0
    total_pub_trusted_expired = 0  # chrome, mozilla, macos, microsoft
    total_pub_trusted_not_expired = 0
    total_valid_chain_expired = 0
    total_valid_chain_not_expired = 0
    total_no_chain_expired = 0
    total_no_chain_not_expired = 0
    total_not_categorized_entries = 0

    for entry in result_dict:
        e_total_per_group = entry.get("total_per_group")
        total_pwned += e_total_per_group
        e_publicly_trusted = entry.get("publicly_trusted")
        e_historical = entry.get("historical")
        e_validation_result = entry.get("val_result")

        if (
            e_publicly_trusted is True
            and e_validation_result == "VALID"
            and e_historical is True
        ):
            total_pub_trusted_expired += e_total_per_group
        elif (
            e_publicly_trusted is True
            and e_validation_result == "VALID"
            and e_historical is False
        ):
            total_pub_trusted_not_expired += e_total_per_group
        elif (
            e_publicly_trusted is False
            and e_validation_result == "VALID"
            and e_historical is True
        ):
            total_valid_chain_expired += e_total_per_group
        elif (
            e_publicly_trusted is False
            and e_validation_result == "VALID"
            and e_historical is False
        ):
            total_valid_chain_not_expired += e_total_per_group
        elif e_validation_result != "VALID" and e_historical is True:
            total_no_chain_expired += e_total_per_group
        elif e_validation_result != "VALID" and e_historical is False:
            total_no_chain_not_expired += e_total_per_group
        else:
            total_not_categorized_entries += e_total_per_group
            print("Entry could not be categorized")
            print(json.dumps(entry, indent=4))

    categorized_result = {
        "total_pwned": total_pwned,
        "total_pub_trusted_expired": total_pub_trusted_expired,
        "total_pub_trusted_not_expired": total_pub_trusted_not_expired,
        "total_valid_chain_expired": total_valid_chain_expired,
        "total_valid_chain_not_expired": total_valid_chain_not_expired,
        "total_no_chain_expired": total_no_chain_expired,
        "total_no_chain_not_expired": total_no_chain_not_expired,
        "total_not_categorized_entries": total_not_categorized_entries,
    }

    print(f"total pwned: {total_pwned:,} (100\\%)")
    print(
        f"total pub trusted expired: {total_pub_trusted_expired:,} ({round((total_pub_trusted_expired / total_pwned) * 100, 2)}\\%)"
    )
    print(
        f"total pub trusted not expired: {total_pub_trusted_not_expired:,} ({round((total_pub_trusted_not_expired / total_pwned) * 100, 2)}\\%)"
    )
    print(
        f"total valid chain expired: {total_valid_chain_expired:,} ({round((total_valid_chain_expired / total_pwned) * 100, 2)}\\%)"
    )
    print(
        f"total valid chain not expired: {total_valid_chain_not_expired:,} ({round((total_valid_chain_not_expired / total_pwned) * 100, 2)}\\%)"
    )
    print(
        f"total no chain expired: {total_no_chain_expired:,} ({round((total_no_chain_expired / total_pwned) * 100, 2)}\\%)"
    )
    print(
        f"total no chain not expired: {total_no_chain_not_expired:,} ({round((total_no_chain_not_expired / total_pwned) * 100, 2)}\\%)"
    )
    print(
        f"total not categorized entries: {total_not_categorized_entries:,} ({round((total_not_categorized_entries / total_pwned) * 100, 2)}\\%)"
    )

    return categorized_result


def get_chain_stats_for_factordb_smime_certificates(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Chain stats for factordb affected S/MIME certificates"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        categorize_entries(result)
        # print(json.dumps(result, indent=4))
        return

    pipeline = [
        {
            "$match": {
                "$and": [
                    {"is_smime.is_smime": True},
                    {
                        "$or": [
                            {"factordb.status": "PRP"},
                            {"factordb.status": "P"},
                            {"factordb.status": "CF"},
                            {"factordb.status": "FF"},
                        ]
                    },
                ]
            }
        },
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
                "cert_fields.tbs_certificate.issuer": 1,
                "cert_fields.tbs_certificate.validity": 1,
            }
        },
        {
            "$group": {
                "_id": {
                    "issuer": "$cert_fields.tbs_certificate.issuer",
                    "publicly_trusted": {
                        "$or": [
                            {"$eq": ["$chain.origin_info.mozilla", 1]},
                            {"$eq": ["$chain.origin_info.microsoft", 1]},
                            {"$eq": ["$chain.origin_info.macOS", 1]},
                            {"$eq": ["$chain.origin_info.chrome", 1]},
                        ]
                    },
                    "historical": "$chain.validation.historical",
                    "val_result": "$chain.validation.validation_result",
                },
                "total_per_issuer": {"$sum": 1},
                "ids": {"$push": "$_id"},
                "not_before": {
                    "$push": "$cert_fields.tbs_certificate.validity.not_before_iso"
                },
                "not_after": {
                    "$push": "$cert_fields.tbs_certificate.validity.not_after_iso"
                },
            }
        },
        {
            "$set": {
                "max_not_after": {"$max": "$not_after"},
                "min_not_before": {"$min": "$not_before"},
            }
        },
        {
            "$group": {
                "_id": {
                    "publicly_trusted": "$_id.publicly_trusted",
                    "historical": "$_id.historical",
                    "val_result": "$_id.val_result",
                },
                "issuers": {
                    "$push": {
                        "issuer": "$_id.issuer",
                        "total_per_issuer": "$total_per_issuer",
                        "min_not_before": "$min_not_before",
                        "max_not_after": "$max_not_after",
                        "ids": "$ids",
                    }
                },
                "total_per_group": {"$sum": "$total_per_issuer"},
            }
        },
        {
            "$set": {
                "publicly_trusted": "$_id.publicly_trusted",
                "historical": "$_id.historical",
                "val_result": "$_id.val_result",
            }
        },
        {"$project": {"_id": 0}},
        {"$sort": {"total_per_group": -1}},
    ]

    logger.info("Executing factordb chain stats query")
    result = aggregate_certs(pipeline=pipeline)
    categorize_entries(result)

    json_cache.save(cache_name, result, comment=comment)


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)
    refresh_flag = False

    if len(sys.argv) > 2:
        print("Usage: %s [refresh]", sys.argv[0])
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == "refresh":
            refresh_flag = True

    total_rsa_keys = get_total_rsa_keys_smime(refresh=refresh_flag)
    get_factordb_status_smime(total_rsa_keys, refresh=refresh_flag)

    get_chain_stats_for_factordb_smime_certificates(refresh=refresh_flag)

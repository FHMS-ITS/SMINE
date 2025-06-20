import json
import logging
from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import (
    aggregate_certs,
    reduce_groups,
    aggregate_certs_batchwise,
)
from analysis.utils.cache import JsonCacheManager, get_cache_name
import os
import sys

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


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


def get_affected_certs_count(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "SMIME certificates containing a weak key"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        categorize_entries(result)
        # print(json.dumps(result, indent=4))
        return

    pipeline = [  # exlude certificates with no chain validation result. These certifcates could not be parsed by cryptography
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {"$set": {"chain": {"$arrayElemAt": ["$chain.chain", 0]}}},
        {
            "$match": {
                "$and": [
                    {"is_smime.is_smime": True},
                    {"chain.validation.validation_result": {"$exists": True}},
                    {
                        "$or": [
                            {"badkeys.results.rsainvalid": {"$exists": True}},
                            {"badkeys.results.roca": {"$exists": True}},
                            {"badkeys.results.fermat": {"$exists": True}},
                            {"badkeys.results.pattern": {"$exists": True}},
                            {"badkeys.results.smallfactors": {"$exists": True}},
                            {"badkeys.results.blocklist": {"$exists": True}},
                            {"fastgcd": True},
                            {"invalid_ecc": True},
                            {"factordb.status": "PRP"},
                            {"factordb.status": "P"},
                            {"factordb.status": "CF"},
                            {"factordb.status": "FF"},
                            {"pwnedkeys.pwned": True},
                        ]
                    },
                ]
            }
        },
        {
            "$group": {
                "_id": {
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
                "total_per_group": {"$sum": 1},
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

    logger.info("Executing weak key smime certificates query")
    json_cache.start_timer()
    result = aggregate_certs(pipeline=pipeline)
    categorize_entries(result)

    json_cache.save(cache_name, result, comment=comment)


def get_affected_certs_count_batchwise(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "SMIME certificates containing a weak key"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        categorize_entries(result)
        # print(json.dumps(result, indent=4))
        return

    pipeline = [  # exlude certificates with no chain validation result. These certifcates could not be parsed by cryptography
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {"$set": {"chain": {"$arrayElemAt": ["$chain.chain", 0]}}},
        {
            "$match": {
                "$and": [
                    {"is_smime.is_smime": True},
                    {"chain.validation.validation_result": {"$exists": True}},
                    {
                        "$or": [
                            {"badkeys.results.rsainvalid": {"$exists": True}},
                            {"badkeys.results.roca": {"$exists": True}},
                            {"badkeys.results.fermat": {"$exists": True}},
                            {"badkeys.results.pattern": {"$exists": True}},
                            {"badkeys.results.smallfactors": {"$exists": True}},
                            {"badkeys.results.blocklist": {"$exists": True}},
                            {"fastgcd": True},
                            {"invalid_ecc": True},
                            {"factordb.status": "PRP"},
                            {"factordb.status": "P"},
                            {"factordb.status": "CF"},
                            {"factordb.status": "FF"},
                            {"pwnedkeys.pwned": True},
                        ]
                    },
                ]
            }
        },
        {
            "$group": {
                "_id": {
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
                "total_per_group": {"$sum": 1},
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

    logger.info("Executing weak key smime certificates query")
    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(
        result, group_by=("publicly_trusted", "historical", "val_result")
    )
    categorize_entries(result)
    json_cache.save(cache_name, result, comment=comment)
    return


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)

    refresh_flag = False

    if len(sys.argv) > 2:
        print("Usage: %s [refesh]", sys.argv[0])
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == "refresh":
            refresh_flag = True

    # get_affected_certs_count(refresh=refresh_flag)
    get_affected_certs_count_batchwise(refresh=refresh_flag)

import logging
import os
import sys

from analysis.general_stats import (
    count_smime_certificates,
    count_certificates,
)
from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import aggregate_certs_batchwise, reduce_groups
from analysis.utils.cache import JsonCacheManager, get_cache_name

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


OIDS = {
    "1.3.6.1.4.1.311.80.1": "Microsoft Document Encryption",
    "2.16.840.1.113730.4.1": "Netscape Server Gated Crypto",
    "1.3.6.1.4.1.311.3.10.3.12": "Microsoft Document Signing with typo?",
}


def get_extended_key_usages(*, smime: bool, refresh: bool = False) -> list[dict]:
    cache_name = get_cache_name(smime=smime)

    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {
            "$match": {
                "is_smime.is_smime": smime,
                "extensions.extended_key_usage": {"$exists": True},
            }
        },
        {
            "$group": {
                "_id": "$extensions.extended_key_usage.value",
                "count": {"$count": {}},
            }
        },
        {"$project": {"_id": 0, "ex_key_usage": "$_id", "count": 1}},
        {"$sort": {"count": -1}},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("ex_key_usage",))
    json_cache.save(cache_name, result)
    return result


def get_key_usage_and_extended_key_usages(
    *, smime: bool, refresh: bool = False
) -> list[dict]:
    cache_name = get_cache_name(smime=smime)

    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": smime}},
        {
            "$group": {
                "_id": {
                    "extended_key_usage": "$extensions.extended_key_usage.value",
                    "key_usage": "$extensions.key_usage.value",
                },
                "count": {"$count": {}},
            }
        },
        {
            "$project": {
                "_id": 0,
                "extended_key_usage": "$_id.extended_key_usage",
                "key_usage": "$_id.key_usage",
                "count": 1,
            }
        },
        {"$sort": {"count": -1}},
    ]

    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("extended_key_usage", "key_usage"))
    json_cache.save(cache_name, result)
    return result


def format_key_usage(ku: str) -> str:
    if ku in OIDS:
        return f"{ku} ({OIDS[ku]})"
    ku_words = ku.split("_")
    return ku_words[0] + "".join(w.capitalize() for w in ku_words[1:])


def print_tables(data: list[dict], total_all_certs: int):
    total_ku_or_eku_certs = sum(d["count"] for d in data)
    total_ku_certs = sum(d["count"] for d in data if d.get("key_usage"))
    total_eku_certs = sum(d["count"] for d in data if d.get("extended_key_usage"))
    total_ku_and_eku_certs = sum(
        d["count"] for d in data if d.get("key_usage") and d.get("extended_key_usage")
    )
    total_ku_not_eku_certs = sum(
        d["count"]
        for d in data
        if d.get("key_usage") and not d.get("extended_key_usage")
    )
    total_eku_not_ku_certs = sum(
        d["count"]
        for d in data
        if not d.get("key_usage") and d.get("extended_key_usage")
    )
    total_not_ex_certs = sum(
        d["count"]
        for d in data
        if not d.get("key_usage") and not d.get("extended_key_usage")
    )
    print(
        f"Total certs with ku or eku ex: {total_ku_or_eku_certs} ({total_ku_or_eku_certs / total_all_certs:.2%})"
    )
    print(
        f"Total certs with ku ex: {total_ku_certs} ({total_ku_certs / total_all_certs:.2%})"
    )
    print(
        f"Total certs with eku ex: {total_eku_certs} ({total_eku_certs / total_all_certs:.2%})"
    )
    print(
        f"Total certs with ku and eku ex: {total_ku_and_eku_certs} ({total_ku_and_eku_certs / total_all_certs:.2%})"
    )
    print(
        f"Total certs with ku and not eku ex: {total_ku_not_eku_certs} ({total_ku_not_eku_certs / total_all_certs:.2%})"
    )
    print(
        f"Total certs with eku and not eku ex: {total_eku_not_ku_certs} ({total_eku_not_ku_certs / total_all_certs:.2%})"
    )
    print(
        f"Total certs with not ku and not eku ex: {total_not_ex_certs} ({total_not_ex_certs / total_all_certs:.2%})"
    )

    print()
    print("Extension & Count & Percentage \\\\")
    print("\\midrule")
    print(
        f"KU or EKU & {total_ku_or_eku_certs:,} & {total_ku_or_eku_certs / total_all_certs:.2%} \\\\".replace(
            "%", "\\%"
        )
    )
    print(
        f"KU & {total_ku_certs:,} & {total_ku_certs / total_all_certs:.2%} \\\\".replace(
            "%", "\\%"
        )
    )
    print(
        f"EKU & {total_eku_certs:,} & {total_eku_certs / total_all_certs:.2%} \\\\".replace(
            "%", "\\%"
        )
    )
    print(
        f"KU and EKU & {total_ku_and_eku_certs:,} & {total_ku_and_eku_certs / total_all_certs:.2%} \\\\".replace(
            "%", "\\%"
        )
    )
    print()

    print("Distinct eku groups (ordered):", len(data))
    merged_data = {}  # [clientAuth, serverAuth] == [serverAuth, clientAuth]
    for entry in data:
        usages = (
            tuple(sorted(entry.get("key_usage", []))),
            tuple(sorted(entry.get("extended_key_usage", []))),
        )
        if usages in merged_data:
            merged_data[usages]["count"] += entry.get("count")
        else:
            merged_data[usages] = entry

    print("Distinct ku+eku groups (merged):", len(merged_data))

    data = list(merged_data.values())

    sorted_groups = sorted(data, key=lambda x: x["count"], reverse=True)

    print("\nTop 10 KU+EKU groups, percentage of all certificates with exact group:\n")
    print("KU & EKU & Count & Percentage \\\\")
    for entry in sorted_groups[:10]:
        count = entry["count"]
        kus = ", ".join(map(format_key_usage, entry.get("key_usage", [])))
        ekus = ", ".join(map(format_key_usage, entry.get("extended_key_usage", [])))

        print(
            f"{kus} & {ekus} & {count} & {count / total_all_certs:.2%} \\\\".replace(
                "%", "\\%"
            )
        )

    for key in "key_usage", "extended_key_usage":
        print()
        total_ku_certs = sum(d["count"] for d in data if d.get(key))
        print(
            f"Percentage containing {key} of all: {total_ku_certs / total_all_certs:.2%}"
        )
        unique = set(ku for x in data for ku in x.get(key, []))

        print(f"Number of unique {key} values: {len(unique)}")

        grouped = {e: [d for d in data if e in d.get(key, [])] for e in unique}
        counts = {ku: sum(d["count"] for d in data) for ku, data in grouped.items()}
        sorted_summed = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        print(
            f"\nTop 10 {key} values, percentage of certificates containing {key}/of all:\n"
        )
        print(
            f"{key.replace('_', ' ').title()} & Count & Percentage of certs with {key} & Percentage of all certs \\\\"
        )
        for ku, count in sorted_summed[:10]:
            ku = format_key_usage(ku)
            print(
                f"{ku} & {count:,} & {count / total_ku_certs:.2%} & {count / total_all_certs:.2%} \\\\".replace(
                    "%", "\\%"
                )
            )

    print()


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)

    refresh = sys.argv[1] == "refresh" if len(sys.argv) >= 2 else False

    for smime in (True, False):
        print(f"{'SMIME':=^80}" if smime else f"{'NOT SMIME':=^80}")
        ku_eku_data = get_key_usage_and_extended_key_usages(
            smime=smime, refresh=refresh
        )
        total_certs = (
            count_smime_certificates(refresh=refresh)
            if smime
            else count_certificates(refresh=refresh)
        )

        print_tables(ku_eku_data, total_certs)

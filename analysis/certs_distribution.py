import logging
import sys
import os
from collections import Counter

import pandas as pd
from pandas import DataFrame

from analysis.general_stats import (
    count_certificates,
    count_smime_certificates,
)
from analysis.utils.log import set_up_logging
from analysis.utils.cache import JsonCacheManager, get_cache_name
from analysis.utils.aggregate import aggregate_certs_batchwise, reduce_groups

logger = logging.getLogger()
CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_total_certs_per_host_country(
    only_smime: bool, refresh: bool = False
) -> list[dict]:
    cache_name = get_cache_name(only_smime=only_smime)
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True} if only_smime else {}},
        {"$project": {"source_ids": 1}},
        {
            "$lookup": {
                "from": "sources",
                "localField": "source_ids",
                "foreignField": "_id",
                "as": "sources",
            }
        },
        {
            "$lookup": {
                "from": "hosts",
                "localField": "sources.host_id",
                "foreignField": "_id",
                "as": "host",
            }
        },
        {
            "$project": {
                "country": {
                    "$setIntersection": ["$host.geoip.country", "$host.geoip.country"]
                }
            }
        },
        {"$unwind": {"path": "$country", "preserveNullAndEmptyArrays": False}},
        {"$group": {"_id": "$country", "total": {"$sum": 1}}},
        {"$project": {"_id": 0, "country": "$_id", "total": 1}},
    ]

    logger.info("Executing total smime certificates per host country query")

    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("country",))
    json_cache.save(
        cache_name, result, comment="Number of smime certificates per host country"
    )
    return result


def get_total_certs_per_host(only_smime: bool, refresh: bool = False) -> list[dict]:
    cache_name = get_cache_name(only_smime=only_smime)
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True} if only_smime else {}},
        {"$project": {"source_ids": 1}},
        {
            "$lookup": {
                "from": "sources",
                "localField": "source_ids",
                "foreignField": "_id",
                "as": "sources",
            }
        },
        {
            "$lookup": {
                "from": "hosts",
                "localField": "sources.host_id",
                "foreignField": "_id",
                "as": "host",
                "pipeline": [{"$group": {"_id": "$ip", "geoip": {"$first": "$geoip"}}}],
            }
        },
        {"$unwind": {"path": "$host", "preserveNullAndEmptyArrays": False}},
        {
            "$project": {
                "host.ip": "$host._id",
                "host.country": "$host.geoip.country",
                "host.continent": "$host.geoip.continent",
            }
        },
        {"$group": {"_id": "$host", "total": {"$count": {}}}},
        {
            "$project": {
                "_id": 0,
                "ip": "$_id.ip",
                "country": "$_id.country",
                "continent": "$_id.continent",
                "total": 1,
            }
        },
        {
            "$match": {
                "country": {"$exists": True},
            }
        },
    ]

    logger.info("Executing total smime certificates per host query")

    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("ip", "country", "continent"))
    json_cache.save(cache_name, result, comment="Number of smime certificates per host")
    return result


def get_total_certs_per_host_continent(
    only_smime: bool, refresh: bool = False
) -> list[dict]:
    cache_name = get_cache_name(only_smime=only_smime)
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True} if only_smime else {}},
        {"$project": {"source_ids": 1}},
        {
            "$lookup": {
                "from": "sources",
                "localField": "source_ids",
                "foreignField": "_id",
                "as": "sources",
            }
        },
        {
            "$lookup": {
                "from": "hosts",
                "localField": "sources.host_id",
                "foreignField": "_id",
                "as": "host",
            }
        },
        {
            "$project": {
                "continent": {
                    "$setIntersection": [
                        "$host.geoip.continent",
                        "$host.geoip.continent",
                    ]
                }
            }
        },
        {"$unwind": {"path": "$continent", "preserveNullAndEmptyArrays": False}},
        {"$group": {"_id": "$continent", "total": {"$sum": 1}}},
        {"$project": {"_id": 0, "continent": "$_id", "total": 1}},
    ]

    logger.info("Executing total smime certificates per host continent query")

    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("continent",))
    json_cache.save(
        cache_name, result, comment="Number of smime certificates per host continent"
    )
    return result


def get_hosts_per_certs(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Number of hosts per smime cert"
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {"$project": {"source_ids": 1}},
        {
            "$lookup": {
                "from": "sources",
                "localField": "source_ids",
                "foreignField": "_id",
                "as": "sources",
            }
        },
        {
            "$lookup": {
                "from": "hosts",
                "localField": "sources.host_id",
                "foreignField": "_id",
                "as": "hosts",
                "pipeline": [{"$count": "total_hosts"}],
            }
        },
        {"$group": {"_id": "$hosts.total_hosts", "total": {"$count": {}}}},
        {"$project": {"_id": 0, "host_count": {"$first": "$_id"}, "total": 1}},
        {"$sort": {"total": -1}},
    ]

    logger.info("Executing total hosts per smime certificate query")

    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("host_count",))
    json_cache.save(cache_name, result, comment=comment)
    return result


def print_country_table(
    total_certs: int, country_data: list[dict], hosts_data: list[dict]
):
    country_data = sorted(country_data, key=lambda x: x["total"], reverse=True)
    hosts = Counter(d.get("country") for d in hosts_data)
    for c in country_data:
        name, count = c.values()
        percent = count / total_certs * 100
        print(f"{name} & {hosts[name]} & {count:,d} & ({percent:.2f}\\%)\\\\")
    print()


def print_continent_table(
    total_certs: int, continent_data: list[dict], hosts_data: list[dict]
):
    country_data = sorted(continent_data, key=lambda x: x["total"], reverse=True)
    hosts = Counter(d.get("continent") for d in hosts_data)
    for c in country_data:
        name, count = c.values()
        percent = count / total_certs * 100
        print(f"{name} & {hosts[name]} & {count:,d} & ({percent:.2f}\\%)\\\\")
    print()


def print_largest_hosts(total_certs: int, hosts_data: list[dict], n: int = 100):
    hosts_data = sorted(hosts_data, key=lambda x: x["total"], reverse=True)[:n]
    for h in hosts_data:
        ip = h.get("ip")
        country = h.get("country")
        continent = h.get("continent")
        count = h["total"]
        percent = count / total_certs * 100
        print(f"{ip} & {country} & {continent} & {count:,d} & ({percent:.2f}\\%)\\\\")
    print()

    df = pd.DataFrame(hosts_data)
    df["percent"] = df["total"] / total_certs * 100
    df["cum_percent"] = df["percent"].cumsum()

    print(df.to_string())


def print_hosts_by_country_continent(hosts_data: list[dict]):
    countries = Counter(d.get("continent") for d in hosts_data)
    continents = Counter(d.get("continent") for d in hosts_data)

    print(sum(countries.values()), "hosts in total")
    print(sum(continents.values()), "hosts in total")

    for country, count in countries.most_common():
        percent = count / sum(countries.values()) * 100
        print(f"{country}: {count:,d} ({percent:.2f}\\%)")

    print()

    for continent, count in continents.most_common():
        percent = count / sum(continents.values()) * 100
        print(f"{continent}: {count:,d} ({percent:.2f}\\%)")


def print_continent_table_combined(
    all_certs: int,
    smime_certs: int,
    all_hosts_data: list[dict],
    smime_hosts_data: list[dict],
    all_continent_data: list[dict],
    smime_continent_data: list[dict],
):
    all_continent_data = sorted(
        all_continent_data, key=lambda x: x["total"], reverse=True
    )
    all_hosts = Counter(d.get("continent") for d in all_hosts_data)
    smime_hosts = Counter(d.get("continent") for d in smime_hosts_data)
    for c in all_continent_data:
        c_name, count = c.values()
        percent = count / all_certs * 100

        smime_count = next(
            (x["total"] for x in smime_continent_data if x["continent"] == c_name), 0
        )
        smime_percent = smime_count / smime_certs * 100

        print(
            f"{c_name} & {all_hosts[c_name]} & {count:,d} & ({percent:.2f}\\%) & "
            f"{smime_hosts[c_name]}  & {smime_count:,d} & ({smime_percent:.2f}\\%) \\\\"
        )
    print()


def print_country_table_combined(
    all_certs: int,
    smime_certs: int,
    all_hosts_data: list[dict],
    smime_hosts_data: list[dict],
    all_country_data: list[dict],
    smime_country_data: list[dict],
):
    all_country_data = sorted(all_country_data, key=lambda x: x["total"], reverse=True)

    all_hosts = Counter(d.get("country") for d in all_hosts_data)
    smime_hosts = Counter(d.get("country") for d in smime_hosts_data)
    for c in all_country_data:
        c_name, count = c.values()
        percent = count / all_certs * 100

        smime_count = next(
            (x["total"] for x in smime_country_data if x["country"] == c_name), 0
        )
        smime_percent = smime_count / smime_certs * 100

        print(
            f"{c_name} & {all_hosts[c_name]} & {count:,d} & ({percent:.2f}\\%) & "
            f"{smime_hosts[c_name]}  & {smime_count:,d} & ({smime_percent:.2f}\\%) \\\\"
        )
    print()


def print_hosts_per_cert_table(data: list[dict]):
    data = sorted(data, key=lambda x: x["total"], reverse=True)
    for d in data:
        name, count = d.values()
        percent = count / total_certs * 100
        print(f"{name} & {count:,d} & ({percent:.2f}\\%)\\\\")
    print()

    print(sum(d["host_count"] * d["total"] for d in data) / total_certs)

    df = DataFrame(data)
    df["host_count"] = df["host_count"].astype(int)
    df = df.sort_values(by="total", ascending=True)
    df["percent"] = df["total"] / total_certs * 100
    df["cum_percent"] = df["percent"].cumsum()

    print(df.to_string())


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)

    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [refresh]")
        exit(1)

    refresh_flag = len(sys.argv) == 2 and sys.argv[1] == "refresh"

    for only_smime in (True, False):
        print(f"Processing {'S/MIME' if only_smime else 'all'} certificates...")
        host_data = get_total_certs_per_host(
            only_smime=only_smime, refresh=refresh_flag
        )
        country_data = get_total_certs_per_host_country(
            only_smime=only_smime, refresh=refresh_flag
        )
        continent_data = get_total_certs_per_host_continent(
            only_smime=only_smime, refresh=refresh_flag
        )
        total_certs = (
            count_smime_certificates(refresh=refresh_flag)
            if only_smime
            else count_certificates(refresh=refresh_flag)
        )

        print_country_table(total_certs, country_data, host_data)
        print_continent_table(total_certs, continent_data, host_data)
        print_largest_hosts(total_certs, host_data)
        print_hosts_by_country_continent(host_data)

        print(f"{'=' * 80}\n")
    print("Combined results:")
    # No need to refresh data again, as we already fetched it above
    print_country_table_combined(
        all_certs=count_certificates(refresh=False),
        smime_certs=count_smime_certificates(refresh=False),
        all_hosts_data=get_total_certs_per_host(only_smime=False, refresh=False),
        smime_hosts_data=get_total_certs_per_host(only_smime=True, refresh=False),
        all_country_data=get_total_certs_per_host_country(
            only_smime=False, refresh=False
        ),
        smime_country_data=get_total_certs_per_host_country(
            only_smime=True, refresh=False
        ),
    )
    print_continent_table_combined(
        all_certs=count_certificates(refresh=False),
        smime_certs=count_smime_certificates(refresh=False),
        all_hosts_data=get_total_certs_per_host(only_smime=False, refresh=False),
        smime_hosts_data=get_total_certs_per_host(only_smime=True, refresh=False),
        all_continent_data=get_total_certs_per_host_continent(
            only_smime=False, refresh=False
        ),
        smime_continent_data=get_total_certs_per_host_continent(
            only_smime=True, refresh=False
        ),
    )
    print(f"{'=' * 80}\n")
    print("Hosts per certificate:")
    print_hosts_per_cert_table(get_hosts_per_certs(refresh=refresh_flag))

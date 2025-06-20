import logging
from analysis.utils.log import set_up_logging
from analysis.utils.cache import JsonCacheManager, get_cache_name
from analysis.utils.aggregate import aggregate
import os
import json
import sys

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_crawled_hosts_per_month(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Crawled hosts per month delivering certificates and avg. number of crawled hosts"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"Average hosts per scan: {result.get('avg_hosts_per_scan')}")
        print(json.dumps(result.get("host_data"), indent=4))
        return

    pipeline = [
        {
            "$lookup": {
                "from": "sources",
                "localField": "_id",
                "foreignField": "host_id",
                "as": "sources",
            }
        },
        {"$unwind": {"path": "$sources", "preserveNullAndEmptyArrays": False}},
        {
            "$lookup": {
                "from": "certificates",
                "localField": "sources._id",
                "foreignField": "source_ids",
                "as": "certs",
                "pipeline": [{"$limit": 1}, {"$project": {"_id": 1}}],
            }
        },
        {"$addFields": {"hasCert": {"$gt": [{"$size": "$certs"}, 0]}}},
        {"$match": {"hasCert": True}},
        {"$project": {"sources": 1, "ip": 1, "_id": 0}},
        {
            "$set": {
                "start_time_string": {
                    "$dateToString": {
                        "format": "%Y-%m-%dT%H:%M:%S.%LZ",
                        "date": "$sources.start_time",
                    }
                }
            }
        },
        {"$match": {"start_time_string": {"$gte": "2024-01-01T00:00:00.000Z"}}},
        {
            "$addFields": {
                "ip": "$ip",
                "start_year": {"$year": "$sources.start_time"},
                "start_month": {"$month": "$sources.start_time"},
                "start_day": {"$dayOfMonth": "$sources.start_time"},
            }
        },
        {
            "$addFields": {
                "interval": {
                    "$cond": {
                        "if": {
                            "$or": [
                                {
                                    "$and": [
                                        {"$eq": ["$start_year", 2024]},
                                        {"$in": ["$start_month", [11, 12]]},
                                        {"$lte": ["$start_day", 14]},
                                    ]
                                },
                                {
                                    "$and": [
                                        {"$gte": ["$start_year", 2025]},
                                        {"$lte": ["$start_day", 14]},
                                    ]
                                },
                            ]
                        },
                        "then": "first_half",
                        "else": {
                            "$cond": {
                                "if": {
                                    "$or": [
                                        {
                                            "$and": [
                                                {"$eq": ["$start_year", 2024]},
                                                {"$in": ["$start_month", [11, 12]]},
                                                {"$gte": ["$start_day", 15]},
                                            ]
                                        },
                                        {
                                            "$and": [
                                                {"$gte": ["$start_year", 2025]},
                                                {"$gte": ["$start_day", 15]},
                                            ]
                                        },
                                    ]
                                },
                                "then": "second_half",
                                "else": "full_month",
                            }
                        },
                    }
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "host_ip": "$ip",
                    "year": "$start_year",
                    "month": "$start_month",
                    "interval": "$interval",
                },
                "count": {"$sum": 1},
            }
        },
        {
            "$group": {
                "_id": {
                    "year": "$_id.year",
                    "month": "$_id.month",
                    "interval": "$_id.interval",
                },
                "total_host": {"$sum": 1},
            }
        },
        {"$sort": {"_id.year": 1, "_id.month": 1, "_id.interval": 1}},
    ]

    logger.info("Executing hosts query")
    json_cache.start_timer()
    result = aggregate(collection_name="hosts", pipeline=pipeline)
    total_hosts_list = [entry.get("total_host") for entry in result]
    avg_hosts_per_scan = (
        sum(total_hosts_list) / len(total_hosts_list) if total_hosts_list else 0
    )
    avg_hosts_per_scan = round(avg_hosts_per_scan, 2)

    print(f"Average hosts per scan: {avg_hosts_per_scan}")
    json_cache.save(
        cache_name,
        {
            "host_data": result,
            "avg_hosts_per_scan": avg_hosts_per_scan,
        },
        comment=comment,
    )
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

    get_crawled_hosts_per_month(refresh_flag)

import logging
import sys
import os

from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import aggregate_certs
from analysis.utils.cache import JsonCacheManager, get_cache_name

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def count_certificates(refresh: bool = False) -> int:
    cache_name = get_cache_name()
    comment = "Number of total certificates"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"{result.get('count'):,}")
        return result.get("count")

    pipeline = [{"$sort": {"_id": 1}}, {"$count": "count"}]

    result = aggregate_certs(pipeline=pipeline)
    number_of_certs = result[0].get("count")
    json_cache.save(cache_name, {"count": number_of_certs}, comment=comment)
    print(comment)
    print(f"{number_of_certs:,}")
    return number_of_certs


def count_smime_certificates(refresh: bool = False) -> int:
    cache_name = get_cache_name()
    comment = "Number of smime certificates"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"{result.get('count'):,}")
        return result.get("count")

    pipeline = [{"$match": {"is_smime.is_smime": True}}, {"$count": "count"}]

    result = aggregate_certs(pipeline=pipeline)
    number_of_smime_certs = result[0].get("count")
    json_cache.save(cache_name, {"count": number_of_smime_certs}, comment=comment)
    print(comment)
    print(f"{number_of_smime_certs:,}")
    return number_of_smime_certs


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)
    refresh_flag = False

    if len(sys.argv) > 2:
        print("Usage: %s [refresh]", sys.argv[0])
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == "refresh":
            refresh_flag = True
        else:
            raise ValueError("Invalid argument")

    total_certs = count_certificates(refresh_flag)
    total_smime_certs = count_smime_certificates(refresh_flag)
    percent_smime_certs = total_smime_certs / total_certs

    print()
    print(f"{total_certs=:,}")
    print(f"{total_smime_certs=:,}")
    print(f"{percent_smime_certs=:.2%}")

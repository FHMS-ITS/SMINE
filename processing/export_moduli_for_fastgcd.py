"""Helper script to export rsa moduli."""

import logging
from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import aggregate_certs_batchwise
from analysis.utils.cache import JsonCacheManager, get_cache_name
import sys
import os


logger = logging.getLogger(__name__)
logging.getLogger("pymongo").setLevel(logging.WARNING)

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(process)d [%(levelname)5s] %(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(stream=sys.stdout),
    ],
)


def write_moduli_to_file(result):
    moduli_set = set()
    for entry in result:
        mod = entry.get("modulus")
        if not mod:
            continue
        mod = mod.replace(":", "")
        moduli_set.add(mod)

    with open("assets/rsa_moduli.txt", "w") as fp:
        fp.write("\n".join(moduli_set))


def get_moduli_for_fastgcd(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Export all rsa moduli"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        write_moduli_to_file(result[0])
        return result

    pipeline = [
        {
            "$match": {
                "cert_fields.tbs_certificate.subject_public_key_info.public_key.modulus": {
                    "$exists": True
                }
            }
        },
        {
            "$project": {
                "_id": {"$toString": "$_id"},
                "modulus": "$cert_fields.tbs_certificate.subject_public_key_info.public_key.modulus",
            }
        },
    ]

    logger.info("Exporting rsa moduli")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    print(comment)
    json_cache.save(cache_name, result, comment=comment)

    write_moduli_to_file(result[0])
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

    get_moduli_for_fastgcd(refresh=refresh_flag)

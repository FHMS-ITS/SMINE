import logging
from analysis.utils.log import set_up_logging
from analysis.utils.aggregate import aggregate_certs_batchwise, reduce_groups
from analysis.utils.cache import JsonCacheManager, get_cache_name
import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def write_cert_server_ips(result: list):
    certificate_ips_389 = set()
    certificate_ips_636 = set()
    for entry in result:
        e_ports = entry.get("ports")
        ip = entry.get("ip")
        if 389 in e_ports:
            certificate_ips_389.add(ip)
        if 636 in e_ports:
            certificate_ips_636.add(ip)

    os.makedirs("server_ips", exist_ok=True)
    with open(
        os.path.join("server_ips", "cert_server_ips_389.txt"),
        "w",
    ) as fp1:
        for i in sorted(certificate_ips_389):
            fp1.write(f"{i}\n")
    with open(
        os.path.join("server_ips", "cert_server_ips_636.txt"),
        "w",
    ) as fp2:
        for i in sorted(certificate_ips_636):
            fp2.write(f"{i}\n")


def get_total_certs_and_cert_ids_per_host(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Number of certificates and the corresponding certificate ids per host ordered descending"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"See cache file {cache_name} for details")
        print(f"Total crawled hosts {len(result):,}")
        write_cert_server_ips(result)
        return result

    pipeline = [
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
                "pipeline": [{"$project": {"ip": 1, "port": 1, "_id": 0}}],
            }
        },
        {"$project": {"host": {"$setUnion": "$host"}}},
        {"$unwind": {"path": "$host", "preserveNullAndEmptyArrays": False}},
        {
            "$group": {
                "_id": "$host.ip",
                "ports": {"$addToSet": "$host.port"},
                "unique_cert_ids": {"$addToSet": {"$toString": "$_id"}},
            }
        },
        {
            "$project": {
                "ip": "$_id",
                "_id": 0,
                "ports": 1,
                "unique_cert_ids": 1,
                "total": {"$size": "$unique_cert_ids"},
            }
        },
        {"$sort": {"total": -1}},
    ]

    logger.info("Executing total certificates and cert ids per host query")
    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("ip",))
    result = sorted(result, key=lambda x: x["total"], reverse=True)
    print(comment)
    print(f"See cache file {cache_name} for details")
    print(f"Total crawled hosts {len(result):,}")
    json_cache.save(cache_name, result, comment=comment)

    write_cert_server_ips(result)

    return result


def generate_cdf_certs_per_hosts(result: list):
    TOP_N_PERCENT_SERVERS = 1  # %

    df = pd.DataFrame(result)

    df["cert_set"] = df["unique_cert_ids"].apply(set)
    df["total"] = df["unique_cert_ids"].apply(len)

    mean_count = df["total"].mean()
    median_count = df["total"].median()
    std_count = df["total"].std()
    min_count = df["total"].min()
    max_count = df["total"].max()
    quantiles = df["total"].quantile([0.25, 0.5, 0.75, 0.9])

    # Display the results
    print(f"Average (Mean): {mean_count:,.2f}")
    print(f"Median: {median_count:,}")
    print(f"Standard Deviation: {std_count:,.2f}")
    print(f"Minimum: {min_count:,}")
    print(f"Maximum: {max_count:,}\n")
    print("Quantiles:")
    print(quantiles)

    # Sort data descending by 'total'
    df_sorted = df.sort_values(by="total", ascending=False).reset_index(drop=True)

    # Calculate total count of servers
    total_servers = len(df_sorted)
    print(f"Total servers: {total_servers:,}")

    # Calculate total count of certificates
    all_unique_certs = set.union(*df_sorted["cert_set"])
    total_unique_cert_count = len(all_unique_certs)
    print(f"Total unique certificates: {total_unique_cert_count:,}\n")

    # Generate CDF counting a certiificate only once
    covered_certs = set()
    cdf_server_percent = []
    cdf_cert_percent = []

    for i, certs in enumerate(df_sorted["cert_set"], 1):
        covered_certs.update(certs)
        print(f"certs on server {i}: {len(certs):,}")
        print(f"covered certs {i}: {len(covered_certs):,}")
        covered_fraction = (len(covered_certs) / total_unique_cert_count) * 100
        print(f"covered fraction {i}: {covered_fraction:.2f}%")
        server_fraction = (i / total_servers) * 100
        print(f"server fraction {i}: {server_fraction:.2f}%\n")
        cdf_server_percent.append(server_fraction)
        cdf_cert_percent.append(covered_fraction)
        if covered_fraction >= 100.0:
            break  # Optional: Break when reaching 100%

    # TOP n%
    top_percent_index = next(
        i for i, x in enumerate(cdf_server_percent) if x >= TOP_N_PERCENT_SERVERS
    )
    cert_percent_top = cdf_cert_percent[top_percent_index]
    print(
        f"The top {TOP_N_PERCENT_SERVERS}% servers hold {cert_percent_top:.2f}% of the collected certificates."
    )

    # Add start point (0,0)
    x = [0] + cdf_server_percent
    y = [0] + cdf_cert_percent

    # Plot
    plt.figure(figsize=(10, 6))
    plt.plot(x, y, label="Cumulative Distribution (Unique Certificates)")
    plt.axvline(
        x=TOP_N_PERCENT_SERVERS,
        color="red",
        linestyle="--",
        label=f"Top {TOP_N_PERCENT_SERVERS}% of servers Server",
    )
    plt.axhline(
        y=cert_percent_top,
        color="green",
        linestyle="--",
        label=f"{cert_percent_top:.2f}% of certificates",
    )
    plt.xticks(np.concatenate([np.arange(0, 10, 2), np.arange(10, 101, 10)]))
    plt.xlabel("Cumulative % of servers", fontsize=14)
    plt.ylabel("Cumulative % of certificates (unique)", fontsize=14)
    plt.tick_params(axis="both", which="major", labelsize=12)
    plt.title("CDF: Distribution of unique certificates across servers", fontsize=16)
    plt.legend(fontsize=12)
    plt.grid(True)
    plt.tight_layout()
    os.makedirs("assets/cache/diagrams/", exist_ok=True)
    plt.savefig(
        "assets/cache/diagrams/cert_distribution_across_servers.pdf",
        format="pdf",
        bbox_inches="tight",
    )
    plt.show()


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)
    refresh_flag = False

    if len(sys.argv) > 2:
        print("Usage: %s [refresh]", sys.argv[0])
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == "refresh":
            refresh_flag = True

    generate_cdf_certs_per_hosts(get_total_certs_and_cert_ids_per_host(refresh_flag))

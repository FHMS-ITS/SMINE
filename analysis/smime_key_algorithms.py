import logging
import os
import sys
from pprint import pprint

import matplotlib
import pandas as pd
from matplotlib import pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from analysis.utils.log import set_up_logging
from analysis.utils.cache import JsonCacheManager, get_cache_name
from analysis.utils.aggregate import aggregate_certs_batchwise, reduce_groups

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


def get_key_algorithms(refresh: bool = False) -> list[dict]:
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$group": {
                "_id": "$cert_fields.tbs_certificate.subject_public_key_info.algorithm",
                "total": {"$count": {}},
            }
        },
        {"$sort": {"total": -1}},
        {"$project": {"_id": 0, "algorithm": "$_id", "total": 1}},
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("algorithm",))
    json_cache.save(cache_name, result)

    return result


def get_key_algorithms_with_date(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$project": {
                "date": {
                    "$dateToString": {
                        "format": "%Y-%m",
                        "date": {
                            "$toDate": "$cert_fields.tbs_certificate.validity.not_before_iso"
                        },
                    }
                },
                "algorithm": "$cert_fields.tbs_certificate.subject_public_key_info.algorithm",
            }
        },
        {
            "$group": {
                "_id": {"algorithm": "$algorithm", "date": "$date"},
                "total": {"$count": {}},
            }
        },
        {"$sort": {"total": -1}},
        {
            "$project": {
                "_id": 0,
                "algorithm": "$_id.algorithm.algorithm",
                "parameters": "$_id.algorithm.parameters",
                "date": "$_id.date",
                "total": 1,
            }
        },
    ]

    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("algorithm", "parameters", "date"))
    json_cache.save(cache_name, result)

    return result


def get_issued_rsa_certs_per_month(refresh: bool = False) -> list[dict]:
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {
            "$match": {
                "is_smime.is_smime": True,
                "cert_fields.tbs_certificate.subject_public_key_info.algorithm.algorithm": "rsa",
                "cert_fields.tbs_certificate.subject_public_key_info.public_key.modulus": {
                    "$exists": True
                },
            }
        },
        {
            "$addFields": {
                "rsa_key_len": {
                    "$multiply": [
                        {
                            "$divide": [
                                {
                                    "$add": [
                                        {
                                            "$strLenCP": "$cert_fields.tbs_certificate.subject_public_key_info.public_key.modulus"
                                        },
                                        1,
                                    ]
                                },
                                3,
                            ]
                        },
                        8,
                    ]
                }
            }
        },
        {
            "$set": {
                "date_str": {
                    "$dateToString": {
                        "format": "%Y-%m",
                        "date": {
                            "$toDate": "$cert_fields.tbs_certificate.validity.not_before_iso"
                        },
                    }
                }
            }
        },
        {
            "$group": {
                "_id": {"rsa_key_len": "$rsa_key_len", "dateString": "$date_str"},
                "count": {"$count": {}},
            }
        },
        {
            "$project": {
                "_id": 0,
                "rsa_key_len": "$_id.rsa_key_len",
                "dateString": "$_id.dateString",
                "count": 1,
            }
        },
        {"$sort": {"rsa_key_len": -1, "dateString": -1}},
    ]

    logger.info("Executing rsa key length query")
    json_cache.start_timer()
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("rsa_key_len", "dateString"))
    for entry in result:
        entry["rsa_key_len"] = int(entry["rsa_key_len"])
    json_cache.save(
        cache_name,
        result,
        comment="Number of rsa keys with specific length issued per month",
    )
    return result


def generate_detail_diagram_condensed(data: list[dict], rsa_data: list[dict]) -> None:
    df = pd.DataFrame(data)
    ec_df = df[df["algorithm"] == "ec"]

    # set parameters to "explicit" if it's a dict
    ec_df["parameters"] = ec_df["parameters"].apply(
        lambda x: "xplicit" if isinstance(x, dict) else x
    )

    # Replace OID
    ec_df["parameters"] = ec_df["parameters"].apply(
        lambda x: "sm2p256v1" if x == "1.2.156.10197.1.301" else x
    )

    ec_df["parameters"] = ec_df["parameters"].apply(
        lambda x: "$_other" if x not in EC_PARAMS_TO_PLOT else x
    )

    ec_df = ec_df[ec_df["parameters"] != "$_other"]

    # RSA data

    rsa_data = [
        {
            "total": entry.get("count"),
            "algorithm": "rsa",
            "date": entry.get("dateString"),
            "parameters": entry.get("rsa_key_len"),
        }
        for entry in rsa_data
    ]
    rsa_df = pd.DataFrame(rsa_data)

    rsa_df["parameters"] = rsa_df["parameters"].apply(
        lambda x: "$_other"
        if x not in KEY_LENGTHS_TO_PLOT
        else str(x)  # put other last
    )

    rsa_df = rsa_df[rsa_df["parameters"] != "$_other"]

    # Join RSA and EC data
    df = pd.concat([ec_df, rsa_df])

    total_count = df["total"].sum()
    print(f"{total_count=}")
    print(df.groupby("algorithm")["total"].sum().sort_values(ascending=False))
    print()
    print(
        df.groupby(["algorithm", "parameters"])["total"]
        .sum()
        .sort_values(ascending=False)
    )
    print()

    df["year"] = df["date"].apply(lambda x: x.split("-")[0])
    df["year"] = df["year"].astype(int)
    print(df.groupby(["algorithm", "parameters", "year"])["total"].sum().to_string())

    print()

    new_df = df[df["date"] >= "2020-01"]
    new_df = new_df[new_df["date"] < "2025-01"]
    new_df = new_df.groupby(["year"])["total"].sum().reset_index()

    print(new_df.to_string())
    print(new_df["total"].mean())
    print(new_sum := new_df["total"].sum())
    print(new_sum / total_count * 100)

    old_df = df[df["date"] < "2020-01"]
    old_df = old_df.groupby(["year"])["total"].sum().reset_index()

    print(old_df.to_string())
    print(old_df["total"].mean())
    print(old_sum := old_df["total"].sum())
    print(old_sum / total_count * 100)

    df = df[df["date"] >= f"{START_YEAR}-01"]
    df = df[df["date"] < f"{END_YEAR}-01"]
    # Extract year

    # Group by year, algorithm, and parameters
    grouped = (
        df.groupby(["year", "algorithm", "parameters"])["total"].sum().reset_index()
    )

    # Pivot to prepare data for stacked bar chart
    pivoted = grouped.pivot_table(
        index="year", columns=["algorithm", "parameters"], values="total", fill_value=0
    )

    # average per year
    pivoted = pivoted.div(pivoted.sum(axis=1), axis=0)

    # Plot
    fig, ax = plt.subplots(figsize=(12, 10))
    bar_width = 0.8

    rsa_params = pivoted["rsa"].columns
    rsa_colors = plt.cm.get_cmap("GnBu")(
        [0.2 + 0.8 * i / (len(rsa_params) - 1) for i in range(len(rsa_params))]
    )

    rsa_color_map = {param: rsa_colors[i] for i, param in enumerate(rsa_params)}
    rsa_color_map["$_other"] = "gray"

    ec_params = pivoted["ec"].columns
    ec_colors = plt.cm.get_cmap("YlOrRd")(
        [0.2 + 0.8 * i / (len(ec_params) - 1) for i in range(len(ec_params))]
    )

    ec_color_map = {
        param: ec_colors[i] if param != "$_other" else "gray"
        for i, param in enumerate(ec_params)
    }

    def format_curve_name(name: str) -> str:
        if name.startswith("brainpool"):
            return name.replace("brainpoolp", "brainpoolP")
        elif name == "$_other":
            return "Other"
        elif name == "xplicit":
            return "Explicit"
        else:
            return name

    # Stacking RSA bars
    pivoted_rsa = pivoted["rsa"]

    pivoted_ec = pivoted["ec"]
    # Define hatching patterns for alternating bars
    rsa_hatches = ["//", None] * (len(pivoted_rsa.columns) // 2) + [None]
    ec_hatches = ["\\\\", None] * (len(pivoted_ec.columns) // 2) + [None]

    if not WITH_HATCHES:
        rsa_hatches = [None] * len(pivoted_rsa.columns)
        ec_hatches = [None] * len(pivoted_ec.columns)
    for i, param in enumerate(pivoted_rsa.columns):
        ax.bar(
            pivoted_rsa.index,
            pivoted_rsa[param],
            color=rsa_color_map[param],
            hatch=rsa_hatches[i],
            width=bar_width,
            align="center",
            bottom=pivoted_rsa.iloc[:, :i].sum(axis=1) if i > 0 else None,
            label=param,
            edgecolor="white",
        )

    for i, param in enumerate(pivoted_ec.columns):
        ax.bar(
            pivoted_ec.index,
            pivoted_ec[param],
            color=ec_color_map[param],
            hatch=ec_hatches[i],
            width=bar_width,
            align="center",
            bottom=(pivoted_rsa.sum(axis=1) + pivoted_ec.iloc[:, :i].sum(axis=1))
            if i > 0
            else pivoted_rsa.sum(axis=1),
            label=param,
            edgecolor="white",
        )
        # Plot total number of certificates per year and month as a linear line

    total_per_year = df[df["year"] < (END_YEAR - 1)].groupby("year")["total"].sum()
    last_year = df[df["year"] >= (END_YEAR - 1)].groupby("year")["total"].sum()

    ax2 = ax.twinx()

    # Plot the total certificates
    ax2.plot(
        total_per_year.index,
        total_per_year,
        color="black",
        linewidth=4,
        linestyle="-",
        marker="s",
    )
    ax2.plot(
        [2025],
        [last_year[2025]],
        color="black",
        linewidth=4,
        linestyle="--",
        marker="s",
    )
    ax2.hlines(
        xmin=2024.6,
        xmax=2025.4,
        y=last_year[2025],
        color="black",
        linestyle=":",
        linewidth=2,
    )
    ax2.set_ylabel("Total Certificates per Year", fontsize=TITLE_FONT_SIZE)
    ax2.set_ylim((0, 5_000_000))
    ax2.set_yticks(
        [0, 1000000, 2000000, 3000000, 4000000, 5000000],
        ["0", "1M", "2M", "3M", "4M", "5M"],
    )

    # Format x-axis ticks for years
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_xticks(range(START_YEAR, END_YEAR))
    ax.set_xticklabels(range(START_YEAR, END_YEAR), rotation=45)

    # Separate legends for RSA and EC
    ec_legend_labels = [format_curve_name(param) for param in pivoted_ec.columns]
    ec_legend_handles = [
        Patch(
            facecolor=ec_color_map[param],
            edgecolor="white",
            hatch=ec_hatches[i],
            label=label,
        )
        for i, (param, label) in enumerate(zip(pivoted_ec.columns, ec_legend_labels))
    ][::-1]

    rsa_legend_labels = [
        param if param != "$_other" else "Other" for param in pivoted_rsa.columns
    ]
    rsa_handles = [
        Patch(
            facecolor=rsa_color_map[param],
            edgecolor="white",
            hatch=rsa_hatches[i],
            label=label,
        )
        for i, (param, label) in enumerate(zip(pivoted_rsa.columns, rsa_legend_labels))
    ][::-1]

    # Add EC legend
    ec_legend = ax.legend(
        handles=ec_legend_handles,
        title="ECDSA",
        bbox_to_anchor=(0, 0.63, 0.36, 0.2),
        loc="upper left",
        fontsize=FONT_SIZE,
        title_fontsize=TITLE_FONT_SIZE,
        alignment="center",
        framealpha=1,
        mode="expand",
    )
    ax.add_artist(ec_legend)

    rsa_legend = ax.legend(
        handles=rsa_handles,
        title="RSA",
        bbox_to_anchor=(0, 0.35, 0.36, 0.2),
        loc="upper left",
        fontsize=FONT_SIZE,
        title_fontsize=TITLE_FONT_SIZE,
        alignment="center",
        framealpha=1,
        mode="expand",
    )
    ax.add_artist(rsa_legend)

    total_line_handle = Line2D(
        [0],
        [0],
        color="black",
        linewidth=4,
        linestyle="-",
        marker="s",
        label="Total Certs. per Year",
    )
    last_year_line_handle = Line2D(
        [0],
        [0],
        color="black",
        linewidth=2,
        linestyle=":",
        marker="s",
        label="Total Certs. (01 - mid 04/2025)",
    )
    # Add total line legend
    total_legend = ax.legend(
        handles=[total_line_handle, last_year_line_handle],
        loc="lower left",
        bbox_to_anchor=(0.1, 0),
        fontsize=FONT_SIZE,
        title_fontsize=TITLE_FONT_SIZE,
    )
    ax.add_artist(total_legend)

    # Customizing the plot
    ax.set_ylabel("Proportion of Certificates", fontsize=TITLE_FONT_SIZE)
    ax.set_xlabel("Year of Issuance", fontsize=TITLE_FONT_SIZE)

    ax.set_xlim((START_YEAR - 0.5, END_YEAR - 0.5))

    ax.yaxis.grid(True, linestyle="--", alpha=0.8, linewidth=2)
    ax.tick_params(axis="x", labelsize=FONT_SIZE)
    ax.tick_params(axis="y", labelsize=FONT_SIZE)
    ax2.tick_params(axis="y", labelsize=FONT_SIZE)

    plt.tight_layout()
    plt.savefig("assets/cache/diagrams/smime_key_algorithm_detailed_condensed.pdf", dpi="figure")
    plt.show()


WITH_HATCHES = True
matplotlib.rcParams["hatch.linewidth"] = 1.5
FONT_SIZE = 20
TITLE_FONT_SIZE = 22

KEY_LENGTHS_TO_PLOT = [1024, 2048, 3072, 4096]
EC_PARAMS_TO_PLOT = ["secp256r1", "secp384r1", "brainpoolp256r1", "sm2p256v1"]
START_YEAR, END_YEAR = 2006, 2026

if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)

    if len(sys.argv) > 2:
        print("Usage: %s [refresh]", sys.argv[0])
        exit()

    refresh_flag = len(sys.argv) == 2 and sys.argv[1] == "refresh"

    algorithms = get_key_algorithms(refresh=refresh_flag)
    pprint(algorithms)

    algorithms_date = get_key_algorithms_with_date(refresh=refresh_flag)
    rsa_date = get_issued_rsa_certs_per_month(refresh=refresh_flag)

    generate_detail_diagram_condensed(algorithms_date, rsa_date)

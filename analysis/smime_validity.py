import logging
import os
import sys

from matplotlib import pyplot as plt
from pandas import DataFrame

from analysis.utils.log import set_up_logging

from analysis.utils.cache import JsonCacheManager, get_cache_name
from analysis.utils.aggregate import (
    aggregate_batchwise,
    reduce_groups,
)

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)

FONT_SIZE = 20
TITLE_FONT_SIZE = 22


def get_validity_periods_with_trust(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {"$match": {"is_smime": True}},
        {
            "$lookup": {
                "from": "certificates",
                "localField": "_id",
                "foreignField": "_id",
                "as": "cert",
                "pipeline": [
                    {"$project": {"validity": "$cert_fields.tbs_certificate.validity"}}
                ],
            }
        },
        {"$addFields": {"validity": {"$first": "$cert.validity"}}},
        {
            "$match": {
                "validity.not_after": {"$type": "number"},
                "validity.not_before": {"$type": "number"},
            }
        },
        {
            "$project": {
                "_id": 0,
                "publicly_trusted": {
                    "$anyElementTrue": [
                        [
                            "$chain.origin_info.mozilla",
                            "$chain.origin_info.microsoft",
                            "$chain.origin_info.macOS",
                            "$chain.origin_info.chrome",
                        ]
                    ]
                },
                "valid_chain": {
                    "$eq": ["$chain.validation.validation_result", "VALID"]
                },
                "validityDays": {
                    "$ceil": {
                        "$divide": [
                            {
                                "$subtract": [
                                    "$validity.not_after",
                                    "$validity.not_before",
                                ]
                            },
                            86400,
                        ]
                    }
                },
            }
        },
        {
            "$group": {
                "_id": {
                    "validityDays": "$validityDays",
                    "publicly_trusted": "$publicly_trusted",
                    "valid_chain": "$valid_chain",
                },
                "total": {"$count": {}},
            }
        },
        {"$sort": {"total": -1}},
        {
            "$project": {
                "_id": 0,
                "validityDays": "$_id.validityDays",
                "publicly_trusted": "$_id.publicly_trusted",
                "valid_chain": "$_id.valid_chain",
                "total": 1,
            }
        },
    ]

    json_cache.start_timer()
    result = aggregate_batchwise("chain", pipeline=pipeline)

    result = reduce_groups(
        result, group_by=("validityDays", "publicly_trusted", "valid_chain")
    )

    json_cache.save(cache_name, result)
    return result


def print_table(df: DataFrame):
    # Sort by 'total' in descending order
    df_sorted = df.sort_values(by="total", ascending=False)

    # Calculate the 90% threshold
    total_sum = df["total"].sum()
    threshold = 0.90 * total_sum

    # Find the smallest set of days
    cumulative_sum = 0
    selected_days = []

    for _, row in df_sorted.iterrows():
        cumulative_sum += row["total"]
        selected_days.append(row["validityDays"])
        if cumulative_sum >= threshold:
            break

    selected_days.sort()
    print(selected_days)

    groups = []
    for day in selected_days:
        if not groups or day - groups[-1][-1] > 1:
            groups.append([day])
        else:
            groups[-1].append(day)

    groups = {
        df[df["validityDays"].isin(group)]["total"].sum(): group for group in groups
    }

    print()
    years = {i * 365: i for i in range(1, 11)}
    for s, g in sorted(groups.items(), reverse=True):
        if len(g) == 1:
            g_str = f"{g[0]:,}"
        elif len(g) == 2:
            g_str = f"{g[0]:,}, {g[-1]:,}"
        else:
            g_str = f"{g[0]:,}--{g[-1]:,}"

        year = "".join(str(years.get(day, "")) for day in g)
        year = f"{year} years" if year else f"$\\approx${g[-1] // 365} years"
        print(
            f"{g_str} & {year} & {s:,} & {s / total_sum:.2%} \\\\".replace("%", "\\%")
        )


def generate_cumulative_diagram_trust(data: list[dict[str, int]]) -> None:
    full_df = DataFrame(data)
    full_df = full_df.sort_values(by="validityDays")
    full_df["validityDays"] = full_df["validityDays"].astype(int)

    full_df["cumulative"] = full_df["total"].cumsum()

    full_df = full_df[full_df["validityDays"] >= 0]
    full_df = full_df[full_df["validityDays"] <= 4000]
    trusted_df = full_df[
        (full_df["publicly_trusted"] == True) & (full_df["valid_chain"] == True)  # noqa: E712
    ]
    valid_df = full_df[
        (full_df["publicly_trusted"] == False) & (full_df["valid_chain"] == True)  # noqa: E712
    ]
    data_sets = [
        (full_df, "blue", "All"),
        (trusted_df, "green", "Trusted"),
        (valid_df, "orange", "Valid"),
    ]

    # Create the subplots
    plt.figure(figsize=(12, 8), dpi=300)
    ax = plt.gca()
    for df, color, label in data_sets:
        print(label)
        print_table(df)

        df["cumulative"] = df["total"].cumsum()

        # Plot cumulative curve
        ax.plot(
            df["validityDays"],
            df["cumulative"],
            label=label,
            color=color,
        )
    # Add labels, legend, and grid to the first subplot
    yticks = [0, 5e6, 10e6, 15e6, 20e6, 25e6, 30e6, 35e6, 40e6]
    ylabels = [0, "5M", "10M", "15M", "20M", "25M", "30M", "35M", "40M"]
    ax.set_yticks(yticks)
    ax.set_yticklabels(ylabels)
    ax.set_ylabel("Cumulative Number of Certificates", fontsize=TITLE_FONT_SIZE)
    ax.grid(True, which="both", linestyle="--", alpha=0.5)
    ax.legend(loc="upper left", fontsize=FONT_SIZE)

    ax.set_xlabel("Validity Period in Days", fontsize=TITLE_FONT_SIZE)
    ax.grid(True, which="both", linestyle="--", linewidth=0.5)

    days = [100, *(year * 365 for year in range(1, 11))]
    plt.xticks([0, *days], rotation=45)

    ax.tick_params(axis="x", labelsize=FONT_SIZE)
    ax.tick_params(axis="y", labelsize=FONT_SIZE)
    ax.set_xlim(-100, 4000)

    plt.tight_layout()
    plt.savefig("assets/cache/diagrams/smime_validity_cumulative_trust.pdf", dpi="figure")
    plt.show()


if __name__ == "__main__":
    set_up_logging(log_level=logging.INFO)
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [refresh]")
        exit(1)

    refresh = len(sys.argv) == 2 and sys.argv[1] == "refresh"

    generate_cumulative_diagram_trust(get_validity_periods_with_trust(refresh=refresh))

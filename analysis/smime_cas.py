import numpy as np
import matplotlib.pyplot as plt
import logging
from analysis.utils.log import set_up_logging
import os
import sys
import pandas as pd

from analysis.utils.aggregate import aggregate_certs_batchwise, reduce_groups
from analysis.utils.cache import JsonCacheManager, get_cache_name

from matplotlib import rcParams

rcParams["font.family"] = "DejaVu Sans"  # Set Default Matplotlib font for Chinese CAs

logger = logging.getLogger()
CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)


# Function to determine if a certificate is trusted
def is_trusted_origin(row):
    """Return True if any of the known trust origins is non-zero in this row."""
    trusted_origins = [
        "origin.mozilla",
        "origin.microsoft",
        "origin.macOS",
        "origin.chrome",
    ]
    return sum(row[origin] for origin in trusted_origins) > 0


def is_not_trusted_origin(row):
    return not is_trusted_origin(row)


def get_issuer_org_name_grouped(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Grouped issuer organization names"
    if not refresh and (result := json_cache.load(cache_name)):
        print(f"Total smime issuer organizations: {len(result)}")
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$group": {
                "_id": "$cert_fields.tbs_certificate.issuer.organization_name",
                "total": {"$count": {}},
            }
        },
        {"$project": {"_id": 0, "ca": "$_id", "total": 1}},
    ]

    logger.info("Executing issuer organization name group query")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("ca",))
    result = sorted(result, key=lambda x: x["total"], reverse=True)
    print(f"Total smime issuer organization names: {len(result)}")
    json_cache.save(cache_name, result, comment=comment)
    return result


# Function to compute CDF
def compute_cdf_data(grouped_data):
    totals = sorted([item["total"] for item in grouped_data], reverse=True)
    cumulative = np.cumsum(totals)
    cdf = cumulative / cumulative[-1]
    return cdf, totals


def generate_cdf(data_direct_issuer, data_root_ca):
    # Compute CDFs
    cdf1, counts1 = compute_cdf_data(data_direct_issuer)
    cdf2, counts2 = compute_cdf_data(data_root_ca)

    # Trim to top 50
    cdf1_top_50 = cdf1[:50]
    counts1_top_50 = counts1[:50]
    cdf2_top_50 = cdf2[:50]
    counts2_top_50 = counts2[:50]

    # Calculate cumulative sums
    cumulative_counts1 = np.cumsum(counts1)
    cumulative_counts2 = np.cumsum(counts2)

    # Calculate percentages for top 20 and top 50
    percent_top_20_direct = (
        cumulative_counts1[min(20, len(cumulative_counts1)) - 1]
        / cumulative_counts1[-1]
        * 100
    )
    percent_top_50_direct = (
        cumulative_counts1[min(50, len(cumulative_counts1)) - 1]
        / cumulative_counts1[-1]
        * 100
    )

    percent_top_20_root = (
        cumulative_counts2[min(20, len(cumulative_counts2)) - 1]
        / cumulative_counts2[-1]
        * 100
    )
    percent_top_50_root = (
        cumulative_counts2[min(50, len(cumulative_counts2)) - 1]
        / cumulative_counts2[-1]
        * 100
    )

    # Output
    print(f"Top 20 Direct Issuers: {percent_top_20_direct:.2f}%")
    print(f"Top 50 Direct Issuers: {percent_top_50_direct:.2f}%")
    print(f"Top 20 Root CAs: {percent_top_20_root:.2f}%")
    print(f"Top 50 Root CAs: {percent_top_50_root:.2f}%")

    # Plot
    plt.figure(figsize=(10, 6))
    plt.step(
        range(1, len(counts1_top_50) + 1),
        cdf1_top_50,
        where="mid",
        label="CDF - Intermediate (Top 50)",
    )
    plt.step(
        range(1, len(counts2_top_50) + 1),
        cdf2_top_50,
        where="mid",
        label="CDF - Root CA (Top 50)",
    )
    plt.xlabel("Top 50 Certificate Authorities")
    plt.ylabel("Cumulative Distribution Based on All Data")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.legend()
    plt.tight_layout()
    os.makedirs("assets/cache/diagrams/", exist_ok=True)
    plt.savefig(
        "assets/cache/diagrams/cdf_certificates_issued.png",
        dpi=300,
        bbox_inches="tight",
    )
    plt.show()


def get_root_org_name_grouped(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Grouped root organization names"
    if not refresh and (result := json_cache.load(cache_name)):
        print(f"Total smime root organizations: {len(result)}")
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {"$project": {"chain": {"$arrayElemAt": ["$chain.chain", 0]}}},
        {
            "$group": {
                "_id": "$chain.root_info.organization_name",
                "total": {"$count": {}},
            }
        },
        {"$project": {"_id": 0, "ca": "$_id", "total": 1}},
    ]

    logger.info("Executing root organization name group query")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("ca",))
    result = sorted(result, key=lambda x: x["total"], reverse=True)
    print(f"Total smime root organization names: {len(result)}")
    json_cache.save(cache_name, result, comment=comment)
    return result


def get_grouped_root_cas_for_certs_with_valid_chains(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Grouped root CAs for certs with valid chains"
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {"$project": {"chain": {"$arrayElemAt": ["$chain.chain", 0]}}},
        {
            "$match": {
                "chain.validation.validation_result": "VALID",
                "chain.root_info.organization_name": {
                    "$exists": True,
                    "$ne": "",
                },
            }
        },
        {
            "$group": {
                "_id": {
                    "ca": "$chain.root_info.organization_name",
                    "validation_result": "$chain.validation.validation_result",
                    "historical": "$chain.validation.historical",
                    "origin": "$chain.origin_info",
                },
                "total": {"$sum": 1},
            }
        },
        {
            "$project": {
                "ca": "$_id.ca",
                "validation_result": "$_id.validation_result",
                "historical": "$_id.historical",
                "origin": "$_id.origin",
                "total": 1,
                "_id": 0,
            }
        },
        {"$sort": {"total": -1}},
    ]

    logger.info("Executing grouped root CAs for certs with valid chains")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(
        result,
        group_by=(
            "ca",
            "validation_result",
            "historical",
            "origin",
        ),
    )
    result = sorted(result, key=lambda x: x["total"], reverse=True)
    json_cache.save(cache_name, result, comment=comment)
    return result


def generate_table_metrics_for_the_ten_most_common_root_cas(results):
    df = pd.json_normalize(results)

    # Calculate global totals
    grand_total_count = df["total"].sum()

    # Expired: certificates where "_id.historical" is True
    global_expired_count = df[df["historical"] == True]["total"].sum()

    # Valid: not expired and not trusted
    global_valid_count = df[
        (df["historical"] == False) & (~df.apply(is_trusted_origin, axis=1))
    ]["total"].sum()

    # Trusted: not expired and trusted
    global_trusted_count = df[
        (df["historical"] == False) & df.apply(is_trusted_origin, axis=1)
    ]["total"].sum()

    # Global percentages (should sum to 100%)
    global_expired_percent = (
        100.0 * global_expired_count / grand_total_count if grand_total_count else 0
    )
    global_valid_percent = (
        100.0 * global_valid_count / grand_total_count if grand_total_count else 0
    )
    global_trusted_percent = (
        100.0 * global_trusted_count / grand_total_count if grand_total_count else 0
    )
    global_total_count_percent = 100.0  # Total is 100% of itself

    # Prepare dictionary for the "Total" row
    total_row = {
        "ca": "Total",
        "expired_count": global_expired_count,
        "valid_count": global_valid_count,
        "trusted_count": global_trusted_count,
        "total_count": grand_total_count,
        "expired_percent": global_expired_percent,
        "valid_percent": global_valid_percent,
        "trusted_percent": global_trusted_percent,
        "total_count_percent": global_total_count_percent,
    }

    # Identify top 10 CAs by total count
    top_cas = df.groupby("ca")["total"].sum().sort_values(ascending=False).head(10)
    top_ca_names = top_cas.index.tolist()

    # Filter DataFrame for top 10 CAs
    filtered_df = df[df["ca"].isin(top_ca_names)]

    # Calculate metrics for each CA
    metrics = filtered_df.groupby("ca", group_keys=False).apply(
        lambda x: pd.Series(
            {
                "expired_count": x[x["historical"] == True]["total"].sum(),
                "valid_count": x[
                    (x["historical"] == False) & (~x.apply(is_trusted_origin, axis=1))
                ]["total"].sum(),
                "trusted_count": x[
                    (x["historical"] == False) & x.apply(is_trusted_origin, axis=1)
                ]["total"].sum(),
                "total_count": x["total"].sum(),
            }
        ),
        include_groups=False,
    )

    # Calculate percentages within each CA
    metrics["expired_percent"] = (
        100.0 * metrics["expired_count"] / metrics["total_count"]
    )
    metrics["valid_percent"] = 100.0 * metrics["valid_count"] / metrics["total_count"]
    metrics["trusted_percent"] = (
        100.0 * metrics["trusted_count"] / metrics["total_count"]
    )

    # Calculate percentage of the entire dataset
    metrics["total_count_percent"] = 100.0 * metrics["total_count"] / grand_total_count

    # Prepare final table
    final_table = metrics.reset_index().rename(columns={"ca": "ca"})

    # Ensure counts are integers
    for col in ("expired_count", "valid_count", "trusted_count", "total_count"):
        final_table[col] = final_table[col].astype(int)

    # Sort by total count descending
    final_table = final_table.sort_values(by="total_count", ascending=False)

    # Function to truncate CA names
    def truncate_ca_name(ca_name, length=18):
        """Truncate 'ca_name' if it exceeds 'length' characters, appending '...'."""
        return ca_name if len(ca_name) <= length else (ca_name[: length - 3] + "...")

    final_table["ca"] = final_table["ca"].apply(truncate_ca_name)

    # Generate LaTeX table
    latex_lines = []
    latex_lines.append(r"\begin{table*}[tb]")
    latex_lines.append(r"\centering")
    latex_lines.append(r"\small")
    latex_lines.append(
        r"\begin{tabular}{l r @{\hspace{.5em}} r r @{\hspace{.5em}} r r @{\hspace{.5em}} r r @{\hspace{.5em}} r}"
    )
    latex_lines.append(r"\toprule")
    latex_lines.append(
        r"\textbf{CA} & \multicolumn{2}{r}{\thead{Total (\%)}} & \multicolumn{2}{r}{\thead{Expired (\%)}} & \multicolumn{2}{r}{\thead{Untrusted (\%)}} & \multicolumn{2}{r}{\thead{Trusted (\%)}} \\"
    )
    latex_lines.append(r"\midrule")
    latex_lines.append(r"\midrule")

    # Add "Total" row
    total_ca_str = total_row["ca"]
    total_str = f"{total_row['total_count']:,} ({total_row['total_count_percent'] / 100:.2%})".replace(
        "%", r"\%"
    )
    expired_str = f"{total_row['expired_count']:,} ({total_row['expired_percent'] / 100:.2%})".replace(
        "%", r"\%"
    )
    valid_str = f"{total_row['valid_count']:,} ({total_row['valid_percent'] / 100:.2%})".replace(
        "%", r"\%"
    )
    trusted_str = f"{total_row['trusted_count']:,} ({total_row['trusted_percent'] / 100:.2%})".replace(
        "%", r"\%"
    )
    latex_lines.append(
        f"{total_ca_str} & {total_str} & {expired_str} & {valid_str} & {trusted_str} \\\\"
    )

    # Add gray midrule
    latex_lines.append(r"\arrayrulecolor{gray!90}")
    latex_lines.append(r"\midrule")
    latex_lines.append(r"\arrayrulecolor{black}")

    # Add rows for top 10 CAs
    for _, row in final_table.iterrows():
        ca_str = row["ca"]
        tot_str = (
            f"{row['total_count']:,} ({row['total_count_percent'] / 100:.2%})".replace(
                "%", r"\%"
            )
        )
        exp_str = (
            f"{row['expired_count']:,} ({row['expired_percent'] / 100:.2%})".replace(
                "%", r"\%"
            )
        )
        val_str = f"{row['valid_count']:,} ({row['valid_percent'] / 100:.2%})".replace(
            "%", r"\%"
        )
        trs_str = (
            f"{row['trusted_count']:,} ({row['trusted_percent'] / 100:.2%})".replace(
                "%", r"\%"
            )
        )
        latex_lines.append(
            f"{ca_str} & {tot_str} & {exp_str} & {val_str} & {trs_str} \\\\"
        )

    # Finalize LaTeX table
    latex_lines.append(r"\bottomrule")
    latex_lines.append(r"\end{tabular}")
    latex_lines.append(r"\caption{Metrics for the 10 most common root CAs.}")
    latex_lines.append(r"\label{tab:ca_metrics_with_totals}")
    latex_lines.append(r"\end{table*}")

    # Combine lines and print
    latex_table_code = "\n".join(latex_lines)
    print(latex_table_code)


def get_issuers_grouped(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Grouped issuer"
    if not refresh and (result := json_cache.load(cache_name)):
        print(comment)
        print(f"Total smime issuer: {len(result)}")
        return

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {"$group": {"_id": "$cert_fields.tbs_certificate.issuer"}},
    ]

    logger.info("Executing issuer group query")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(result, group_by=("_id",))
    print(f"Total smime issuer: {len(result)}")
    json_cache.save(cache_name, result, comment=comment)
    return


def get_grouped_validation_results(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Grouped validation results"
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {"$project": {"chain": {"$arrayElemAt": ["$chain.chain", 0]}}},
        {
            "$group": {
                "_id": {
                    "validation_result": "$chain.validation.validation_result",
                    "historical": "$chain.validation.historical",
                    "origin": "$chain.origin_info",
                },
                "total": {"$sum": 1},
            }
        },
        {
            "$project": {
                "validation_result": "$_id.validation_result",
                "historical": "$_id.historical",
                "origin": "$_id.origin",
                "total": 1,
                "_id": 0,
            }
        },
        {"$sort": {"total": -1}},
    ]

    logger.info("Executing grouped validation results query")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(
        result,
        group_by=(
            "validation_result",
            "historical",
            "origin",
        ),
    )
    result = sorted(result, key=lambda x: x["total"], reverse=True)
    json_cache.save(cache_name, result, comment=comment)
    return result


def generate_table_chain_validation_results_grouped_by_trust(results):
    df = pd.json_normalize(results)

    # Calculate totals
    total_expired = df[df["historical"] == True]["total"].sum()
    total_non_expired = df[df["historical"] == False]["total"].sum()
    total_certificates = total_expired + total_non_expired

    # Trusted
    trusted_expired = df[
        (df["historical"] == True) & df.apply(is_trusted_origin, axis=1)
    ]["total"].sum()
    trusted_non_expired = df[
        (df["historical"] == False) & df.apply(is_trusted_origin, axis=1)
    ]["total"].sum()
    trusted_total = trusted_expired + trusted_non_expired

    # Untrusted
    untrusted_expired = df[
        (df["validation_result"] == "VALID")
        & df.apply(is_not_trusted_origin, axis=1)
        & (df["historical"] == True)
    ]["total"].sum()

    untrusted_non_expired = df[
        (df["validation_result"] == "VALID")
        & df.apply(is_not_trusted_origin, axis=1)
        & (df["historical"] == False)
    ]["total"].sum()

    untrusted_total = untrusted_expired + untrusted_non_expired

    # Non-validatable
    non_validatable_expired = total_expired - trusted_expired - untrusted_expired
    non_validatable_non_expired = (
        total_non_expired - trusted_non_expired - untrusted_non_expired
    )
    non_validatable_total = non_validatable_expired + non_validatable_non_expired

    # Percentages (escaped for LaTeX)
    non_validatable_pct = f"{(non_validatable_total / total_certificates) * 100:.2f}\\%"
    untrusted_pct = f"{(untrusted_total / total_certificates) * 100:.2f}\\%"
    trusted_pct = f"{(trusted_total / total_certificates) * 100:.2f}\\%"

    # LaTeX output
    latex = f"""
    \\begin{{table}}[tb]
        \\footnotesize
        \\centering
        \\setlength\\tabcolsep{{.4em}}
        \\begin{{tabular}}{{l r r @{{\\hspace{{1.2em}}}} r @{{\hspace{{.3em}}}} r}}
        \\toprule
                \\thead{{Expired}} & \\thead{{Non-Expired}} & \\multicolumn{{2}}{{r}}{{\\thead{{S/MIME certs. (\\%)}}}}\\
        \\midrule\\midrule
        Total     & {total_expired:,} & {total_non_expired:,} & {total_certificates:,} & (100.00\\%)\\\\
        \\midrule
        Trusted   & {trusted_expired:,} & {trusted_non_expired:,} & {trusted_total:,} & ({trusted_pct})\\\\
        Untrusted & {untrusted_expired:,} & {untrusted_non_expired:,} & {untrusted_total:,} & ({untrusted_pct})\\\\
        Non-Validatable  & {non_validatable_expired:,} & {non_validatable_non_expired:,} & {non_validatable_total:,} & ({non_validatable_pct})\\\\
        \\arrayrulecolor{{black}}
        \\bottomrule
        \\end{{tabular}}
        \\caption{{Chain validation results for S/MIME certificates.}}
        \\label{{tab:smime_chains}}
    \\end{{table}}
    """

    print(latex)


def get_most_common_chain_validation_error_reasons(refresh: bool = False):
    cache_name = get_cache_name()
    comment = "Most common chain validation error reasons"
    if not refresh and (result := json_cache.load(cache_name)):
        return result

    pipeline = [
        {
            "$lookup": {
                "from": "chain",
                "localField": "_id",
                "foreignField": "_id",
                "as": "chain",
            }
        },
        {"$project": {"chain": {"$arrayElemAt": ["$chain.chain", 0]}}},
        {"$match": {"chain.validation.error": {"$ne": ""}}},
        {"$match": {"chain.validation.error": {"$ne": None}}},
        {
            "$group": {
                "_id": {
                    "result": "$chain.validation.validation_result",
                    "error": "$chain.validation.error",
                },
                "total": {"$sum": 1},
            }
        },
        {
            "$project": {
                "result": "$_id.result",
                "error": "$_id.error",
                "total": 1,
                "_id": 0,
            }
        },
        {"$sort": {"total": -1}},
    ]

    logger.info("Executing most common chain validation error reasons query")
    result = aggregate_certs_batchwise(pipeline=pipeline)
    result = reduce_groups(
        result,
        group_by=(
            "result",
            "error",
        ),
    )
    result = sorted(result, key=lambda x: x["total"], reverse=True)
    json_cache.save(cache_name, result, comment=comment)

    print("Most common reasons for invalid chains:")
    for i, entry in enumerate(result[:5], 1):
        print(f"{i}. {entry['total']:,}: {entry['result']}:{entry['error']}")

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

    result_issuer_names = get_issuer_org_name_grouped(refresh=refresh_flag)
    result_root_names = get_root_org_name_grouped(refresh=refresh_flag)
    generate_cdf(result_issuer_names, result_root_names)

    result_grouped_by_root_cas = get_grouped_root_cas_for_certs_with_valid_chains(
        refresh=refresh_flag
    )
    generate_table_metrics_for_the_ten_most_common_root_cas(result_grouped_by_root_cas)

    get_issuers_grouped(refresh=refresh_flag)

    results_grouped_validation_result = get_grouped_validation_results(
        refresh=refresh_flag
    )
    generate_table_chain_validation_results_grouped_by_trust(
        results_grouped_validation_result
    )

    get_most_common_chain_validation_error_reasons(refresh=refresh_flag)

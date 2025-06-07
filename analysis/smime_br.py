# %%
from collections import defaultdict
from copy import deepcopy
import logging
import os
import sys
from pprint import pprint

# %%
from analysis.utils.log import set_up_logging

from analysis.utils.cache import JsonCacheManager, get_cache_name
from analysis.utils.aggregate import aggregate_batchwise, reduce_groups

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger()

CACHE_PATH = os.path.join("assets", "cache")
json_cache = JsonCacheManager(CACHE_PATH)
SMIME_TOTAL = 0
# %%
BR_PUBLISHED = "2023-01-01T00:00:00+00:00"

FILTER_BR_LOOKUP_PUBLISHED = [
    {
        "$lookup": {
            "from": "certificates",
            "localField": "_id",
            "foreignField": "_id",
            "as": "validity",
            "pipeline": [
                {
                    "$project": {
                        "not_before": "$cert_fields.tbs_certificate.validity.not_before_iso"
                    }
                },
            ],
        }
    },
    {"$match": {"validity.not_before": {"$gt": BR_PUBLISHED}}},
]


FILTER_BR_PUBLISHED = [
    {
        "$match": {
            "cert_fields.tbs_certificate.validity.not_before_iso": {"$gt": BR_PUBLISHED}
        }
    }
]
# %%


def count_smime_certificates_br_published(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result[0].get("count")
    pipeline = [
        *FILTER_BR_PUBLISHED,
        {
            "$match": {
                "is_smime.is_smime": True,
            }
        },
        {"$group": {"_id": None, "count": {"$sum": 1}}},
    ]

    result = aggregate_batchwise("certificates", pipeline=pipeline, processes=60)
    result = reduce_groups(result=result, group_by=("_id",))

    number_of_smime_certs = result[0].get("count")

    json_cache.save(cache_name, result)
    return number_of_smime_certs


# %%
BR_CATEGORY_DICT = {
    "Faulty Value": {
        "cabf.cps_uri_is_not_http",
        "cabf.invalid_organization_identifier_country",
        "cabf.invalid_organization_identifier_registration_scheme",
        "cabf.invalid_subject_organization_identifier_encoding",
        "cabf.invalid_subject_organization_identifier_format",
        "cabf.smime.multiple_reserved_policy_oids",
        "cabf.smime.org_identifier_and_country_name_attribute_inconsistent",
        "iso.lei.invalid_lei_format",
        "itu.bitstring_not_der_encoded",
        "msft.invalid_user_principal_name_syntax",
        "pkix.basic_constraints_has_pathlen_for_non_ca",
        "pkix.certificate_negative_validity_period",
        "pkix.certificate_serial_number_out_of_range",
        "pkix.certificate_version_is_not_v3",
        "pkix.duplicate_certificate_policy_oids",
        "pkix.duplicate_extension",
        "pkix.invalid_domain_name_syntax",
        "pkix.invalid_email_address_syntax",
        "pkix.invalid_time_syntax",
        "pkix.invalid_uri_syntax",
        "pkix.name_domain_components_invalid_domain_name",
        "pkix.rdn_contains_duplicate_attribute_types",
        "pkix.rfc5280_certificate_policies_invalid_explicit_text_encoding",
        "pkix.utctime_incorrect_syntax",
        "pkix.wrong_time_useful_type",
    },
    "Key Usage Issues": {
        "cabf.smime.emailprotection_eku_missing",
        "cabf.smime.extended_key_usage_extension_missing",
        "cabf.smime.key_usage_extension_missing",
        "cabf.smime.prohibited_eku_present",
        "cabf.smime.prohibited_ku_present",
        "cabf.smime.unknown_certificate_key_usage_type",
        "pkix.ca_certificate_keycertsign_keyusage_not_set",
        "pkix.ca_certificate_no_ku_extension",
        "pkix.ee_certificate_keycertsign_keyusage_set",
    },
    "Insecure Parameters": {
        "cabf.rsa_exponent_prohibited_value",
        "cabf.rsa_modulus_invalid_length",
        "cabf.smime.certificate_validity_period_exceeds_1185_days",
        "cabf.smime.certificate_validity_period_exceeds_825_days",
        "cabf.smime.is_ca_certificate",
        "cabf.smime.prohibited_signature_algorithm_encoding",
        "cabf.smime.prohibited_spki_algorithm_encoding",
        "cabf.smime.unsupported_public_key_type",
        "pkix.certificate_signature_algorithm_mismatch",
    },
    "Missing Mandatory Info": {
        "cabf.aia_ca_issuers_has_no_http_uri",
        "cabf.aia_ocsp_has_no_http_uri",
        "cabf.certificate_extensions_missing",
        "cabf.no_http_crldp_uri",
        "cabf.smime.certificate_policies_extension_missing",
        "cabf.smime.missing_required_attribute",
        "cabf.smime.no_required_reserved_policy_oid",
        "cabf.smime.required_attribute_missing_for_dependent_attribute",
        "cabf.smime.san_does_not_contain_email_address",
        "cabf.smime.san_extension_missing",
        "pkix.authority_key_identifier_extension_absent",
        "pkix.authority_key_identifier_keyid_missing",
        "pkix.certificate_skid_ca_missing",
        "pkix.subject_email_address_not_in_san",
    },
    "Oversharing": {
        "cabf.authority_key_identifier_has_issuer_cert",
        "cabf.insignificant_attribute_value_present",
        "pkix.issuer_unique_id_present",
    },
    "Prohibited Value": {
        "cabf.internal_domain_name",
        "cabf.internal_ip_address",
        "cabf.smime.anypolicy_present",
        "cabf.smime.crldp_fullname_prohibited_generalname_type",
        "cabf.smime.crldp_fullname_prohibited_uri_scheme",
        "cabf.smime.email_address_in_attribute_not_in_san",
        "cabf.smime.mixed_name_and_pseudonym_attributes",
        "cabf.smime.prohibited_attribute",
        "cabf.smime.prohibited_generalname_type_present",
        "cabf.smime.prohibited_organization_identifier_reference_present_for_scheme",
        "cabf.smime.prohibited_othername_type_present",
        "cabf.smime.subject_directory_attributes_extension_prohibited",
        "cabf.smime.usernotice_has_noticeref",
        "pkix.prohibited_qualified_statement_present",
    },
    "Unknown Value": {
        "cabf.invalid_country_code",
        "cabf.smime.common_name_value_unknown_source",
        "itu.invalid_printablestring_character",
    },
    "Wrong Criticality": {
        "cabf.critical_crldp_extension",
        "cabf.smime.qc_statements_extension_critical",
        "pkix.authority_information_access_extension_critical",
        "pkix.authority_key_identifier_critical",
        "pkix.basic_constraints_extension_not_critical",
        "pkix.certificate_name_constraints_extension_not_critical",
        "pkix.certificate_skid_extension_critical",
    },
}
ALL_CODES = set()
for _, v in BR_CATEGORY_DICT.items():
    for x in v:
        assert x not in ALL_CODES  # Ensure no duplicate categorization
        ALL_CODES.add(x)

INCORRECT_REVOCATION = [
    "cabf.aia_ca_issuers_has_no_http_uri",
    "cabf.aia_ocsp_has_no_http_uri",
    "cabf.no_http_crldp_uri",
]
LONG_VALIDITY = [
    "cabf.smime.certificate_validity_period_exceeds_825_days",
    "cabf.smime.certificate_validity_period_exceeds_1185_days",
]

PAPER_MAP = {
    "ReservedPolicy": ["cabf.smime.no_required_reserved_policy_oid"],
    "Forbidden Signature Algorithm": [
        "cabf.smime.prohibited_signature_algorithm_encoding"
    ],
    "No Issuer HTTP URI": ["cabf.aia_ca_issuers_has_no_http_uri"],
    "Invalid RSA Modulus Length": ["cabf.rsa_modulus_invalid_length"],
}


def create_category_table():
    # %%
    prefix = r"""\begin{table}[!p]
\setlength\tabcolsep{1pt}
    \footnotesize
    \centering
\begin{tabularx}{\linewidth}{@{} X @{}}
\toprule
    \thead{Group Name} \\
\arrayrulecolor{black}
\midrule"""
    suffix1 = r"""
\arrayrulecolor{black}
\bottomrule
\end{tabularx}
\caption{Grouped pkilint checks with severity 'Error'.}
\label{tab:pkilint_error_group}
\end{table}"""
    suffix2 = r"""
\arrayrulecolor{black}
\bottomrule
\end{tabularx}
\caption{Grouped pkilint checks with severity 'Error'.}
\label{tab:pkilint_error_group2}
\end{table}"""
    body1 = ""
    body2 = ""
    for category, values in BR_CATEGORY_DICT.items():
        category_head = r"\thead{" + category + "}\\\\"
        if category in [
            "Key Usage Issues",
            "Insecure Parameters",
            "Missing Mandatory Info",
        ]:
            body1 += (
                f"\n\\midrule\n{category_head}\n\\arrayrulecolor{{gray!90}}\\midrule"
            )
            for value in values:
                escaped = value.replace("_", r"\_")
                body1 += f"\n{escaped}\\\\"
        else:
            body2 += (
                f"\n\\midrule\n{category_head}\n\\arrayrulecolor{{gray!90}}\\midrule"
            )
            for value in values:
                escaped = value.replace("_", r"\_")
                body2 += f"\n{escaped}\\\\"

    return prefix + body1 + suffix1 + "\n\n" + prefix + body2 + suffix2


# %%


# TODO: Finding Descriptions can be an array of multiple values, e.g. for "cabf.rsa_modulus_has_small_prime_factor"
def get_br_error_count(refresh: bool = False) -> dict:
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {
            "$match": {
                "pkilint.results.finding_descriptions.severity": "ERROR",
                "is_smime": True,
            }
        },
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$project": {
                "findings": {
                    "$reduce": {
                        "input": "$pkilint.results",
                        "initialValue": [],
                        "in": {
                            "$concatArrays": ["$$value", "$$this.finding_descriptions"]
                        },
                    }
                }
            }
        },
        {
            "$project": {
                "findings": {
                    "$filter": {
                        "input": "$findings",
                        "as": "value",
                        "cond": {"$eq": ["$$value.severity", "ERROR"]},
                    }
                }
            }
        },
        {"$project": {"codes": {"$setIntersection": ["$findings.code"]}}},
        {"$unwind": {"path": "$codes", "preserveNullAndEmptyArrays": False}},
        {"$group": {"_id": "$codes", "count": {"$count": {}}}},
    ]

    result = aggregate_batchwise("pkilint", pipeline=pipeline, processes=60)

    result = reduce_groups(results=result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_valid_too_long(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {
            "$match": {"is_smime": True},
        },
        {"$match": {"pkilint.results.finding_descriptions.severity": "ERROR"}},
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$project": {
                "codes": {
                    "$reduce": {
                        "input": "$pkilint.results.finding_descriptions.code",
                        "initialValue": [],
                        "in": {"$concatArrays": ["$$value", "$$this"]},
                    }
                }
            }
        },
        {
            "$addFields": {
                "long_validity": {
                    "$toInt": {
                        "$toBool": {
                            "$size": {"$setIntersection": ["$codes", LONG_VALIDITY]}
                        }
                    }
                }
            }
        },
        {
            "$group": {
                "_id": "long_validity",
                "count": {"$sum": "$long_validity"},
            }
        },
    ]
    result = aggregate_batchwise("pkilint", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_incorrect_revocation(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {
            "$match": {"is_smime": True},
        },
        {"$match": {"pkilint.results.finding_descriptions.severity": "ERROR"}},
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$project": {
                "codes": {
                    "$reduce": {
                        "input": "$pkilint.results.finding_descriptions.code",
                        "initialValue": [],
                        "in": {"$concatArrays": ["$$value", "$$this"]},
                    }
                }
            }
        },
        {
            "$addFields": {
                "incorrect_revocation": {
                    "$toInt": {
                        "$toBool": {
                            "$size": {
                                "$setIntersection": ["$codes", INCORRECT_REVOCATION]
                            }
                        }
                    }
                }
            }
        },
        {
            "$group": {
                "_id": "incorrect_revocation",
                "count": {"$sum": "$incorrect_revocation"},
            }
        },
    ]
    result = aggregate_batchwise("pkilint", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_br_category_counts(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {
            "$match": {"is_smime": True},
        },
        {"$match": {"pkilint.results.finding_descriptions.severity": "ERROR"}},
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$project": {
                "codes": {
                    "$reduce": {
                        "input": "$pkilint.results.finding_descriptions.code",
                        "initialValue": [],
                        "in": {"$concatArrays": ["$$value", "$$this"]},
                    }
                }
            }
        },
        {
            "$addFields": {
                category: {
                    "$toInt": {
                        "$toBool": {
                            "$size": {"$setIntersection": ["$codes", list(values)]}
                        }
                    }
                }
                for category, values in BR_CATEGORY_DICT.items()
            }
        },
        {
            "$group": {
                "_id": None,
                **{
                    category: {"$sum": f"${category}"}
                    for category in BR_CATEGORY_DICT.keys()
                },
            }
        },
    ]
    result = aggregate_batchwise("pkilint", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_br_category_counts_no_policy(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    br_dict = deepcopy(BR_CATEGORY_DICT)
    br_dict["Missing Mandatory Info"].remove(
        "cabf.smime.no_required_reserved_policy_oid"
    )
    pipeline = [
        {
            "$match": {"is_smime": True},
        },
        {"$match": {"pkilint.results.finding_descriptions.severity": "ERROR"}},
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$project": {
                "codes": {
                    "$reduce": {
                        "input": "$pkilint.results.finding_descriptions.code",
                        "initialValue": [],
                        "in": {"$concatArrays": ["$$value", "$$this"]},
                    }
                }
            }
        },
        {
            "$addFields": {
                category: {
                    "$toInt": {
                        "$toBool": {
                            "$size": {"$setIntersection": ["$codes", list(values)]}
                        }
                    }
                }
                for category, values in br_dict.items()
            }
        },
        {
            "$group": {
                "_id": None,
                **{category: {"$sum": f"${category}"} for category in br_dict.keys()},
            }
        },
    ]

    result = aggregate_batchwise("pkilint", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_br_category_counts_by_ca(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {"$match": {"is_smime": True}},
        {"$project": {"root_ca": "$chain.root_info.organization_name"}},
        {"$match": {"root_ca": {"$ne": None}}},
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$lookup": {
                "from": "pkilint",
                "localField": "_id",
                "foreignField": "_id",
                "as": "code",
                "pipeline": [
                    {
                        "$match": {
                            "pkilint.results.finding_descriptions.severity": "ERROR"
                        }
                    },
                    {
                        "$project": {
                            "codes": {
                                "$reduce": {
                                    "input": "$pkilint.results.finding_descriptions.code",
                                    "initialValue": [],
                                    "in": {"$concatArrays": ["$$value", "$$this"]},
                                }
                            }
                        }
                    },
                ],
            }
        },
        {"$project": {"root_ca": 1, "codes": {"$first": "$code.codes"}}},
        {"$project": {"root_ca": 1, "codes": {"$ifNull": ["$codes", []]}}},
        {
            "$addFields": {
                "count": 1,
                **{
                    category: {
                        "$toInt": {
                            "$toBool": {
                                "$size": {"$setIntersection": ["$codes", list(values)]}
                            }
                        }
                    }
                    for category, values in BR_CATEGORY_DICT.items()
                },
            }
        },
        {
            "$project": {
                "count": 1,
                **{category: 1 for category in BR_CATEGORY_DICT.keys()},
                "root_ca": 1,
                "none": {"$cond": [{"$eq": [{"$size": "$codes"}, 0]}, 1, 0]},
            }
        },
        {
            "$group": {
                "_id": "$root_ca",
                "count": {"$sum": "$count"},
                "none": {"$sum": "$none"},
                **{
                    category: {"$sum": f"${category}"}
                    for category in BR_CATEGORY_DICT.keys()
                },
            }
        },
    ]
    result = aggregate_batchwise("chain", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_br_error_counts_by_ca(refresh: bool = False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {"$match": {"is_smime": True}},
        {"$project": {"root_ca": "$chain.root_info.organization_name"}},
        {"$match": {"root_ca": {"$ne": None}}},
        *FILTER_BR_LOOKUP_PUBLISHED,
        {
            "$lookup": {
                "from": "pkilint",
                "localField": "_id",
                "foreignField": "_id",
                "as": "code",
                "pipeline": [
                    {
                        "$project": {
                            "findings": {
                                "$reduce": {
                                    "input": "$pkilint.results",
                                    "initialValue": [],
                                    "in": {
                                        "$concatArrays": [
                                            "$$value",
                                            "$$this.finding_descriptions",
                                        ]
                                    },
                                }
                            }
                        }
                    }
                ],
            }
        },
        {"$project": {"root_ca": 1, "codes": {"$first": "$code.findings"}}},
        {
            "$project": {
                "root_ca": 1,
                "findings": {
                    "$filter": {
                        "input": "$codes",
                        "as": "value",
                        "cond": {"$eq": ["$$value.severity", "ERROR"]},
                    }
                },
            }
        },
        {"$project": {"root_ca": 1, "codes": "$findings.code"}},
        {"$unwind": {"path": "$codes", "preserveNullAndEmptyArrays": False}},
        {
            "$group": {
                "_id": {"root_ca": "$root_ca", "codes": "$codes"},
                "count": {"$count": {}},
            }
        },
        {"$project": {"_id": "$_id.root_ca", "code": "$_id.codes", "count": 1}},
    ]
    result = aggregate_batchwise("chain", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id", "code"))

    json_cache.save(cache_name, result)
    return result


def get_no_aia(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {
            "$match": {
                "is_smime.is_smime": True,
                "extensions.authority_information_access": {"$exists": False},
            }
        },
        *FILTER_BR_PUBLISHED,
        {
            "$group": {
                "_id": None,
                "no_aia": {"$count": {}},
            }
        },
    ]
    result = aggregate_batchwise("certificates", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_aia_without_issuers(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        *FILTER_BR_PUBLISHED,
        {
            "$match": {
                "is_smime.is_smime": True,
                "extensions.authority_information_access": {"$exists": True},
                "extensions.authority_information_access.value.access_method": {
                    "$ne": "ca_issuers"
                },
            }
        },
        {
            "$group": {
                "_id": None,
                "no_aia_issuer": {"$count": {}},
            }
        },
    ]
    result = aggregate_batchwise("certificates", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_without_ocsp_or_crl(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        *FILTER_BR_PUBLISHED,
        {
            "$match": {
                "is_smime.is_smime": True,
                "extensions.authority_information_access": {"$exists": True},
                "extensions.authority_information_access.value.access_method": {
                    "$ne": "ocsp"
                },
                "extensions.crl_distribution_points": {"$exists": False},
            }
        },
        {
            "$group": {
                "_id": None,
                "no_revocation": {"$count": {}},
            }
        },
    ]
    result = aggregate_batchwise("certificates", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_no_eku(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {
            "$match": {
                "is_smime.is_smime": True,
                "extensions.extended_key_usage": {"$exists": False},
            }
        },
        *FILTER_BR_PUBLISHED,
        {
            "$group": {
                "_id": None,
                "no_eku": {"$count": {}},
            }
        },
    ]
    result = aggregate_batchwise("certificates", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def get_error_related_numbers(refresh=False):
    return {
        "NoEku": get_no_eku(refresh)[0]["no_eku"],
        "NoAia": get_no_aia(refresh)[0]["no_aia"],
        "NoAiaIssuer": get_aia_without_issuers(refresh)[0]["no_aia_issuer"],
        "InvalidRevocation": get_incorrect_revocation(refresh)[0]["count"],
        "NoRevocation": get_without_ocsp_or_crl(refresh)[0]["no_revocation"],
        "LongValidity": get_valid_too_long(refresh)[0]["count"],
    }


def paper_numbers(numbers: dict[str, dict], error_counts, refresh=False):
    numbers["errors"] = defaultdict(lambda: deepcopy({"total": 0, "pct": 0}))
    numbers["stats"] = {}
    stats = get_error_related_numbers()
    for k, v in stats.items():
        numbers["stats"][k] = {
            "total": f"{v:,}",
            "pct": f"{v / SMIME_TOTAL_SINCE_23 * 100:.2f}",
        }
    for error in error_counts:
        key = error["_id"]
        for k, v in PAPER_MAP.items():
            if key in v:
                name = k
                total = numbers["errors"][name]["total"] + error["count"]
                pct = total / SMIME_TOTAL_SINCE_23
                numbers["errors"][name] = {
                    "total": total,
                    "pct": pct,
                }
    for k, v in numbers["errors"].items():
        total = v["total"]
        numbers["errors"][k]["total"] = f"{total:,}"
        numbers["errors"][k]["pct"] = f"{total / SMIME_TOTAL_SINCE_23 * 100:.2f}"
    for k, v in numbers.items():
        command_name_first = f"{k}"
        for k_inner, v_inner in v.items():
            command_name = command_name_first + k_inner.replace(" ", "")
            print(
                r"\newcommand{" + "\\" + command_name + r"}{" + v_inner["total"] + r"}"
            )
            print(
                f"\\newcommand{{\\{command_name}Pct}}{{\\SI{{{v_inner['pct']}}}{{\\percent}}}}"
            )
    print(f"\\newcommand{{\\allSMIMESinceBR}}{{{SMIME_TOTAL_SINCE_23:,}}}")


def get_trust_by_month(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {"$match": {"is_smime": True, "chain.validation.validation_result": "VALID"}},
        {
            "$project": {
                "root_ca": "$chain.root_info.organization_name",
                "validation_result": "$chain.validation.validation_result",
                "trusted": {
                    "$expr": {
                        "$or": [
                            {"$eq": ["$chain.origin_info.mozilla", 1]},
                            {"$eq": ["$chain.origin_info.microsoft", 1]},
                            {"$eq": ["$chain.origin_info.macOS", 1]},
                            {"$eq": ["$chain.origin_info.chrome", 1]},
                        ]
                    }
                },
            }
        },
        {"$match": {"trusted": True}},
        {
            "$lookup": {
                "from": "certificates",
                "localField": "_id",
                "foreignField": "_id",
                "as": "valid_since",
                "pipeline": [
                    {
                        "$project": {
                            "valid_since": {
                                "$dateToString": {
                                    "format": "%Y-%m",
                                    "date": {
                                        "$toDate": {
                                            "$multiply": [
                                                "$cert_fields.tbs_certificate.validity.not_before",
                                                1000,
                                            ]
                                        }
                                    },
                                }
                            }
                        }
                    }
                ],
            }
        },
        {"$addFields": {"valid_since": {"$first": "$valid_since.valid_since"}}},
        {
            "$lookup": {
                "from": "pkilint",
                "localField": "_id",
                "foreignField": "_id",
                "as": "severity",
                "pipeline": [
                    {
                        "$project": {
                            "severity": {
                                "$reduce": {
                                    "input": "$pkilint.results.finding_descriptions.severity",
                                    "initialValue": [],
                                    "in": {"$concatArrays": ["$$value", "$$this"]},
                                }
                            },
                            "error": "$pkilint.error",
                        }
                    },
                    {
                        "$project": {
                            "critical": {
                                "$toInt": {
                                    "$toBool": {
                                        "$size": {
                                            "$setIntersection": [
                                                {
                                                    "$ifNull": [
                                                        "$severity",
                                                        {
                                                            "$cond": [
                                                                {
                                                                    "$not": [
                                                                        "$pkilint.error"
                                                                    ]
                                                                },
                                                                ["FATAL"],
                                                                [],
                                                            ]
                                                        },
                                                    ]
                                                },
                                                ["FATAL", "ERROR"],
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    {"$addFields": {"non_critical": {"$toInt": {"$not": "$critical"}}}},
                ],
            }
        },
        {"$addFields": {"severity": {"$first": "$severity"}}},
        {
            "$group": {
                "_id": {"valid_since": "$valid_since", "root_ca": "$root_ca"},
                "critical": {"$sum": "$severity.critical"},
                "non_critical": {"$sum": "$severity.non_critical"},
                "count": {"$count": {}},
            }
        },
        {
            "$project": {
                "_id": 0,
                "root_ca": {"$ifNull": ["$_id.root_ca", ""]},
                "valid_since": "$_id.valid_since",
                "critical": 1,
                "non_critical": 1,
                "count": 1,
            }
        },
    ]
    result = aggregate_batchwise(
        "chain", pipeline=pipeline, processes=80, batch_size=100000
    )

    result = reduce_groups(result, group_by=("root_ca", "valid_since"))

    json_cache.save(cache_name, result)
    return result


def generate_top_10_heatmap(result: list[dict]):
    # results = group_by_nested_key(data["results"],['severity','code','root_ca'])
    results = []
    for row in result:
        for k in row.keys():
            if k in BR_CATEGORY_DICT.keys() or k == "none":
                new_row = {
                    "root_ca": row["_id"],
                    "total": row["count"],
                    "count": row[k],
                    "classes": k if k != "none" else "Correct",
                }
                results.append(new_row)
    df = pd.json_normalize(results)

    # 1) Create a dictionary to map long names to short names
    rename_map = {
        "A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH": "A-Trust"
        # Add more if you wish
    }

    # 2) Apply the replacements in your DataFrame
    df["root_ca"] = df["root_ca"].replace(rename_map)

    # ----------------------------------------------------------------------------
    # 0) Identify top 10 root CAs by total count
    top_cas = df.groupby("root_ca")["total"].max().nlargest(10).index

    # 1) Filter the DataFrame for these top 10 root CAs
    filtered_df = df[df["root_ca"].isin(top_cas)].copy()

    # ----------------------------------------------------------------------------
    # 2) Group by the "classes" column and "root_ca"
    grouped_df = (
        filtered_df.groupby(["classes", "root_ca"])[["count", "total"]]
        .sum()
        .reset_index()
    )
    grouped_df["pct"] = grouped_df["count"] / grouped_df["total"] * 100.0

    # 3) Pivot for the heatmap: rows = classes, columns = root_ca
    heatmap_data = grouped_df.pivot(
        index="classes", columns="root_ca", values=["pct"]
    ).fillna(0)

    # 4) Remove pct- prefix
    heatmap_data.columns = heatmap_data.columns.get_level_values(1)

    heatmap_data = heatmap_data.loc[list(BR_CATEGORY_DICT.keys()) + ["Correct"]]
    # 5) Plot the heatmap with percentages
    plt.figure(figsize=(12, 8))
    ax = sns.heatmap(
        heatmap_data,
        annot=True,
        fmt=".1f",
        annot_kws={"size": 14},  # Change annotation font size
        cmap="YlGnBu",
        linewidths=0.5,
    )
    ax.set_xlabel(None)

    # Increase x and y label font sizes
    # plt.ylabel("Categories of pkilint error messages", fontsize=14)
    ax.set(ylabel=None)

    # Increase x and y tick font sizes
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    # Rotate x-tick labels 45 degrees and align them to the right
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    plt.axhline(8, 0, 1, color="gray", linewidth=2, linestyle=":")

    plt.tight_layout()
    os.makedirs("assets/cache/diagrams/", exist_ok=True)
    plt.savefig("assets/cache/diagrams/br_heatmap.pdf")
    plt.show()

    # Compute average percentage per category across top 10 CAs
    category_avg_pct = heatmap_data.mean(axis=1).sort_values(ascending=False)

    print("Average % of each error category across Top 10 Root CAs:\n")
    for cls, pct in category_avg_pct.items():
        print(f"{cls:40s}: {pct:.2f}%")


def generate_br_histogram(data):
    # Convert data into a DataFrame
    reformatted = []
    for item in data:
        if item["valid_since"] >= "2023-01" and item["valid_since"] <= "2025-04":
            reformatted.append(
                {
                    "root_ca": item["root_ca"],
                    "valid_since": item["valid_since"],
                    "severity": "critical",
                    "count": item["critical"],
                }
            )
            reformatted.append(
                {
                    "root_ca": item["root_ca"],
                    "valid_since": item["valid_since"],
                    "severity": "non_critical",
                    "count": item["non_critical"],
                }
            )
    df = pd.DataFrame(
        [
            {
                "organization_name": item["root_ca"],
                "valid_since": item["valid_since"],
                "severity": item["severity"],
                "count": item["count"],
            }
            for item in reformatted
        ]
    )

    # Convert 'valid_since' to datetime format
    df["valid_since"] = pd.to_datetime(df["valid_since"], format="%Y-%m")

    # Group and sum counts by month and severity
    monthly_severity = (
        df.groupby(["valid_since", "severity"])["count"].sum().unstack(fill_value=0)
    )

    # Reorder columns to have 'non_critical' at the bottom
    monthly_severity = monthly_severity[["non_critical", "critical"]]

    # Normalize data by month
    normalized_monthly_severity = monthly_severity.div(
        monthly_severity.sum(axis=1), axis=0
    )

    # Filter data for the desired date range
    start_date = pd.to_datetime("01.2023", format="%m.%Y")
    end_date = pd.to_datetime("04.2025", format="%m.%Y")
    filtered_severity = normalized_monthly_severity.loc[start_date:end_date]

    # Calculate unique organizations per month for 'non_critical' severity
    unique_orgs_per_month = (
        df[df["severity"] == "non_critical"]
        .groupby("valid_since")["organization_name"]
        .nunique()
        .reindex(filtered_severity.index, fill_value=0)
    )

    # Create a figure and axis
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.tick_params(axis="y", labelsize=12)

    # Convert the index to a simple range for plotting
    x = range(len(filtered_severity.index))

    # Extract values for stacked bars
    non_crit_values = filtered_severity["non_critical"].values
    crit_values = filtered_severity["critical"].values

    # 1) Plot the stacked bars
    # Bottom layer (non_critical)
    ax.bar(x, non_crit_values, width=0.8, color="#3E7B27", label="BR-Compliant")

    # Top layer (critical)
    ax.bar(
        x,
        crit_values,
        width=0.8,
        bottom=non_crit_values,
        color="#BFBBA9",
        label="non-BR-Compliant",
    )

    ax2 = ax.twinx()
    ax2.tick_params(axis="y", labelsize=12)
    ax2.set_ylabel("# of trusted CAs issuing BR-compliant Certs.", fontsize=12)
    ax2.set_ylim(0, unique_orgs_per_month.max() * 1.2)

    # 2) Plot the line for unique organizations on the same axis
    ax2.plot(
        x,
        unique_orgs_per_month.values,
        color="#5B913B",
        marker="o",
        linestyle="-",
        label="# of trusted CAs issuing BR-compliant Certs.",
    )
    ax2.legend(loc="upper right", fontsize=10, framealpha=1)

    # Single y-axis: keep in mind that proportions and absolute counts share the same scale
    ax.set_ylabel("Proportion of BR-compliant trusted Certs.", fontsize=12)
    # ax.set_title('Normalized Baseline Requirement Compliance')

    # Set x-ticks and their labels to the month-year from the filtered index
    ax.set_xticks(x)
    ax.set_xticklabels(
        filtered_severity.index.strftime("%m.%Y"), rotation=90, fontsize=12
    )
    ax2.set_yticks(range(0, 21, 2))

    # Show legend
    ax.legend(loc="upper left", fontsize=10, framealpha=1)

    # Adjust layout for better appearance
    plt.tight_layout()
    os.makedirs("assets/cache/diagrams/", exist_ok=True)
    plt.savefig("assets/cache/diagrams/br_histogram.pdf", dpi=300, bbox_inches="tight")

    # Display the plot
    plt.show()


def get_policy_data(refresh=False):
    cache_name = get_cache_name()
    if not refresh and (result := json_cache.load(cache_name)):
        return result
    pipeline = [
        {"$match": {"is_smime.is_smime": True}},
        *FILTER_BR_PUBLISHED,
        {
            "$lookup": {
                "from": "pkilint",
                "localField": "_id",
                "foreignField": "_id",
                "as": "pkilint",
            }
        },
        {"$project": {"pkilint": {"$arrayElemAt": ["$pkilint.pkilint", 0]}}},
        {"$group": {"_id": "$pkilint.certificate_type", "count": {"$sum": 1}}},
    ]
    result = aggregate_batchwise("certificates", pipeline=pipeline, processes=60)

    result = reduce_groups(result, group_by=("_id",))

    json_cache.save(cache_name, result)
    return result


def generate_br_policy_table(data):
    # Create DataFrame
    df = pd.DataFrame(data)

    # Handle missing IDs and split '_id' into 'Type' and 'Generation'
    # df["_id"] = df["_id"].fillna("Unknown")
    df[["Type", "Generation"]] = df["_id"].str.split("-", expand=True)

    # Normalize the 'Generation' column to lowercase
    df["Generation"] = df["Generation"].str.lower().fillna("unknown")

    # Pivot the data
    pivot_table = df.pivot_table(
        index="Type", columns="Generation", values="count", aggfunc="sum", fill_value=0
    )

    # Ensure the expected columns are present
    for col in ["legacy", "multipurpose", "strict"]:
        if col not in pivot_table.columns:
            pivot_table[col] = 0

    # Reorder the columns
    pivot_table = pivot_table[["legacy", "multipurpose", "strict"]]
    pivot_table = pivot_table.fillna(0).astype(int)

    # Format numbers with commas
    formatted_rows = []
    for idx, row in pivot_table.iterrows():
        formatted = [f"{row[col]:,}" for col in ["legacy", "multipurpose", "strict"]]
        formatted_rows.append(
            f"    {str(idx).capitalize()} & {formatted[0]} & {formatted[1]} & {formatted[2]} \\\\"
        )

    # Generate LaTeX table
    latex_lines = (
        [
            "\\begin{table}",
            "\\small",
            "\\centering",
            "\\begin{tabular}{lrrr}",
            "",
            "\\toprule",
            "\\thead{Type} & \\thead{Legacy} & \\thead{Multipurpose} & \\thead{Strict} \\\\",
            "\\midrule",
            "\\midrule",
        ]
        + formatted_rows
        + [
            "\\bottomrule",
            "\\end{tabular}",
            "\\caption{\\done{Certificate Types and Generations from BR.}}",
            "\\label{tab:br_certificate_types_and_generations}",
            "\\end{table}",
        ]
    )

    # Print for verification
    print("\n".join(latex_lines))


if __name__ == "__main__":
    global SMIME_TOTAL_SINCE_23
    set_up_logging(log_level=logging.INFO)
    numbers = {}
    refresh = sys.argv[1] == "refresh" if len(sys.argv) >= 2 else False
    SMIME_TOTAL_SINCE_23 = count_smime_certificates_br_published(refresh)

    error_counts = sorted(
        get_br_error_count(refresh=refresh), key=lambda x: x["count"], reverse=True
    )
    codes_found = {x["_id"] for x in error_counts}
    print("\nErrors in dataset but not in category:")
    pprint(codes_found.difference(ALL_CODES))

    print("\nErrors in categorization but not in dataset:")
    pprint(ALL_CODES.difference(codes_found))

    categories = get_br_category_counts(refresh=refresh)
    result_non_reserved = get_br_category_counts_no_policy(refresh=refresh)
    print("With reserved")
    numbers["all"] = {}
    for k, v in categories[0].items():
        if k == "_id":
            continue
        print(f"{k}: {v:,} ({v / SMIME_TOTAL_SINCE_23:.2%})")
        numbers["all"][k] = {
            "total": f"{v:,}",
            "pct": f"{v / SMIME_TOTAL_SINCE_23 * 100:.2f}",
        }
    print("-" * 40)
    print("Without reserved")
    numbers["noReserved"] = {}
    for k, v in result_non_reserved[0].items():
        if k == "_id":
            continue
        print(f"{k}: {v:,} ({v / SMIME_TOTAL_SINCE_23:.2%})")
        if k == "Missing Mandatory Info":
            numbers["noReserved"][k] = {
                "total": f"{v:,}",
                "pct": f"{v / SMIME_TOTAL_SINCE_23 * 100:.2f}",
            }
    counts_by_ca = get_br_category_counts_by_ca(refresh=refresh)
    detailed_counts_by_ca = get_br_error_counts_by_ca(refresh=refresh)
    generate_top_10_heatmap(counts_by_ca)
    paper_numbers(numbers, error_counts, refresh)
    # print(create_category_table())
    trust_br = get_trust_by_month(refresh)
    generate_br_histogram(trust_br)
    generate_br_policy_table(get_policy_data(refresh))
# %%

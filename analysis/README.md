# Analysis

This directory contains the scripts used to analyze the collected certificates and generate the results presented in the paper.
The following guide will help you to work out which script to look at for each section of the paper.

## Usage
You can execute the scripts as follows:
```shell
python general_stats.py [refresh]
```
Once a script was executed it will generate a cache file containing the results. If you want to update the results you may use the `refresh` flag for triggering the update.
Warning: Updating the results may take some time.

## Index

### Section 4.2
- Number of certificates: [`general_stats.py`](general_stats.py)
- Number of hosts: [`certs_per_host.py (get_total_certs_and_cert_ids_per_host)`](certs_per_host.py)
- Average hosts per scan: [`crawled_hosts_per_month.py`](crawled_hosts_per_month.py)

### Section 4.3
- Number of certificates by country/continent (Tables 2, 3): [`certs_distribution.py`](certs_distribution.py) 
- Occurrences of certificates on different servers: [`certs_distribution.py (get_hosts_per_certs)`](certs_distribution.py)

### Section 5
- Number of S/MIME certificates: [`general_stats.py (count_smime_certificates)`](general_stats.py)
  - See also [`processing/tasks/is_smime_task.py`](../processing/tasks/is_smime_task.py) for the script that labels certificates as S/MIME.
- Client acceptance (Table 4): [`smime_client_support.py`](smime_client_support.py)

### Section 5.1
- Email addresses & domains, tranco statistics: [`smime_email_addresses.py`](smime_email_addresses.py)
- Time of Issuance and Validity (Figure 3): [`smime_validity.py`](smime_validity.py)
- Key Usage and Extended Key Usage (Table 4): [`key_usage.py`](key_usage.py)
- Key Algorithms (Figure 4): [`smime_key_algorithms.py`](smime_key_algorithms.py)

### Section 5.2
- Certificate Authorities (Figure 5, Table 5): [`smime_cas.py (generate_cdf, generate_table_metrics_for_the_ten_most_common_root_cas, get_issuers_grouped)`](smime_cas.py)

### Section 5.3
- Baseline Requirements (Figure 6): [`smime_br.py`](smime_br.py)

### Section 6.2
- Chain Validation Results (Table 6): [`smime_cas.py (generate_table_chain_validation_results_grouped_by_trust, get_most_common_chain_validation_error_reasons)`](smime_cas.py)

### Section 7
- FastGCD: [`key_analysis/fastgcd_status.py`](key_analysis/fastgcd_status.py)
  - See also [`processing/export_moduli_for_fastgcd.py`](processing/export_moduli_for_fastgcd.py). This script exports the RSA moduli from our certificate database as input for FastGCD ([`https://github.com/sagi/fastgcd`](https://github.com/sagi/fastgcd)).

- FactorDB: [`key_analysis/factordb_status.py`](key_analysis/factordb_status.py)
  - See also [`processing/tasks/factordb_task.py`](processing/tasks/factordb_task.py) for the script that executes the factordb checks.

- Pwnedkeys: [`key_analysis/pwnedkeys_blocklist_merge_status.py`](key_analysis/pwnedkeys_blocklist_merge_status.py)
  - See also [`processing/tasks/pwnedkeys_task.py`](../processing/tasks/pwnedkeys_task.py) for the script that executes the pwnedkeys checks.

- Badkeys (ROCA, fermat, blocklist): [`key_analysis/badkeys.py`](key_analysis/badkeys.py)
  - See also [`processing/tasks/badkeys_task.py`](../processing/tasks/badkeys_task.py) for the script that executes the badkeys checks.

- Invalid ECC keys: [`key_analysis/ec_keys.py`](key_analysis/ec_keys.py)

### Appendix
- S/MIME condition tree (Figure 7): [`smime_tree.py`](smime_tree.py)
- EKUs in non-S/MIME certs (Table 9): [`key_usage.py`](key_usage.py)
- Elliptic Curve Usage (Table 10): [`key_analysis/ec_keys.py`](key_analysis/ec_keys.py)
- BR types and generations (Table 12): [`smime_br.py (generate_br_policy_table)`](smime_br.py)
- BR Errors by CA Heatmap (Figure 8): [`smime_br.py (generate_top_10_heatmap)`](smime_br.py)
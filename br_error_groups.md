## Grouped pkilint checks with severity 'Error'

### Key Usage Issues
- [`cabf.smime.extended_key_usage_extension_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L36)
- [`cabf.smime.unknown_certificate_key_usage_type`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L61)
- [`cabf.smime.key_usage_extension_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L39)
- [`cabf.smime.prohibited_eku_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L50)
- [`cabf.smime.prohibited_ku_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L52)
- [`cabf.smime.emailprotection_eku_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L35)
- [`pkix.ca_certificate_no_ku_extension`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L79)
- [`pkix.ca_certificate_keycertsign_keyusage_not_set`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L78)
- [`pkix.ee_certificate_keycertsign_keyusage_set`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L90)

### Insecure Parameters
- [`cabf.smime.prohibited_spki_algorithm_encoding`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L55)
- [`cabf.smime.is_ca_certificate`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L38)
- [`cabf.rsa_modulus_invalid_length`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L20)
- [`cabf.smime.unsupported_public_key_type`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L62)
- `pkix.certificate_signature_algorithm_mismatch`
- `cabf.smime.certificate_validity_period_exceeds_825_days`
- [`cabf.smime.certificate_validity_period_exceeds_1185_days`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L29)
- [`cabf.rsa_exponent_prohibited_value`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L19)
- [`cabf.smime.prohibited_signature_algorithm_encoding`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L54)

### Missing Mandatory Info
- [`cabf.smime.san_does_not_contain_email_address`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L58)
- `cabf.certificate_extensions_missing`
- [`pkix.subject_email_address_not_in_san`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L118)
- [`cabf.aia_ocsp_has_no_http_uri`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L6)
- [`cabf.smime.certificate_policies_extension_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L28)
- [`pkix.certificate_skid_ca_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L85)
- [`pkix.authority_key_identifier_keyid_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L74)
- [`pkix.authority_key_identifier_extension_absent`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L73)
- [`cabf.smime.missing_required_attribute`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L44)
- [`cabf.smime.no_required_reserved_policy_oid`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L47)
- [`cabf.smime.san_extension_missing`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L59)
- `cabf.smime.required_attribute_missing_for_dependent_attribute`
- [`cabf.aia_ca_issuers_has_no_http_uri`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L5)
- [`cabf.no_http_crldp_uri`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L18)

### Faulty Value
- [`pkix.invalid_domain_name_syntax`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L92)
- `pkix.duplicate_extension`
- [`cabf.invalid_organization_identifier_country`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L12)
- [`pkix.invalid_email_address_syntax`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L93)
- `pkix.rdn_contains_duplicate_attribute_types`
- [`pkix.certificate_version_is_not_v3`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L87)
- [`pkix.invalid_uri_syntax`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L95)
- [`msft.invalid_user_principal_name_syntax`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L68)
- [`cabf.invalid_subject_organization_identifier_encoding`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L13)
- [`pkix.certificate_serial_number_out_of_range`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L83)
- [`pkix.duplicate_certificate_policy_oids`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L89)
- [`pkix.name_domain_components_invalid_domain_name`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L104)
- [`cabf.smime.multiple_reserved_policy_oids`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L46)
- `cabf.cps_uri_is_not_http`
- [`pkix.rfc5280_certificate_policies_invalid_explicit_text_encoding`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L108)
- `pkix.utctime_incorrect_syntax`
- [`cabf.invalid_subject_organization_identifier_format`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L14)
- [`pkix.invalid_time_syntax`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L94)
- `pkix.basic_constraints_has_pathlen_for_non_ca`
- [`iso.lei.invalid_lei_format`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L65)
- [`cabf.smime.org_identifier_and_country_name_attribute_inconsistent`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L48)
- `cabf.invalid_organization_identifier_registration_scheme`
- [`pkix.wrong_time_useful_type`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L124)
- [`itu.bitstring_not_der_encoded`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L66)
- [`pkix.certificate_negative_validity_period`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L81)

### Oversharing
- [`cabf.insignificant_attribute_value_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L9)
- [`pkix.issuer_unique_id_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L99)
- [`cabf.authority_key_identifier_has_issuer_cert`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L7)

### Prohibited Value
- [`cabf.smime.mixed_name_and_pseudonym_attributes`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L45)
- [`cabf.smime.prohibited_othername_type_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L53)
- [`cabf.smime.prohibited_generalname_type_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L51)
- [`cabf.smime.email_address_in_attribute_not_in_san`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L34)
- `cabf.smime.prohibited_organization_identifier_reference_present_for_scheme`
- `pkix.prohibited_qualified_statement_present`
- `cabf.internal_ip_address`
- [`cabf.smime.usernotice_has_noticeref`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L63)
- [`cabf.smime.prohibited_attribute`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L49)
- [`cabf.smime.anypolicy_present`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L27)
- [`cabf.smime.crldp_fullname_prohibited_generalname_type`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L32)
- [`cabf.smime.crldp_fullname_prohibited_uri_scheme`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L33)
- [`cabf.smime.subject_directory_attributes_extension_prohibited`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L60)
- [`cabf.internal_domain_name`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L10)

### Unknown Value
- [`cabf.invalid_country_code`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L11)
- [`cabf.smime.common_name_value_unknown_source`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L30)
- [`itu.invalid_printablestring_character`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L67)

### Wrong Criticality
- [`pkix.authority_key_identifier_critical`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L72)
- `pkix.basic_constraints_extension_not_critical`
- [`pkix.certificate_name_constraints_extension_not_critical`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L80)
- [`cabf.smime.qc_statements_extension_critical`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L56)
- [`pkix.certificate_skid_extension_critical`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L86)
- `cabf.critical_crldp_extension`
- [`pkix.authority_information_access_extension_critical`](https://github.com/digicert/pkilint/blob/5b9b884a6dd7f4fdb31996bcf77cb2a648d0fa6e/pkilint/cabf/smime/finding_metadata.csv#L71)


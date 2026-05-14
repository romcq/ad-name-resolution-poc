# AD-like Name Resolution Prototype

This prototype demonstrates AD-like name resolution for an ITDR-style workflow. The input is an already parsed LDAP or Kerberos event. The resolver detects the name format, searches a local AD snapshot, and returns the matched object or a clear failure reason.

The project does not connect to a real AD, does not perform LDAP Bind or Kerberos exchange, and does not parse pcap. It checks the name-resolution algorithm itself.

## Structure

- `run.py` - CLI entry point.
- `ad_snapshot.json` - single local AD snapshot used by manual mode and all tests.
- `tests.json` - test cases based on the article tables and algorithm sections.
- `ad_name_resolution/resolver.py` - top-level LDAP/Kerberos router.
- `ad_name_resolution/ldap_resolver.py` - LDAP Simple Authentication order.
- `ad_name_resolution/kerberos_resolver.py` - Kerberos Client Principal Lookup and Server Principal Lookup.
- `ad_name_resolution/repository.py` - lookup helpers over the local snapshot.
- `ad_name_resolution/cli.py` - manual mode, menus, result printing.
- `ad_name_resolution/test_runner.py` - JSON test runner.

## LDAP Flow

LDAP uses `LDAPMessage -> protocolOp: bindRequest -> bindRequest -> name`.

Lookup order:

1. `distinguishedName`
2. `userPrincipalName` / generated UPN
3. `DOMAIN\sAMAccountName`
4. `canonicalName`
5. `objectGUID`
6. `displayName`
7. `servicePrincipalName`
8. `MapSPN`
9. `objectSid`
10. `sIDHistory`
11. `canonicalName` with the last `/` replaced by `\n`

Generated UPN is checked after explicit `userPrincipalName`. First the resolver tries the exact `userPrincipalName`; if it is not found, `name@domain` can resolve as `sAMAccountName=name` and `domainFQDN=domain`.

## Kerberos Flow

Kerberos input is an already parsed principal: `message_type`, `cname` or `sname`, `name_type`, `name_string[]`, and `realm`.

Branch selection:

```text
AS-REQ  -> cname -> Client Principal Lookup
TGS-REQ -> sname -> Server Principal Lookup
```

Supported `name_type` values in the prototype: `1` (`KRB5-NT-PRINCIPAL`), `2` (`KRB5-NT-SRV-INST`), `3` (`KRB5-NT-SRV-HST`), `10` (`KRB5-NT-ENTERPRISE-PRINCIPAL`).

`realm` stays an explicit input field, as it is in Kerberos traffic. The CLI may suggest a default, but the resolver receives `realm` as a separate field.

## Snapshot Objects

All tests use the same `ad_snapshot.json`. Corner cases use dedicated users, so they do not change the base `userA` / `userB` checks.

| id | Type | Domain | sAMAccountName | Key fields | Why it exists |
|---|---|---|---|---|---|
| userA | user | pastukhov.lab | userA | UPN=userA@pastukhov.lab; SPN=HTTP/userA; sIDHistory=S-1-5-21-2845156888-2425353457-3474467337-5114; displayName=User A | Base user in pastukhov.lab for LDAP and Kerberos format checks. |
| userB | user | domain3.lab | userB | UPN=userB@domain3.lab; SPN=HTTP/userB; sIDHistory=S-1-5-21-3677553567-317466416-2570716728-5106; displayName=UserB | Base user in domain3.lab for second-domain checks. |
| dc01 | computer | pastukhov.lab | 10-23-RP-DC-01$ | SPN=cifs/10-23-RP-DC-01.pastukhov.lab, HOST/10-23-RP-DC-01.pastukhov.lab; displayName=10-23-RP-DC-01 | Computer/service object for SPN and Kerberos TGS-REQ checks. |
| krbtgt | service | pastukhov.lab | krbtgt | - | Service object for the krbtgt special case. |
| userImplicit | user | pastukhov.lab | userImplicit | - | Generated UPN case: userPrincipalName is empty. |
| userUpnSet | user | pastukhov.lab | userUpnSet | UPN=userUpnSetX@pastukhov.lab | Explicit UPN differs from generated UPN. |
| userImplicitOwner | user | pastukhov.lab | userImplicitOwner | - | Owns the generated UPN that is shadowed by another explicit UPN. |
| userConflict | user | pastukhov.lab | userConflict | UPN=userImplicitOwner@pastukhov.lab | Explicit UPN equals userImplicitOwner generated UPN and must win. |
| userTrustPastukhov | user | pastukhov.lab | userTrust | UPN=userTrust@pastukhov.lab | Same UPN exists in two domains; pastukhov.lab local object. |
| userTrustDomain3 | user | domain3.lab | userTrust | UPN=userTrust@pastukhov.lab | Same UPN exists in two domains; domain3.lab local object. |
| dnEscapedComma | user | pastukhov.lab | dnEscapedComma | UPN=dnEscapedComma@pastukhov.lab | DN escaped comma case. |
| dnEscapedPlus | user | pastukhov.lab | dnEscapedPlus | UPN=dnEscapedPlus@pastukhov.lab | DN escaped plus case. |
| dnEscapedQuote | user | pastukhov.lab | dnEscapedQuote | UPN=dnEscapedQuote@pastukhov.lab | DN escaped quote case. |
| dnEscapedBackslash | user | pastukhov.lab | dnEscapedBackslash | UPN=dnEscapedBackslash@pastukhov.lab | DN escaped backslash case. |
| dnEscapedAngle | user | pastukhov.lab | dnEscapedAngle | UPN=dnEscapedAngle@pastukhov.lab | DN escaped angle brackets case. |
| dnEscapedSemicolon | user | pastukhov.lab | dnEscapedSemicolon | UPN=dnEscapedSemicolon@pastukhov.lab | DN escaped semicolon case. |
| dnEscapedEquals | user | pastukhov.lab | dnEscapedEquals | UPN=dnEscapedEquals@pastukhov.lab | DN escaped equals sign case. |
| dnSlash | user | pastukhov.lab | dnSlash | UPN=dnSlash@pastukhov.lab | DN slash case. |
| dnEscapedHash | user | pastukhov.lab | dnEscapedHash | UPN=dnEscapedHash@pastukhov.lab | DN leading hash case. |
| cornerSamTarget | user | pastukhov.lab | cornerSamTarget | UPN=cornerSamTarget@pastukhov.lab; displayName=Corner SAM Target | Target object for displayName = sAMAccountName priority check. |
| cornerUpnTarget | user | pastukhov.lab | cornerUpnTarget | UPN=cornerUpnTarget@pastukhov.lab | Target object for displayName = userPrincipalName priority check. |
| cornerDownlevelTarget | user | pastukhov.lab | cornerDownlevelTarget | UPN=cornerDownlevelTarget@pastukhov.lab | Target object for displayName = down-level name priority check. |
| cornerDnTarget | user | pastukhov.lab | cornerDnTarget | UPN=cornerDnTarget@pastukhov.lab | Target object for displayName = distinguishedName priority check. |
| cornerCanonicalTarget | user | pastukhov.lab | cornerCanonicalTarget | UPN=cornerCanonicalTarget@pastukhov.lab | Target object for displayName = canonicalName priority check. |
| cornerGuidTarget | user | pastukhov.lab | cornerGuidTarget | UPN=cornerGuidTarget@pastukhov.lab | Target object for displayName = objectGUID priority check. |
| cornerSpnTarget | user | pastukhov.lab | cornerSpnTarget | UPN=cornerSpnTarget@pastukhov.lab; SPN=HTTP/cornerSpnTarget | Target object for displayName = servicePrincipalName priority check. |
| cornerSidTarget | user | pastukhov.lab | cornerSidTarget | UPN=cornerSidTarget@pastukhov.lab | Target object for displayName = objectSid priority check. |
| userDisplaySam | user | pastukhov.lab | userDisplaySam | UPN=userDisplaySam@pastukhov.lab; displayName=cornerSamTarget | displayName intentionally equals cornerSamTarget sAMAccountName. |
| userDisplayUpn | user | pastukhov.lab | userDisplayUpn | UPN=userDisplayUpn@pastukhov.lab; displayName=cornerUpnTarget@pastukhov.lab | displayName intentionally equals cornerUpnTarget UPN. |
| userDisplayNetbios | user | pastukhov.lab | userDisplayNetbios | UPN=userDisplayNetbios@pastukhov.lab; displayName=PASTUKHOV\cornerDownlevelTarget | displayName intentionally equals cornerDownlevelTarget down-level name. |
| userDisplayDn | user | pastukhov.lab | userDisplayDn | UPN=userDisplayDn@pastukhov.lab; displayName=CN=cornerDnTarget,CN=Users,DC=pastukhov,DC=lab | displayName intentionally equals cornerDnTarget DN. |
| userDisplayCanonical | user | pastukhov.lab | userDisplayCanonical | UPN=userDisplayCanonical@pastukhov.lab; displayName=pastukhov.lab/Users/cornerCanonicalTarget | displayName intentionally equals cornerCanonicalTarget canonicalName. |
| userDisplayGuid | user | pastukhov.lab | userDisplayGuid | UPN=userDisplayGuid@pastukhov.lab; displayName={cccccccc-0000-0000-0000-000000000066} | displayName intentionally equals cornerGuidTarget GUID. |
| userDisplaySpn | user | pastukhov.lab | userDisplaySpn | UPN=userDisplaySpn@pastukhov.lab; displayName=HTTP/cornerSpnTarget | displayName intentionally equals cornerSpnTarget SPN. |
| userDisplaySid | user | pastukhov.lab | userDisplaySid | UPN=userDisplaySid@pastukhov.lab; displayName=S-1-5-21-2845156888-2425353457-3474467337-1668 | displayName intentionally equals cornerSidTarget SID. |
| userSameDisplayOne | user | pastukhov.lab | userSameDisplayOne | UPN=userSameDisplayOne@pastukhov.lab; displayName=Same Display | First object with duplicated displayName. |
| userSameDisplayTwo | user | pastukhov.lab | userSameDisplayTwo | UPN=userSameDisplayTwo@pastukhov.lab; displayName=Same Display | Second object with duplicated displayName. |

## Test Cases

Case descriptions are written as: input event => expected detected format/object. OS-version columns from the article are intentionally not copied; the prototype checks name format, algorithm branch, and matched object.

| id | Category | Description |
|---|---|---|
| ldap_sam_userA_not_accepted | ldap_table | LDAP: userA => displayName -> object_not_found |
| ldap_upn_userA | ldap_table | LDAP: userA@pastukhov.lab => userPrincipalName -> userA |
| ldap_upn_userB | ldap_table | LDAP: userB@domain3.lab => userPrincipalName -> userB |
| ldap_downlevel_userA | ldap_table | LDAP: PASTUKHOV\userA => downLevelLogonName -> userA |
| ldap_downlevel_userB | ldap_table | LDAP: DOMAIN3\userB => downLevelLogonName -> userB |
| ldap_dn_userA | ldap_table | LDAP: CN=userA,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> userA |
| ldap_dn_userB | ldap_table | LDAP: CN=userB,CN=Users,DC=domain3,DC=lab => distinguishedName -> userB |
| ldap_canonical_userA | ldap_table | LDAP: pastukhov.lab/Users/userA => canonicalName -> userA |
| ldap_canonical_userB | ldap_table | LDAP: domain3.lab/Users/userB => canonicalName -> userB |
| ldap_display_userA | ldap_table | LDAP: User A => displayName -> userA |
| ldap_display_userB | ldap_table | LDAP: UserB => displayName -> userB |
| ldap_guid_userA | ldap_table | LDAP: {5c69b042-e0e9-475a-ae37-1751ef9e05e7} => objectGUID -> userA |
| ldap_guid_userB | ldap_table | LDAP: {36eba909-f454-4695-918b-dcdf33b7cd88} => objectGUID -> userB |
| ldap_spn_userA | ldap_table | LDAP: HTTP/userA => servicePrincipalName -> userA |
| ldap_spn_userB | ldap_table | LDAP: HTTP/userB => servicePrincipalName -> userB |
| ldap_object_sid_userA | ldap_table | LDAP: S-1-5-21-2845156888-2425353457-3474467337-1114 => objectSid -> userA |
| ldap_object_sid_userB | ldap_table | LDAP: S-1-5-21-3677553567-317466416-2570716728-1106 => objectSid -> userB |
| ldap_mapspn_userA | ldap_table | LDAP: HOST/userA => MapSPN -> userA |
| ldap_mapspn_userB | ldap_table | LDAP: HOST/userB => MapSPN -> userB |
| ldap_sid_history_userA | ldap_algorithm | LDAP: S-1-5-21-2845156888-2425353457-3474467337-5114 => sIDHistory -> userA |
| ldap_canonical_lf_userA | ldap_algorithm | LDAP: pastukhov.lab/Users\nuserA => canonicalNameWithLF -> userA |
| ldap_dnEscapedComma | ldap_dn_special | LDAP: CN=user\,A,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedComma |
| ldap_dnEscapedPlus | ldap_dn_special | LDAP: CN=user\+A,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedPlus |
| ldap_dnEscapedQuote | ldap_dn_special | LDAP: CN=user\"A\",CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedQuote |
| ldap_dnEscapedBackslash | ldap_dn_special | LDAP: CN=user\\A,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedBackslash |
| ldap_dnEscapedAngle | ldap_dn_special | LDAP: CN=user\<A\>,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedAngle |
| ldap_dnEscapedSemicolon | ldap_dn_special | LDAP: CN=user\;A,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedSemicolon |
| ldap_dnEscapedEquals | ldap_dn_special | LDAP: CN=user\=A,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedEquals |
| ldap_dnSlash | ldap_dn_special | LDAP: CN=user/A,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnSlash |
| ldap_dnEscapedHash | ldap_dn_special | LDAP: CN=\#userA,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> dnEscapedHash |
| ldap_generated_upn | ldap_corner | LDAP: userImplicit@pastukhov.lab => generatedUPN -> userImplicit |
| ldap_implicit_upn_still_resolves_when_explicit_set | ldap_corner | LDAP: userUpnSet@pastukhov.lab => generatedUPN -> userUpnSet |
| ldap_explicit_changed_upn | ldap_corner | LDAP: userUpnSetX@pastukhov.lab => userPrincipalName -> userUpnSet |
| ldap_explicit_upn_wins | ldap_corner | LDAP: userImplicitOwner@pastukhov.lab => userPrincipalName -> userConflict |
| ldap_trust_local_pastukhov_wins | ldap_corner | LDAP: userTrust@pastukhov.lab => userPrincipalName -> userTrustPastukhov |
| ldap_trust_local_domain3_wins | ldap_corner | LDAP: userTrust@pastukhov.lab => userPrincipalName -> userTrustDomain3 |
| ldap_duplicate_display_name | ldap_corner | LDAP: Same Display => displayName -> not_unique |
| ldap_display_equals_sam | ldap_corner | LDAP: cornerSamTarget => displayName -> userDisplaySam |
| ldap_display_equals_upn | ldap_corner | LDAP: cornerUpnTarget@pastukhov.lab => userPrincipalName -> cornerUpnTarget |
| ldap_display_equals_downlevel | ldap_corner | LDAP: PASTUKHOV\cornerDownlevelTarget => downLevelLogonName -> cornerDownlevelTarget |
| ldap_display_equals_dn | ldap_corner | LDAP: CN=cornerDnTarget,CN=Users,DC=pastukhov,DC=lab => distinguishedName -> cornerDnTarget |
| ldap_display_equals_canonical | ldap_corner | LDAP: pastukhov.lab/Users/cornerCanonicalTarget => canonicalName -> cornerCanonicalTarget |
| ldap_display_equals_guid | ldap_corner | LDAP: {cccccccc-0000-0000-0000-000000000066} => objectGUID -> cornerGuidTarget |
| ldap_display_equals_spn | ldap_corner | LDAP: HTTP/cornerSpnTarget => displayName -> userDisplaySpn |
| ldap_display_equals_sid | ldap_corner | LDAP: S-1-5-21-2845156888-2425353457-3474467337-1668 => displayName -> userDisplaySid |
| krb_as_enterprise_upn_userA | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[userA@pastukhov.lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE/userPrincipalName -> userA |
| krb_as_enterprise_upn_userB | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[userB@domain3.lab] realm=DOMAIN3.LAB => NT-ENTERPRISE/userPrincipalName -> userB |
| krb_as_enterprise_generated_upn | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[userImplicit@pastukhov.lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE/generatedUPN -> userImplicit |
| krb_as_enterprise_implicit_upn_with_explicit_set | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[userUpnSet@pastukhov.lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE/generatedUPN -> userUpnSet |
| krb_as_enterprise_explicit_changed_upn | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[userUpnSetX@pastukhov.lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE/userPrincipalName -> userUpnSet |
| krb_as_enterprise_explicit_wins | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[userImplicitOwner@pastukhov.lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE/userPrincipalName -> userConflict |
| krb_as_principal_sam_userA | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=1 name=[userA] realm=PASTUKHOV.LAB => NT-PRINCIPAL/sAMAccountName -> userA |
| krb_as_principal_sam_userB | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=1 name=[userB] realm=DOMAIN3.LAB => NT-PRINCIPAL/sAMAccountName -> userB |
| krb_as_principal_sam_dollar | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=1 name=[10-23-RP-DC-01] realm=PASTUKHOV.LAB => NT-PRINCIPAL/sAMAccountName+$ -> dc01 |
| krb_as_principal_upn_fallback | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=1 name=[userUpnSetX] realm=PASTUKHOV.LAB => NT-PRINCIPAL/userPrincipalName -> userUpnSet |
| krb_as_dn_not_accepted | kerberos_client_lookup | Kerberos AS-REQ client lookup: AS-REQ cname type=10 name=[CN=userA,CN=Users,DC=pastukhov,DC=lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE -> object_not_found |
| krb_tgs_srv_inst_userprincipalname_not_found | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=2 name=[cifs,10-23-RP-DC-01.pastukhov.lab] realm=PASTUKHOV.LAB => NT-SRV-INST/userPrincipalName -> object_not_found |
| krb_tgs_krbtgt_special_case | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=2 name=[krbtgt,krbtgt] realm=PASTUKHOV.LAB => NT-SRV-INST/krbtgt/sAMAccountName -> krbtgt |
| krb_tgs_srv_inst_sam_dollar | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=2 name=[10-23-RP-DC-01] realm=PASTUKHOV.LAB => NT-SRV-INST/sAMAccountName+$ -> dc01 |
| krb_tgs_enterprise_spn_dc | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=10 name=[cifs/10-23-RP-DC-01.pastukhov.lab] realm=PASTUKHOV.LAB => NT-ENTERPRISE/servicePrincipalName -> dc01 |
| krb_tgs_enterprise_spn_userA | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=10 name=[HTTP/userA] realm=PASTUKHOV.LAB => NT-ENTERPRISE/servicePrincipalName -> userA |
| krb_tgs_enterprise_sam_with_spn | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=10 name=[userA] realm=PASTUKHOV.LAB => NT-ENTERPRISE/sAMAccountName -> userA |
| krb_tgs_enterprise_fallback_without_spn_fails | kerberos_server_lookup | Kerberos TGS-REQ server lookup: TGS-REQ sname type=10 name=[userUpnSet] realm=PASTUKHOV.LAB => NT-ENTERPRISE/sAMAccountName -> object_not_found |

## Run

Interactive mode:

```powershell
python run.py
```

Run all tests:

```powershell
python run.py --run-all
```

List tests:

```powershell
python run.py --list-tests
```

Run one category:

```powershell
python run.py --run-category ldap_corner
```

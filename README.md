# Прототип AD-like Name Resolution

Прототип показывает, как ITDR-подобный продукт может разобрать имя из уже выделенного LDAP/Kerberos события, определить формат имени, найти объект в локальном снимке AD и вернуть результат проверки.

Проект не подключается к реальному AD, не выполняет LDAP Bind, не делает Kerberos-обмен и не парсит pcap. Здесь проверяется только логика разбора имени и сопоставления с объектами из локальной базы.

## Состав проекта

- `run.py` - точка запуска CLI.
- `ad_snapshot.json` - единая локальная база AD-объектов для ручного режима и тестов.
- `tests.json` - тестовые кейсы по таблицам и алгоритмам статьи.
- `ad_name_resolution/resolver.py` - общий роутер LDAP/Kerberos.
- `ad_name_resolution/ldap_resolver.py` - порядок проверок LDAP Simple Authentication.
- `ad_name_resolution/kerberos_resolver.py` - Kerberos Client Principal Lookup и Server Principal Lookup.
- `ad_name_resolution/repository.py` - функции поиска по локальному снимку AD.
- `ad_name_resolution/cli.py` - ручной режим, меню и вывод результата.
- `ad_name_resolution/test_runner.py` - запуск тестов из JSON.

## Как идет LDAP-проверка

Для LDAP используется поле `LDAPMessage -> protocolOp: bindRequest -> bindRequest -> name`.

Порядок проверки:

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
11. `canonicalName` с заменой последнего `/` на `\n`

Generated UPN проверяется после явного `userPrincipalName`. Сначала ищется точное значение `userPrincipalName`; если оно не найдено, строка вида `name@domain` может быть сопоставлена как `sAMAccountName=name` и `domainFQDN=domain`.

## Как идет Kerberos-проверка

Для Kerberos на вход подается уже разобранный principal из трафика: `message_type`, `cname` или `sname`, `name_type`, `name_string[]` и `realm`.

Выбор ветки:

```text
AS-REQ  -> cname -> Client Principal Lookup
TGS-REQ -> sname -> Server Principal Lookup
```

Поддержанные в прототипе `name_type`:

- `1` - `KRB5-NT-PRINCIPAL`
- `2` - `KRB5-NT-SRV-INST`
- `3` - `KRB5-NT-SRV-HST`
- `10` - `KRB5-NT-ENTERPRISE-PRINCIPAL`

`realm` оставлен отдельным полем, как в реальном Kerberos-трафике. CLI может подсказать значение по имени, но в сам resolver `realm` передается отдельно.

## Объекты в базе

Все тесты используют одну базу `ad_snapshot.json`. Для корнеров добавлены отдельные объекты, чтобы не менять базовые проверки `userA` и `userB`.

| id | Тип | Домен | sAMAccountName | Ключевые поля | Зачем нужен |
|---|---|---|---|---|---|
| userA | пользователь | pastukhov.lab | userA | UPN=userA@pastukhov.lab; SPN=HTTP/userA; sIDHistory=S-1-5-21-2845156888-2425353457-3474467337-5114; displayName=User A | Базовый пользователь домена pastukhov.lab для проверок LDAP и Kerberos. |
| userB | пользователь | domain3.lab | userB | UPN=userB@domain3.lab; SPN=HTTP/userB; sIDHistory=S-1-5-21-3677553567-317466416-2570716728-5106; displayName=UserB | Базовый пользователь домена domain3.lab для проверок второго домена. |
| dc01 | компьютер | pastukhov.lab | 10-23-RP-DC-01$ | SPN=cifs/10-23-RP-DC-01.pastukhov.lab, HOST/10-23-RP-DC-01.pastukhov.lab; displayName=10-23-RP-DC-01 | Компьютерный/сервисный объект для SPN и Kerberos TGS-REQ. |
| krbtgt | сервис | pastukhov.lab | krbtgt | - | Сервисный объект для отдельного случая krbtgt. |
| userImplicit | пользователь | pastukhov.lab | userImplicit | - | Проверка generated UPN: userPrincipalName не задан, но sAMAccountName@domainFQDN должен находиться. |
| userUpnSet | пользователь | pastukhov.lab | userUpnSet | UPN=userUpnSetX@pastukhov.lab | Проверка отличия явного UPN от generated UPN. |
| userImplicitOwner | пользователь | pastukhov.lab | userImplicitOwner | - | Объект, у которого generated UPN пересекается с явным UPN другого объекта. |
| userConflict | пользователь | pastukhov.lab | userConflict | UPN=userImplicitOwner@pastukhov.lab | Объект с явным UPN, который должен иметь приоритет над generated UPN другого объекта. |
| userTrustPastukhov | пользователь | pastukhov.lab | userTrust | UPN=userTrust@pastukhov.lab | Проверка одинакового UPN-like значения в разных доменных контекстах: объект pastukhov.lab. |
| userTrustDomain3 | пользователь | domain3.lab | userTrust | UPN=userTrust@pastukhov.lab | Проверка одинакового UPN-like значения в разных доменных контекстах: объект domain3.lab. |
| dnEscapedComma | пользователь | pastukhov.lab | dnEscapedComma | UPN=dnEscapedComma@pastukhov.lab | DN со спецсимволом запятая. |
| dnEscapedPlus | пользователь | pastukhov.lab | dnEscapedPlus | UPN=dnEscapedPlus@pastukhov.lab | DN со спецсимволом плюс. |
| dnEscapedQuote | пользователь | pastukhov.lab | dnEscapedQuote | UPN=dnEscapedQuote@pastukhov.lab | DN с кавычками. |
| dnEscapedBackslash | пользователь | pastukhov.lab | dnEscapedBackslash | UPN=dnEscapedBackslash@pastukhov.lab | DN с обратным слешем. |
| dnEscapedAngle | пользователь | pastukhov.lab | dnEscapedAngle | UPN=dnEscapedAngle@pastukhov.lab | DN с угловыми скобками. |
| dnEscapedSemicolon | пользователь | pastukhov.lab | dnEscapedSemicolon | UPN=dnEscapedSemicolon@pastukhov.lab | DN с точкой с запятой. |
| dnEscapedEquals | пользователь | pastukhov.lab | dnEscapedEquals | UPN=dnEscapedEquals@pastukhov.lab | DN со знаком равно. |
| dnSlash | пользователь | pastukhov.lab | dnSlash | UPN=dnSlash@pastukhov.lab | DN со слешем. |
| dnEscapedHash | пользователь | pastukhov.lab | dnEscapedHash | UPN=dnEscapedHash@pastukhov.lab | DN с экранированным # в начале CN. |
| cornerSamTarget | пользователь | pastukhov.lab | cornerSamTarget | UPN=cornerSamTarget@pastukhov.lab; displayName=Corner SAM Target | Целевой объект для проверки, что sAMAccountName/UPN-подобные форматы проверяются раньше displayName. |
| cornerUpnTarget | пользователь | pastukhov.lab | cornerUpnTarget | UPN=cornerUpnTarget@pastukhov.lab | Целевой объект для проверки приоритета userPrincipalName над displayName. |
| cornerDownlevelTarget | пользователь | pastukhov.lab | cornerDownlevelTarget | UPN=cornerDownlevelTarget@pastukhov.lab | Целевой объект для проверки приоритета DOMAIN\user над displayName. |
| cornerDnTarget | пользователь | pastukhov.lab | cornerDnTarget | UPN=cornerDnTarget@pastukhov.lab | Целевой объект для проверки приоритета distinguishedName над displayName. |
| cornerCanonicalTarget | пользователь | pastukhov.lab | cornerCanonicalTarget | UPN=cornerCanonicalTarget@pastukhov.lab | Целевой объект для проверки приоритета canonicalName над displayName. |
| cornerGuidTarget | пользователь | pastukhov.lab | cornerGuidTarget | UPN=cornerGuidTarget@pastukhov.lab | Целевой объект для проверки приоритета objectGUID над displayName. |
| cornerSpnTarget | пользователь | pastukhov.lab | cornerSpnTarget | UPN=cornerSpnTarget@pastukhov.lab; SPN=HTTP/cornerSpnTarget | Целевой объект для проверки пересечения SPN/displayName. |
| cornerSidTarget | пользователь | pastukhov.lab | cornerSidTarget | UPN=cornerSidTarget@pastukhov.lab | Целевой объект для проверки пересечения objectSid/displayName. |
| userDisplaySam | пользователь | pastukhov.lab | userDisplaySam | UPN=userDisplaySam@pastukhov.lab; displayName=cornerSamTarget | displayName намеренно совпадает с sAMAccountName другого объекта. |
| userDisplayUpn | пользователь | pastukhov.lab | userDisplayUpn | UPN=userDisplayUpn@pastukhov.lab; displayName=cornerUpnTarget@pastukhov.lab | displayName намеренно совпадает с UPN другого объекта. |
| userDisplayNetbios | пользователь | pastukhov.lab | userDisplayNetbios | UPN=userDisplayNetbios@pastukhov.lab; displayName=PASTUKHOV\cornerDownlevelTarget | displayName намеренно совпадает с down-level именем другого объекта. |
| userDisplayDn | пользователь | pastukhov.lab | userDisplayDn | UPN=userDisplayDn@pastukhov.lab; displayName=CN=cornerDnTarget,CN=Users,DC=pastukhov,DC=lab | displayName намеренно совпадает с DN другого объекта. |
| userDisplayCanonical | пользователь | pastukhov.lab | userDisplayCanonical | UPN=userDisplayCanonical@pastukhov.lab; displayName=pastukhov.lab/Users/cornerCanonicalTarget | displayName намеренно совпадает с canonicalName другого объекта. |
| userDisplayGuid | пользователь | pastukhov.lab | userDisplayGuid | UPN=userDisplayGuid@pastukhov.lab; displayName={cccccccc-0000-0000-0000-000000000066} | displayName намеренно совпадает с GUID другого объекта. |
| userDisplaySpn | пользователь | pastukhov.lab | userDisplaySpn | UPN=userDisplaySpn@pastukhov.lab; displayName=HTTP/cornerSpnTarget | displayName намеренно совпадает с SPN другого объекта. |
| userDisplaySid | пользователь | pastukhov.lab | userDisplaySid | UPN=userDisplaySid@pastukhov.lab; displayName=S-1-5-21-2845156888-2425353457-3474467337-1668 | displayName намеренно совпадает с SID другого объекта. |
| userSameDisplayOne | пользователь | pastukhov.lab | userSameDisplayOne | UPN=userSameDisplayOne@pastukhov.lab; displayName=Same Display | Первый объект с одинаковым displayName. |
| userSameDisplayTwo | пользователь | pastukhov.lab | userSameDisplayTwo | UPN=userSameDisplayTwo@pastukhov.lab; displayName=Same Display | Второй объект с таким же displayName для проверки not_unique. |

## Тестовые кейсы

Описания кейсов читаются так: какое событие подается на вход -> какой формат должен быть определен -> какой объект или причина ожидается. Колонки про версии Windows из статьи сюда не переносятся: прототип проверяет формат имени, ветку алгоритма и найденный объект.

| id | Раздел | Что проверяется |
|---|---|---|
| ldap_sam_userA_not_accepted | LDAP: форматы из таблицы | LDAP: вход "userA" -> ожидаемый формат: displayName -> результат: object_not_found |
| ldap_upn_userA | LDAP: форматы из таблицы | LDAP: вход "userA@pastukhov.lab" -> ожидаемый формат: userPrincipalName -> результат: userA |
| ldap_upn_userB | LDAP: форматы из таблицы | LDAP: вход "userB@domain3.lab" -> ожидаемый формат: userPrincipalName -> результат: userB |
| ldap_downlevel_userA | LDAP: форматы из таблицы | LDAP: вход "PASTUKHOV\userA" -> ожидаемый формат: downLevelLogonName -> результат: userA |
| ldap_downlevel_userB | LDAP: форматы из таблицы | LDAP: вход "DOMAIN3\userB" -> ожидаемый формат: downLevelLogonName -> результат: userB |
| ldap_dn_userA | LDAP: форматы из таблицы | LDAP: вход "CN=userA,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: userA |
| ldap_dn_userB | LDAP: форматы из таблицы | LDAP: вход "CN=userB,CN=Users,DC=domain3,DC=lab" -> ожидаемый формат: distinguishedName -> результат: userB |
| ldap_canonical_userA | LDAP: форматы из таблицы | LDAP: вход "pastukhov.lab/Users/userA" -> ожидаемый формат: canonicalName -> результат: userA |
| ldap_canonical_userB | LDAP: форматы из таблицы | LDAP: вход "domain3.lab/Users/userB" -> ожидаемый формат: canonicalName -> результат: userB |
| ldap_display_userA | LDAP: форматы из таблицы | LDAP: вход "User A" -> ожидаемый формат: displayName -> результат: userA |
| ldap_display_userB | LDAP: форматы из таблицы | LDAP: вход "UserB" -> ожидаемый формат: displayName -> результат: userB |
| ldap_guid_userA | LDAP: форматы из таблицы | LDAP: вход "{5c69b042-e0e9-475a-ae37-1751ef9e05e7}" -> ожидаемый формат: objectGUID -> результат: userA |
| ldap_guid_userB | LDAP: форматы из таблицы | LDAP: вход "{36eba909-f454-4695-918b-dcdf33b7cd88}" -> ожидаемый формат: objectGUID -> результат: userB |
| ldap_spn_userA | LDAP: форматы из таблицы | LDAP: вход "HTTP/userA" -> ожидаемый формат: servicePrincipalName -> результат: userA |
| ldap_spn_userB | LDAP: форматы из таблицы | LDAP: вход "HTTP/userB" -> ожидаемый формат: servicePrincipalName -> результат: userB |
| ldap_object_sid_userA | LDAP: форматы из таблицы | LDAP: вход "S-1-5-21-2845156888-2425353457-3474467337-1114" -> ожидаемый формат: objectSid -> результат: userA |
| ldap_object_sid_userB | LDAP: форматы из таблицы | LDAP: вход "S-1-5-21-3677553567-317466416-2570716728-1106" -> ожидаемый формат: objectSid -> результат: userB |
| ldap_mapspn_userA | LDAP: форматы из таблицы | LDAP: вход "HOST/userA" -> ожидаемый формат: MapSPN -> результат: userA |
| ldap_mapspn_userB | LDAP: форматы из таблицы | LDAP: вход "HOST/userB" -> ожидаемый формат: MapSPN -> результат: userB |
| ldap_sid_history_userA | LDAP: дополнительные шаги алгоритма | LDAP: вход "S-1-5-21-2845156888-2425353457-3474467337-5114" -> ожидаемый формат: sIDHistory -> результат: userA |
| ldap_canonical_lf_userA | LDAP: дополнительные шаги алгоритма | LDAP: вход "pastukhov.lab/Users\nuserA" -> ожидаемый формат: canonicalNameWithLF -> результат: userA |
| ldap_dnEscapedComma | LDAP: спецсимволы в DN | LDAP: вход "CN=user\,A,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedComma |
| ldap_dnEscapedPlus | LDAP: спецсимволы в DN | LDAP: вход "CN=user\+A,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedPlus |
| ldap_dnEscapedQuote | LDAP: спецсимволы в DN | LDAP: вход "CN=user\"A\",CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedQuote |
| ldap_dnEscapedBackslash | LDAP: спецсимволы в DN | LDAP: вход "CN=user\\A,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedBackslash |
| ldap_dnEscapedAngle | LDAP: спецсимволы в DN | LDAP: вход "CN=user\<A\>,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedAngle |
| ldap_dnEscapedSemicolon | LDAP: спецсимволы в DN | LDAP: вход "CN=user\;A,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedSemicolon |
| ldap_dnEscapedEquals | LDAP: спецсимволы в DN | LDAP: вход "CN=user\=A,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedEquals |
| ldap_dnSlash | LDAP: спецсимволы в DN | LDAP: вход "CN=user/A,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnSlash |
| ldap_dnEscapedHash | LDAP: спецсимволы в DN | LDAP: вход "CN=\#userA,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: dnEscapedHash |
| ldap_generated_upn | LDAP: пересечения полей и приоритеты | LDAP: вход "userImplicit@pastukhov.lab" -> ожидаемый формат: generatedUPN -> результат: userImplicit |
| ldap_implicit_upn_still_resolves_when_explicit_set | LDAP: пересечения полей и приоритеты | LDAP: вход "userUpnSet@pastukhov.lab" -> ожидаемый формат: generatedUPN -> результат: userUpnSet |
| ldap_explicit_changed_upn | LDAP: пересечения полей и приоритеты | LDAP: вход "userUpnSetX@pastukhov.lab" -> ожидаемый формат: userPrincipalName -> результат: userUpnSet |
| ldap_explicit_upn_wins | LDAP: пересечения полей и приоритеты | LDAP: вход "userImplicitOwner@pastukhov.lab" -> ожидаемый формат: userPrincipalName -> результат: userConflict |
| ldap_trust_local_pastukhov_wins | LDAP: пересечения полей и приоритеты | LDAP: вход "userTrust@pastukhov.lab" -> ожидаемый формат: userPrincipalName -> результат: userTrustPastukhov |
| ldap_trust_local_domain3_wins | LDAP: пересечения полей и приоритеты | LDAP: вход "userTrust@pastukhov.lab" -> ожидаемый формат: userPrincipalName -> результат: userTrustDomain3 |
| ldap_duplicate_display_name | LDAP: пересечения полей и приоритеты | LDAP: вход "Same Display" -> ожидаемый формат: displayName -> результат: not_unique |
| ldap_display_equals_sam | LDAP: пересечения полей и приоритеты | LDAP: вход "cornerSamTarget" -> ожидаемый формат: displayName -> результат: userDisplaySam |
| ldap_display_equals_upn | LDAP: пересечения полей и приоритеты | LDAP: вход "cornerUpnTarget@pastukhov.lab" -> ожидаемый формат: userPrincipalName -> результат: cornerUpnTarget |
| ldap_display_equals_downlevel | LDAP: пересечения полей и приоритеты | LDAP: вход "PASTUKHOV\cornerDownlevelTarget" -> ожидаемый формат: downLevelLogonName -> результат: cornerDownlevelTarget |
| ldap_display_equals_dn | LDAP: пересечения полей и приоритеты | LDAP: вход "CN=cornerDnTarget,CN=Users,DC=pastukhov,DC=lab" -> ожидаемый формат: distinguishedName -> результат: cornerDnTarget |
| ldap_display_equals_canonical | LDAP: пересечения полей и приоритеты | LDAP: вход "pastukhov.lab/Users/cornerCanonicalTarget" -> ожидаемый формат: canonicalName -> результат: cornerCanonicalTarget |
| ldap_display_equals_guid | LDAP: пересечения полей и приоритеты | LDAP: вход "{cccccccc-0000-0000-0000-000000000066}" -> ожидаемый формат: objectGUID -> результат: cornerGuidTarget |
| ldap_display_equals_spn | LDAP: пересечения полей и приоритеты | LDAP: вход "HTTP/cornerSpnTarget" -> ожидаемый формат: displayName -> результат: userDisplaySpn |
| ldap_display_equals_sid | LDAP: пересечения полей и приоритеты | LDAP: вход "S-1-5-21-2845156888-2425353457-3474467337-1668" -> ожидаемый формат: displayName -> результат: userDisplaySid |
| krb_as_enterprise_upn_userA | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[userA@pastukhov.lab], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE/userPrincipalName -> результат: userA |
| krb_as_enterprise_upn_userB | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[userB@domain3.lab], realm=DOMAIN3.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE/userPrincipalName -> результат: userB |
| krb_as_enterprise_generated_upn | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[userImplicit@pastukhov.lab], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE/generatedUPN -> результат: userImplicit |
| krb_as_enterprise_implicit_upn_with_explicit_set | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[userUpnSet@pastukhov.lab], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE/generatedUPN -> результат: userUpnSet |
| krb_as_enterprise_explicit_changed_upn | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[userUpnSetX@pastukhov.lab], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE/userPrincipalName -> результат: userUpnSet |
| krb_as_enterprise_explicit_wins | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[userImplicitOwner@pastukhov.lab], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE/userPrincipalName -> результат: userConflict |
| krb_as_principal_sam_userA | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=1, name-string=[userA], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-PRINCIPAL/sAMAccountName -> результат: userA |
| krb_as_principal_sam_userB | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=1, name-string=[userB], realm=DOMAIN3.LAB -> Client Principal Lookup; ожидаемый формат: NT-PRINCIPAL/sAMAccountName -> результат: userB |
| krb_as_principal_sam_dollar | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=1, name-string=[10-23-RP-DC-01], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-PRINCIPAL/sAMAccountName+$ -> результат: dc01 |
| krb_as_principal_upn_fallback | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=1, name-string=[userUpnSetX], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-PRINCIPAL/userPrincipalName -> результат: userUpnSet |
| krb_as_dn_not_accepted | Kerberos: Client Principal Lookup | Kerberos AS-REQ: cname name-type=10, name-string=[CN=userA,CN=Users,DC=pastukhov,DC=lab], realm=PASTUKHOV.LAB -> Client Principal Lookup; ожидаемый формат: NT-ENTERPRISE -> результат: object_not_found |
| krb_tgs_srv_inst_userprincipalname_not_found | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=2, name-string=[cifs, 10-23-RP-DC-01.pastukhov.lab], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-SRV-INST/userPrincipalName -> результат: object_not_found |
| krb_tgs_krbtgt_special_case | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=2, name-string=[krbtgt, krbtgt], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-SRV-INST/krbtgt/sAMAccountName -> результат: krbtgt |
| krb_tgs_srv_inst_sam_dollar | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=2, name-string=[10-23-RP-DC-01], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-SRV-INST/sAMAccountName+$ -> результат: dc01 |
| krb_tgs_enterprise_spn_dc | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=10, name-string=[cifs/10-23-RP-DC-01.pastukhov.lab], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-ENTERPRISE/servicePrincipalName -> результат: dc01 |
| krb_tgs_enterprise_spn_userA | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=10, name-string=[HTTP/userA], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-ENTERPRISE/servicePrincipalName -> результат: userA |
| krb_tgs_enterprise_sam_with_spn | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=10, name-string=[userA], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-ENTERPRISE/sAMAccountName -> результат: userA |
| krb_tgs_enterprise_fallback_without_spn_fails | Kerberos: Server Principal Lookup | Kerberos TGS-REQ: sname name-type=10, name-string=[userUpnSet], realm=PASTUKHOV.LAB -> Server Principal Lookup; ожидаемый формат: NT-ENTERPRISE/sAMAccountName -> результат: object_not_found |

## Как запускать

Ручной режим:

```powershell
python run.py
```

Запустить все тесты:

```powershell
python run.py --run-all
```

Посмотреть список тестов:

```powershell
python run.py --list-tests
```

Запустить один раздел:

```powershell
python run.py --run-category ldap_corner
```

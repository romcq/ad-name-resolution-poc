"""Repository-style lookup helpers over the local JSON AD snapshot.

Resolver-файлы не должны знать, как именно устроен JSON. Они спрашивают
repository: "найди по UPN", "найди по SID", "найди по SPN". Так алгоритм
остается читаемым, а вся работа с локальной базой собрана здесь.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import ADObject
from .utils import canonical_with_lf, norm, norm_guid


class ADSnapshotRepository:
    def __init__(self, objects: Iterable[ADObject]):
        self.objects = list(objects)

    @classmethod
    def load(cls, path: str | Path) -> "ADSnapshotRepository":
        with Path(path).open("r", encoding="utf-8") as file:
            raw = json.load(file)
        return cls(ADObject.from_dict(item) for item in raw["objects"])

    def subset_by_ids(self, object_ids: Iterable[str]) -> "ADSnapshotRepository":
        # В статье corner-кейсы проверяются как отдельные лабораторные сценарии.
        # Например, displayName может специально совпадать со SPN, поэтому тесты
        # запускаются на своем подмножестве объектов, а не всегда на всей базе.
        id_set = set(object_ids)
        return ADSnapshotRepository(obj for obj in self.objects if obj.id in id_set)

    def domain_matches(self, obj: ADObject, domain: str | None) -> bool:
        # domain_context/realm может прийти как DNS-имя pastukhov.lab
        # или как NetBIOS PASTUKHOV. Для PoC считаем оба варианта эквивалентными.
        if not domain:
            return True
        domain_norm = norm(domain)
        return domain_norm in {norm(obj.domainFQDN), norm(obj.domainNetBIOS)}

    def prefer_domain(self, candidates: list[ADObject], domain: str | None) -> list[ADObject]:
        # В этой PoC-модели snapshot принадлежит ITDR-продукту, а не одному DC.
        # Поэтому полные идентификаторы сначала ищутся по всей базе. Доменный
        # контекст не является жестким фильтром: он только помогает выбрать
        # локальный объект, если одинаковое значение найдено в нескольких доменах.
        if not domain or len(candidates) <= 1:
            return candidates
        preferred = [candidate for candidate in candidates if self.domain_matches(candidate, domain)]
        return preferred or candidates

    def find_distinguished_name(self, value: str) -> list[ADObject]:
        return [obj for obj in self.objects if norm(obj.distinguishedName) == norm(value)]

    def find_user_principal_name(self, value: str, domain_context: str | None = None) -> list[ADObject]:
        # Explicit UPN ищется как целая строка. Suffix после @ не обязан
        # совпадать с domainFQDN объекта.
        candidates = [
            obj
            for obj in self.objects
            if obj.userPrincipalName is not None and norm(obj.userPrincipalName) == norm(value)
        ]
        return self.prefer_domain(candidates, domain_context)

    def find_generated_upn(
        self,
        account: str,
        suffix: str,
        domain_context: str | None = None,
    ) -> list[ADObject]:
        # Generated/implicit UPN собирается как sAMAccountName@domainFQDN.
        # Он проверяется только после точного поиска по userPrincipalName, поэтому
        # явный userPrincipalName другого объекта имеет приоритет. При этом generated
        # форма может разрешить аккаунт, у которого уже задан отдельный explicit UPN.
        candidates = [
            obj
            for obj in self.objects
            if norm(obj.sAMAccountName) == norm(account)
            and norm(obj.domainFQDN) == norm(suffix)
        ]
        return self.prefer_domain(candidates, domain_context)

    def find_downlevel(self, netbios_domain: str, account: str) -> list[ADObject]:
        return [
            obj
            for obj in self.objects
            if norm(obj.domainNetBIOS) == norm(netbios_domain)
            and norm(obj.sAMAccountName) == norm(account)
        ]

    def find_canonical_name(self, value: str) -> list[ADObject]:
        return [obj for obj in self.objects if norm(obj.canonicalName) == norm(value)]

    def find_canonical_name_lf(self, value: str) -> list[ADObject]:
        return [obj for obj in self.objects if norm(canonical_with_lf(obj.canonicalName)) == norm(value)]

    def find_object_guid(self, value: str) -> list[ADObject]:
        return [obj for obj in self.objects if norm_guid(obj.objectGUID) == norm_guid(value)]

    def find_display_name(self, value: str, domain_context: str | None = None) -> list[ADObject]:
        return self.prefer_domain(
            [obj for obj in self.objects if norm(obj.displayName) == norm(value)],
            domain_context,
        )

    def find_service_principal_name(self, value: str, domain_context: str | None = None) -> list[ADObject]:
        candidates = [
            obj
            for obj in self.objects
            if any(norm(spn) == norm(value) for spn in obj.servicePrincipalName)
        ]
        return self.prefer_domain(candidates, domain_context)

    def find_mapped_spn(
        self,
        value: str,
        spn_mappings: dict[str, list[str]],
        domain_context: str | None = None,
    ) -> tuple[list[ADObject], str | None]:
        # Упрощенный MapSPN: берем service class слева от "/" и пробуем
        # заменить его на классы из локального словаря spn_mappings.
        service, _, instance = value.partition("/")
        if not service or not instance:
            return [], None
        for mapped_class in spn_mappings.get(service.upper(), []):
            mapped_value = f"{mapped_class}/{instance}"
            matches = self.find_service_principal_name(mapped_value, domain_context)
            if matches:
                return matches, mapped_value
        return [], None

    def find_object_sid(self, value: str) -> list[ADObject]:
        return [obj for obj in self.objects if norm(obj.objectSid) == norm(value)]

    def find_sid_history(self, value: str) -> list[ADObject]:
        return [obj for obj in self.objects if any(norm(sid) == norm(value) for sid in obj.sIDHistory)]

    def find_sam_in_domain(self, account: str, domain: str | None) -> list[ADObject]:
        # Короткие имена вроде sAMAccountName не самодостаточны, поэтому здесь
        # domain/realm уже используется как реальная область поиска.
        candidates = [obj for obj in self.objects if norm(obj.sAMAccountName) == norm(account)]
        if domain:
            candidates = [candidate for candidate in candidates if self.domain_matches(candidate, domain)]
        return candidates

    def domain_fqdn_for_context(self, domain: str | None) -> str | None:
        # Kerberos realm часто приходит как PASTUKHOV.LAB. Для дальнейших
        # проверок нужен DNS-домен в формате pastukhov.lab.
        if not domain:
            return None
        for obj in self.objects:
            if self.domain_matches(obj, domain):
                return obj.domainFQDN
        return domain.lower()

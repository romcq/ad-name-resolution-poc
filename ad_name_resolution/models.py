"""Result and AD object models shared by all resolver branches."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ADObject:
    id: str
    object_type: str
    sAMAccountName: str
    userPrincipalName: str | None
    distinguishedName: str
    canonicalName: str
    displayName: str
    objectGUID: str
    objectSid: str
    servicePrincipalName: list[str] = field(default_factory=list)
    sIDHistory: list[str] = field(default_factory=list)
    domainFQDN: str = ""
    domainNetBIOS: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ADObject":
        return cls(
            id=data["id"],
            object_type=data["object_type"],
            sAMAccountName=data["sAMAccountName"],
            userPrincipalName=data.get("userPrincipalName") or None,
            distinguishedName=data["distinguishedName"],
            canonicalName=data["canonicalName"],
            displayName=data["displayName"],
            objectGUID=data["objectGUID"],
            objectSid=data["objectSid"],
            servicePrincipalName=list(data.get("servicePrincipalName") or []),
            sIDHistory=list(data.get("sIDHistory") or []),
            domainFQDN=data["domainFQDN"],
            domainNetBIOS=data["domainNetBIOS"],
        )

    def short_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "object_type": self.object_type,
            "sAMAccountName": self.sAMAccountName,
            "userPrincipalName": self.userPrincipalName,
            "distinguishedName": self.distinguishedName,
            "canonicalName": self.canonicalName,
            "displayName": self.displayName,
            "objectGUID": self.objectGUID,
            "objectSid": self.objectSid,
            "domainFQDN": self.domainFQDN,
            "domainNetBIOS": self.domainNetBIOS,
        }


@dataclass
class ResolutionResult:
    resolved: bool
    protocol: str | None = None
    algorithm_branch: str | None = None
    input_field: str | None = None
    input_value: str | None = None
    matched_format: str | None = None
    matched_field: str | None = None
    matched_value: str | None = None
    matched_object_id: str | None = None
    matched_object: ADObject | None = None
    reason: str | None = None
    unimplemented_steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self, include_object: bool = False, include_trace: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {"resolved": self.resolved}
        optional_values = {
            "protocol": self.protocol,
            "algorithm_branch": self.algorithm_branch,
            "input_field": self.input_field,
            "input_value": self.input_value,
            "matched_format": self.matched_format,
            "matched_field": self.matched_field,
            "matched_value": self.matched_value,
            "matched_object_id": self.matched_object_id,
            "reason": self.reason,
            "unimplemented_steps": self.unimplemented_steps or None,
            "notes": self.notes or None,
        }
        for key, value in optional_values.items():
            if value is not None:
                result[key] = value
        if include_object and self.matched_object is not None:
            result["matched_object"] = self.matched_object.short_dict()
        if include_trace and self.trace:
            result["trace"] = self.trace
        return result


def found_result(
    *,
    protocol: str,
    algorithm_branch: str,
    input_field: str,
    input_value: str,
    matched_format: str,
    matched_field: str,
    matched_value: str,
    obj: ADObject,
    notes: list[str] | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> ResolutionResult:
    return ResolutionResult(
        resolved=True,
        protocol=protocol,
        algorithm_branch=algorithm_branch,
        input_field=input_field,
        input_value=input_value,
        matched_format=matched_format,
        matched_field=matched_field,
        matched_value=matched_value,
        matched_object_id=obj.id,
        matched_object=obj,
        notes=notes or [],
        trace=trace or [],
    )


def not_found_result(
    *,
    protocol: str,
    algorithm_branch: str,
    input_field: str,
    input_value: str,
    unimplemented_steps: list[str] | None = None,
    notes: list[str] | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> ResolutionResult:
    return ResolutionResult(
        resolved=False,
        protocol=protocol,
        algorithm_branch=algorithm_branch,
        input_field=input_field,
        input_value=input_value,
        reason="object_not_found",
        unimplemented_steps=unimplemented_steps or [],
        notes=notes or [],
        trace=trace or [],
    )


def not_unique_result(
    *,
    protocol: str,
    algorithm_branch: str,
    input_field: str,
    input_value: str,
    matched_format: str,
    matched_field: str,
    matched_value: str,
    candidates: list[ADObject],
    trace: list[dict[str, Any]] | None = None,
) -> ResolutionResult:
    return ResolutionResult(
        resolved=False,
        protocol=protocol,
        algorithm_branch=algorithm_branch,
        input_field=input_field,
        input_value=input_value,
        matched_format=matched_format,
        matched_field=matched_field,
        matched_value=matched_value,
        reason="not_unique",
        notes=[f"{len(candidates)} candidates matched internally"],
        trace=trace or [],
    )


def invalid_input_result(reason: str) -> ResolutionResult:
    return ResolutionResult(resolved=False, reason=reason)


def unsupported_result(
    *,
    protocol: str | None = None,
    algorithm_branch: str | None = None,
    input_field: str | None = None,
    input_value: str | None = None,
    reason: str = "unsupported_scenario",
    notes: list[str] | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> ResolutionResult:
    return ResolutionResult(
        resolved=False,
        protocol=protocol,
        algorithm_branch=algorithm_branch,
        input_field=input_field,
        input_value=input_value,
        reason=reason,
        notes=notes or [],
        trace=trace or [],
    )

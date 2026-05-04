from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from .models import ControlResult


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_get(dct: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = dct
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def contains_value(values: Optional[Iterable[Any]], expected: str) -> bool:
    return expected in set(values or [])


def result(
    control_id: str,
    title: str,
    status: str,
    confidence: str,
    reason: str,
    expected: str,
    observed: str,
    evidence: Dict[str, Any],
    remediation_hint: Optional[str] = None,
    notes: Optional[str] = None,
    source: str = "graph",
) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title=title,
        status=status,
        confidence=confidence,
        reason=reason,
        expected=expected,
        observed=observed,
        evidence=evidence,
        timestamp_utc=utc_now(),
        source=source,
        remediation_hint=remediation_hint,
        notes=notes,
    )


def summarize_ca_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": policy.get("id"),
        "displayName": policy.get("displayName"),
        "state": policy.get("state"),
        "includeUsers": safe_get(policy, "conditions", "users", "includeUsers", default=[]),
        "excludeUsers": safe_get(policy, "conditions", "users", "excludeUsers", default=[]),
        "includeGroups": safe_get(policy, "conditions", "users", "includeGroups", default=[]),
        "excludeGroups": safe_get(policy, "conditions", "users", "excludeGroups", default=[]),
        "includeRoles": safe_get(policy, "conditions", "users", "includeRoles", default=[]),
        "excludeRoles": safe_get(policy, "conditions", "users", "excludeRoles", default=[]),
        "clientAppTypes": safe_get(policy, "conditions", "clientAppTypes", default=[]),
        "signInRiskLevels": safe_get(policy, "conditions", "signInRiskLevels", default=[]),
        "userRiskLevels": safe_get(policy, "conditions", "userRiskLevels", default=[]),
        "grantControls": safe_get(policy, "grantControls", "builtInControls", default=[]),
        "authenticationStrength": safe_get(policy, "grantControls", "authenticationStrength", default=None),
    }

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

import requests


GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
DEFAULT_GRAPH_BASE_URL = os.getenv("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
DEFAULT_OUTPUT_PATH = os.getenv("OUTPUT_PATH", "drmf_output.json")


class GraphCollectorError(Exception):
    """Raised for collector-specific failures."""


@dataclass
class ControlResult:
    control_id: str
    title: str
    status: str
    confidence: str
    evidence: Dict[str, Any]
    timestamp_utc: str
    source: str = "graph"
    notes: Optional[str] = None


class GraphClient:
    """Minimal Graph client with token caching, paging, retries, and timeouts."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        graph_base_url: str = DEFAULT_GRAPH_BASE_URL,
        timeout: int = 30,
        max_retries: int = 4,
    ) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.graph_base_url = graph_base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._token: Optional[str] = None
        self._token_expires_epoch: float = 0
        self.session = requests.Session()

    def _get_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expires_epoch - 120:
            return self._token

        url = GRAPH_TOKEN_URL.format(tenant_id=self.tenant_id)
        data = {
            "client_id": self.client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }
        response = self.session.post(url, data=data, timeout=self.timeout)
        response.raise_for_status()
        token_data = response.json()
        self._token = token_data["access_token"]
        self._token_expires_epoch = now + int(token_data.get("expires_in", 3600))
        return self._token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }

    def get(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = f"{self.graph_base_url}/{path_or_url.lstrip('/')}"

        attempt = 0
        while True:
            attempt += 1
            response = self.session.get(url, headers=self._headers(), params=params, timeout=self.timeout)

            if response.status_code in (429, 500, 502, 503, 504) and attempt <= self.max_retries:
                retry_after = response.headers.get("Retry-After")
                sleep_seconds = int(retry_after) if retry_after and retry_after.isdigit() else min(2 ** attempt, 20)
                time.sleep(sleep_seconds)
                continue

            response.raise_for_status()
            return response.json()

    def list_all(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        data = self.get(path_or_url, params=params)
        items = list(data.get("value", []))
        next_link = data.get("@odata.nextLink")
        while next_link:
            data = self.get(next_link)
            items.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
        return items


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


def evaluate_mfa_all_users(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    matches = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        built_in = safe_get(p, "grantControls", "builtInControls", default=[]) or []
        include_users = safe_get(p, "conditions", "users", "includeUsers", default=[]) or []
        if contains_value(built_in, "mfa") and ("All" in include_users or "AllUsers" in include_users):
            matches.append(
                {
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                    "excludeUsers": safe_get(p, "conditions", "users", "excludeUsers", default=[]),
                    "excludeGroups": safe_get(p, "conditions", "users", "excludeGroups", default=[]),
                }
            )

    return ControlResult(
        control_id="ID-01",
        title="MFA enforced for all users",
        status="pass" if matches else "fail",
        confidence="medium",
        evidence={"matched_policies": matches, "policy_count": len(matches)},
        timestamp_utc=utc_now(),
        notes="Presence of CA policy is evidence of configuration, not guaranteed effective enforcement.",
    )


def evaluate_mfa_admin_roles(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    matches = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        built_in = safe_get(p, "grantControls", "builtInControls", default=[]) or []
        include_roles = safe_get(p, "conditions", "users", "includeRoles", default=[]) or []
        if contains_value(built_in, "mfa") and include_roles:
            matches.append(
                {
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                    "includeRoles": include_roles,
                    "excludeUsers": safe_get(p, "conditions", "users", "excludeUsers", default=[]),
                }
            )

    return ControlResult(
        control_id="ID-02",
        title="MFA enforced for all admin roles",
        status="pass" if matches else "fail",
        confidence="medium",
        evidence={"matched_policies": matches, "policy_count": len(matches)},
        timestamp_utc=utc_now(),
        notes="Role-scoped policy presence only. Exclusions and overlap still require review.",
    )


def evaluate_break_glass(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    signins = client.list_all("auditLogs/signIns", params={"$top": 50})
    excluded_refs = []
    for p in policies:
        exclude_users = safe_get(p, "conditions", "users", "excludeUsers", default=[]) or []
        exclude_groups = safe_get(p, "conditions", "users", "excludeGroups", default=[]) or []
        if exclude_users or exclude_groups:
            excluded_refs.append(
                {
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                    "excludeUsers": exclude_users,
                    "excludeGroups": exclude_groups,
                }
            )

    evidence = {
        "policies_with_exclusions": excluded_refs,
        "recent_signin_count": len(signins),
    }
    status = "partial" if excluded_refs else "fail"

    return ControlResult(
        control_id="ID-05",
        title="Break-glass accounts excluded from CA and monitored",
        status=status,
        confidence="low",
        evidence=evidence,
        timestamp_utc=utc_now(),
        notes="Cannot prove documented ownership or quarterly testing from Graph alone.",
    )


def evaluate_compliant_device_required(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    matched = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        built_in = safe_get(p, "grantControls", "builtInControls", default=[]) or []
        if contains_value(built_in, "compliantDevice"):
            matched.append(
                {
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                }
            )

    return ControlResult(
        control_id="ID-06",
        title="Conditional Access requires compliant device",
        status="pass" if matched else "fail",
        confidence="medium",
        evidence={"matched_policies": matched, "policy_count": len(matched)},
        timestamp_utc=utc_now(),
        notes="Policy presence only. Intune compliance scope and exclusions still matter.",
    )


def evaluate_auth_methods_policy(client: GraphClient) -> ControlResult:
    policy = client.get("policies/authenticationMethodsPolicy")
    methods = policy.get("authenticationMethodConfigurations", [])
    interesting = []
    for m in methods:
        interesting.append(
            {
                "id": m.get("id"),
                "state": m.get("state"),
                "type": m.get("@odata.type"),
            }
        )

    voice_sms_disabled = [
        x for x in interesting
        if ("sms" in (x.get("id") or "").lower() or "voice" in (x.get("id") or "").lower())
        and x.get("state") == "disabled"
    ]
    status = "pass" if voice_sms_disabled else "partial"

    return ControlResult(
        control_id="ID-09",
        title="Authentication Methods Policy hardened",
        status=status,
        confidence="medium",
        evidence={
            "policyId": policy.get("id"),
            "methods": interesting,
            "disabled_sms_or_voice_methods": voice_sms_disabled,
        },
        timestamp_utc=utc_now(),
        notes="Interpretation is intentionally conservative. Review exact tenant design and allowed method set.",
    )


def evaluate_admin_consent_workflow(client: GraphClient) -> ControlResult:
    policy = client.get("policies/adminConsentRequestPolicy")
    enabled = bool(policy.get("isEnabled"))
    return ControlResult(
        control_id="ID-10",
        title="Admin consent workflow enabled",
        status="pass" if enabled else "fail",
        confidence="high",
        evidence=policy,
        timestamp_utc=utc_now(),
    )


def evaluate_app_registration_restricted(client: GraphClient) -> ControlResult:
    policy = client.get("policies/authorizationPolicy/authorizationPolicy")
    perms = policy.get("defaultUserRolePermissions", {})
    allowed = perms.get("allowedToCreateApps")
    status = "pass" if allowed is False else "fail"

    return ControlResult(
        control_id="ID-11",
        title="Application registrations restricted",
        status=status,
        confidence="high",
        evidence={
            "authorizationPolicyId": policy.get("id"),
            "defaultUserRolePermissions": perms,
        },
        timestamp_utc=utc_now(),
        notes="Pass means default users cannot create app registrations.",
    )


def evaluate_cross_tenant_access(client: GraphClient) -> ControlResult:
    policy = client.get("policies/crossTenantAccessPolicy")
    configured = bool(policy)
    return ControlResult(
        control_id="ID-13",
        title="Cross-tenant access settings configured",
        status="pass" if configured else "fail",
        confidence="medium",
        evidence={
            "policyId": policy.get("id"),
            "hasDefaultSettings": "default" in policy,
            "partnerCountHint": len(policy.get("partners", {})) if isinstance(policy.get("partners"), dict) else None,
        },
        timestamp_utc=utc_now(),
        notes="This confirms policy object presence, not whether configuration is suitably restrictive.",
    )


def evaluate_named_locations(client: GraphClient) -> ControlResult:
    locations = client.list_all("identity/conditionalAccess/namedLocations")
    return ControlResult(
        control_id="ID-14",
        title="Named locations defined",
        status="pass" if len(locations) > 0 else "fail",
        confidence="high",
        evidence={"named_location_count": len(locations), "locations": locations[:20]},
        timestamp_utc=utc_now(),
    )


def evaluate_security_defaults_replaced(client: GraphClient) -> ControlResult:
    try:
        sec_defaults = client.get("policies/identitySecurityDefaultsEnforcementPolicy")
        is_enabled = bool(sec_defaults.get("isEnabled"))
    except Exception as exc:  # noqa: BLE001
        return ControlResult(
            control_id="ID-16",
            title="Security defaults disabled only if replaced by CA baseline",
            status="partial",
            confidence="low",
            evidence={"error": str(exc)},
            timestamp_utc=utc_now(),
            notes="Could not read identitySecurityDefaultsEnforcementPolicy with current permissions or tenant support.",
        )

    policies = client.list_all("identity/conditionalAccess/policies")
    enabled_ca = [p for p in policies if p.get("state") == "enabled"]

    if is_enabled:
        status = "pass"
        note = "Security defaults are enabled."
    elif enabled_ca:
        status = "partial"
        note = "Security defaults disabled; CA policies exist, but equivalence still requires review."
    else:
        status = "fail"
        note = "Security defaults disabled and no enabled CA policies found."

    return ControlResult(
        control_id="ID-16",
        title="Security defaults disabled only if replaced by CA baseline",
        status=status,
        confidence="medium" if is_enabled else "low",
        evidence={
            "securityDefaultsEnabled": is_enabled,
            "enabledCAPolicyCount": len(enabled_ca),
            "enabledCAPolicies": [{"id": p.get("id"), "displayName": p.get("displayName")} for p in enabled_ca[:20]],
        },
        timestamp_utc=utc_now(),
        notes=note,
    )


def evaluate_access_reviews(client: GraphClient) -> ControlResult:
    definitions = client.list_all("identityGovernance/accessReviews/definitions")
    active = []
    for d in definitions:
        sched = d.get("settings", {})
        if sched:
            active.append(
                {
                    "id": d.get("id"),
                    "displayName": d.get("displayName"),
                    "mailNotificationsEnabled": sched.get("mailNotificationsEnabled"),
                    "recurrence": sched.get("recurrence"),
                }
            )

    return ControlResult(
        control_id="ID-17",
        title="Access Reviews scheduled and enforced",
        status="pass" if active else "fail",
        confidence="medium",
        evidence={"definition_count": len(definitions), "scheduled_reviews": active[:25]},
        timestamp_utc=utc_now(),
        notes="Scheduling evidence only. Completion quality and review outcomes require deeper review.",
    )


def evaluate_bitlocker_escrow(client: GraphClient) -> ControlResult:
    keys = client.list_all("informationProtection/bitlocker/recoveryKeys")
    return ControlResult(
        control_id="EP-05",
        title="BitLocker recovery keys escrowed",
        status="pass" if len(keys) > 0 else "fail",
        confidence="medium",
        evidence={"recovery_key_count": len(keys), "sample": keys[:10]},
        timestamp_utc=utc_now(),
        notes="This proves escrow presence, not complete enforcement across all in-scope devices.",
    )


CONTROL_EVALUATORS: List[Callable[[GraphClient], ControlResult]] = [
    evaluate_mfa_all_users,
    evaluate_mfa_admin_roles,
    evaluate_break_glass,
    evaluate_compliant_device_required,
    evaluate_auth_methods_policy,
    evaluate_admin_consent_workflow,
    evaluate_app_registration_restricted,
    evaluate_cross_tenant_access,
    evaluate_named_locations,
    evaluate_security_defaults_replaced,
    evaluate_access_reviews,
    evaluate_bitlocker_escrow,
]


def load_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise GraphCollectorError(f"Missing required environment variable: {name}")
    return value


def run() -> List[ControlResult]:
    tenant_id = load_required_env("TENANT_ID")
    client_id = load_required_env("CLIENT_ID")
    client_secret = load_required_env("CLIENT_SECRET")

    client = GraphClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

    results: List[ControlResult] = []
    for evaluator in CONTROL_EVALUATORS:
        try:
            results.append(evaluator(client))
        except requests.HTTPError as exc:
            results.append(
                ControlResult(
                    control_id=getattr(evaluator, "__name__", "unknown"),
                    title=getattr(evaluator, "__name__", "unknown"),
                    status="error",
                    confidence="low",
                    evidence={
                        "http_status": exc.response.status_code if exc.response is not None else None,
                        "response_text": exc.response.text[:2000] if exc.response is not None else str(exc),
                    },
                    timestamp_utc=utc_now(),
                    notes="HTTP error during Graph query.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                ControlResult(
                    control_id=getattr(evaluator, "__name__", "unknown"),
                    title=getattr(evaluator, "__name__", "unknown"),
                    status="error",
                    confidence="low",
                    evidence={"error": str(exc)},
                    timestamp_utc=utc_now(),
                    notes="Unhandled exception during evaluation.",
                )
            )

    return results


def main() -> int:
    try:
        results = run()
    except GraphCollectorError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2

    output_path = os.getenv("OUTPUT_PATH", DEFAULT_OUTPUT_PATH)
    payload = {
        "generated_at_utc": utc_now(),
        "result_count": len(results),
        "results": [asdict(r) for r in results],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    print(f"[ok] wrote {len(results)} control results to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

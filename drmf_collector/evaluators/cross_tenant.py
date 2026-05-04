from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result


def evaluate_cross_tenant_access(client: GraphClient) -> ControlResult:
    policy = client.get("policies/crossTenantAccessPolicy")
    default_settings = policy.get("default")
    partner_settings = policy.get("partners")

    if default_settings:
        status = "partial"
        reason = "Cross-tenant access policy exists, but this check does not yet validate whether defaults are restrictive."
        observed = "Cross-tenant access policy object returned by Graph."
    else:
        status = "fail"
        reason = "Cross-tenant access policy default settings were not found in the response."
        observed = "No default cross-tenant access settings observed."

    return result(
        control_id="ID-13",
        title="Cross-tenant access settings configured",
        status=status,
        confidence="medium",
        reason=reason,
        expected="Cross-tenant inbound/outbound defaults and partner-specific exceptions are explicitly configured and reviewed.",
        observed=observed,
        evidence={
            "policyId": policy.get("id"),
            "has_default_settings": bool(default_settings),
            "has_partner_settings": bool(partner_settings),
            "raw_keys": list(policy.keys()),
        },
        remediation_hint="Review inbound/outbound B2B defaults and configure partner-specific trust only where justified.",
        notes="This control needs stricter logic before it can be marked pass automatically.",
    )

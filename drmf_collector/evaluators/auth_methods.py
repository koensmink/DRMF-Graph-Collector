from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result


def evaluate_auth_methods_policy(client: GraphClient) -> ControlResult:
    policy = client.get("policies/authenticationMethodsPolicy")
    methods = policy.get("authenticationMethodConfigurations", [])

    method_summary = [
        {
            "id": method.get("id"),
            "state": method.get("state"),
            "type": method.get("@odata.type"),
        }
        for method in methods
    ]

    weak_methods = [
        method for method in method_summary
        if any(x in (method.get("id") or "").lower() for x in ["sms", "voice"])
    ]

    weak_enabled = [
        method for method in weak_methods
        if method.get("state") == "enabled"
    ]

    stronger_enabled = [
        method for method in method_summary
        if any(x in (method.get("id") or "").lower() for x in ["fido2", "windowshello", "temporaryaccesspass"])
        and method.get("state") == "enabled"
    ]

    if weak_enabled:
        status = "fail"
        reason = "Weak authentication methods are enabled."
        observed = f"{len(weak_enabled)} weak method(s) enabled: {', '.join([m.get('id') or '' for m in weak_enabled])}."
    elif stronger_enabled:
        status = "pass"
        reason = "No enabled SMS/voice methods found and at least one stronger method appears enabled."
        observed = f"{len(stronger_enabled)} stronger method(s) enabled."
    else:
        status = "partial"
        reason = "No enabled SMS/voice methods found, but no clearly phishing-resistant method was identified in this simple evaluation."
        observed = "Weak methods not enabled; phishing-resistant method coverage needs review."

    return result(
        control_id="ID-09",
        title="Authentication Methods Policy hardened",
        status=status,
        confidence="medium",
        reason=reason,
        expected="SMS/voice disabled or restricted; phishing-resistant methods such as FIDO2/WHfB enabled where possible.",
        observed=observed,
        evidence={
            "policyId": policy.get("id"),
            "methods": method_summary,
            "weak_methods": weak_methods,
            "weak_methods_enabled": weak_enabled,
            "stronger_methods_enabled": stronger_enabled,
        },
        remediation_hint="Disable or tightly scope SMS/voice. Enable FIDO2 security keys and/or Windows Hello for Business for privileged users.",
    )

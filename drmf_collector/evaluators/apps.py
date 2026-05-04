from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result


def evaluate_admin_consent_workflow(client: GraphClient) -> ControlResult:
    policy = client.get("policies/adminConsentRequestPolicy")
    enabled = bool(policy.get("isEnabled"))

    return result(
        control_id="ID-10",
        title="Admin consent workflow enabled",
        status="pass" if enabled else "fail",
        confidence="high",
        reason="Admin consent request workflow is enabled." if enabled else "Admin consent request workflow is disabled.",
        expected="Admin consent workflow enabled, with reviewers and notification settings configured.",
        observed=f"isEnabled={enabled}",
        evidence=policy,
        remediation_hint="Enable admin consent workflow and configure reviewers so user consent requests are governed instead of ad hoc.",
    )


def evaluate_app_registration_restricted(client: GraphClient) -> ControlResult:
    policy = client.get("policies/authorizationPolicy/authorizationPolicy")
    perms = policy.get("defaultUserRolePermissions", {})
    allowed = perms.get("allowedToCreateApps")

    if allowed is False:
        status = "pass"
        reason = "Default users are not allowed to create application registrations."
        observed = "defaultUserRolePermissions.allowedToCreateApps=false"
    elif allowed is True:
        status = "fail"
        reason = "Default users are allowed to create application registrations."
        observed = "defaultUserRolePermissions.allowedToCreateApps=true"
    else:
        status = "partial"
        reason = "Could not determine app registration creation setting from authorization policy."
        observed = f"defaultUserRolePermissions.allowedToCreateApps={allowed}"

    return result(
        control_id="ID-11",
        title="Application registrations restricted",
        status=status,
        confidence="high" if allowed is not None else "low",
        reason=reason,
        expected="Default users should not be allowed to create app registrations unless explicitly justified.",
        observed=observed,
        evidence={
            "authorizationPolicyId": policy.get("id"),
            "defaultUserRolePermissions": perms,
        },
        remediation_hint="Set 'Users can register applications' to No or restrict app creation to controlled roles/processes.",
    )

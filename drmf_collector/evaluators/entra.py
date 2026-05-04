from __future__ import annotations

from typing import Any, Dict, List

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import contains_value, result, safe_get, summarize_ca_policy


def evaluate_mfa_all_users(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    enabled = [p for p in policies if p.get("state") == "enabled"]
    mfa_policies = [
        p for p in enabled
        if contains_value(safe_get(p, "grantControls", "builtInControls", default=[]), "mfa")
    ]
    matching = [
        p for p in mfa_policies
        if "All" in (safe_get(p, "conditions", "users", "includeUsers", default=[]) or [])
        or "AllUsers" in (safe_get(p, "conditions", "users", "includeUsers", default=[]) or [])
    ]

    if matching:
        status = "pass"
        reason = "At least one enabled Conditional Access policy requires MFA for all users or an equivalent all-user scope."
        observed = f"{len(matching)} matching enabled MFA policy/policies found."
    elif mfa_policies:
        status = "partial"
        reason = "MFA policies exist, but no enabled policy was found that clearly targets all users."
        observed = f"{len(mfa_policies)} enabled MFA policy/policies found, but target scope is not all users."
    else:
        status = "fail"
        reason = "No enabled Conditional Access policy requiring MFA was found."
        observed = "0 enabled MFA Conditional Access policies found."

    return result(
        control_id="ID-01",
        title="MFA enforced for all users",
        status=status,
        confidence="medium",
        reason=reason,
        expected="At least one enabled Conditional Access policy requiring MFA for all users, with documented exclusions only.",
        observed=observed,
        evidence={
            "total_ca_policies": len(policies),
            "enabled_ca_policies": len(enabled),
            "enabled_mfa_policies": len(mfa_policies),
            "matching_policies": [summarize_ca_policy(p) for p in matching],
            "other_mfa_policies": [summarize_ca_policy(p) for p in mfa_policies if p not in matching],
        },
        remediation_hint="Create or enable a Conditional Access policy that targets all users and requires MFA. Review and document exclusions such as break-glass accounts.",
        notes="Policy presence is configuration evidence; exclusions and policy interactions still require review.",
    )


def evaluate_mfa_admin_roles(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    enabled = [p for p in policies if p.get("state") == "enabled"]

    matching = []
    mfa_no_roles = []

    for p in enabled:
        built_in = safe_get(p, "grantControls", "builtInControls", default=[]) or []
        include_roles = safe_get(p, "conditions", "users", "includeRoles", default=[]) or []

        if contains_value(built_in, "mfa") and include_roles:
            matching.append(p)
        elif contains_value(built_in, "mfa"):
            mfa_no_roles.append(p)

    if matching:
        status = "pass"
        reason = "At least one enabled Conditional Access policy requires MFA and explicitly targets admin directory roles."
        observed = f"{len(matching)} role-scoped MFA policy/policies found."
    elif mfa_no_roles:
        status = "partial"
        reason = "MFA policies exist, but no enabled policy was found that explicitly targets admin roles."
        observed = f"{len(mfa_no_roles)} enabled MFA policy/policies found without admin role targeting."
    else:
        status = "fail"
        reason = "No enabled Conditional Access policy requiring MFA for admin roles was found."
        observed = "0 role-scoped MFA Conditional Access policies found."

    return result(
        control_id="ID-02",
        title="MFA enforced for all admin roles",
        status=status,
        confidence="medium",
        reason=reason,
        expected="Enabled Conditional Access policy requiring MFA for privileged/admin roles, with controlled exclusions.",
        observed=observed,
        evidence={
            "matching_policies": [summarize_ca_policy(p) for p in matching],
            "mfa_policies_without_role_scope": [summarize_ca_policy(p) for p in mfa_no_roles],
        },
        remediation_hint="Create or enable a Conditional Access policy scoped to privileged roles and require MFA or stronger authentication strength.",
        notes="Role coverage must be reviewed against actual role set and exclusions.",
    )


def evaluate_legacy_auth_blocked(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    enabled = [p for p in policies if p.get("state") == "enabled"]

    legacy_block = []
    legacy_related = []

    for p in enabled:
        client_apps = safe_get(p, "conditions", "clientAppTypes", default=[]) or []
        built_in = safe_get(p, "grantControls", "builtInControls", default=[]) or []
        targets_legacy = any(app in client_apps for app in ["exchangeActiveSync", "other"])

        if targets_legacy and contains_value(built_in, "block"):
            legacy_block.append(p)
        elif targets_legacy:
            legacy_related.append(p)

    if legacy_block:
        status = "partial"
        reason = "At least one enabled CA policy appears to block legacy client app types, but SMTP AUTH requires Exchange validation."
        observed = f"{len(legacy_block)} legacy-auth block policy/policies found in Conditional Access."
    elif legacy_related:
        status = "partial"
        reason = "Legacy client app policies exist, but no enabled block grant control was identified."
        observed = f"{len(legacy_related)} legacy-related CA policy/policies found without block grant."
    else:
        status = "fail"
        reason = "No enabled Conditional Access policy blocking legacy client app types was found."
        observed = "0 enabled legacy-auth block CA policies found."

    return result(
        control_id="ID-03",
        title="Legacy authentication blocked tenant-wide",
        status=status,
        confidence="low",
        reason=reason,
        expected="Legacy authentication is blocked via Conditional Access and SMTP AUTH is disabled or explicitly scoped in Exchange Online.",
        observed=observed,
        evidence={
            "legacy_block_policies": [summarize_ca_policy(p) for p in legacy_block],
            "legacy_related_policies": [summarize_ca_policy(p) for p in legacy_related],
        },
        remediation_hint="Create/enable a CA policy blocking Exchange ActiveSync and other legacy client apps. Validate SMTP AUTH separately in Exchange Online.",
        notes="Graph CA data alone is insufficient for tenant-wide SMTP AUTH validation.",
    )


def evaluate_break_glass(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")

    policies_with_exclusions = []
    for p in policies:
        exclude_users = safe_get(p, "conditions", "users", "excludeUsers", default=[]) or []
        exclude_groups = safe_get(p, "conditions", "users", "excludeGroups", default=[]) or []
        if exclude_users or exclude_groups:
            policies_with_exclusions.append({
                "policy": summarize_ca_policy(p),
                "excluded_user_count": len(exclude_users),
                "excluded_group_count": len(exclude_groups),
            })

    signins = []
    signin_error = None
    try:
        signins = client.list_all("auditLogs/signIns", params={"$top": 50})
    except Exception as exc:
        signin_error = str(exc)

    if policies_with_exclusions:
        status = "partial"
        reason = "Conditional Access exclusions exist, which may include break-glass accounts, but Graph output alone does not prove ownership, documentation, or quarterly testing."
        observed = f"{len(policies_with_exclusions)} CA policy/policies contain user or group exclusions."
    else:
        status = "fail"
        reason = "No Conditional Access exclusions were found. If break-glass accounts exist, they may not be excluded from CA."
        observed = "0 CA policies with user/group exclusions found."

    return result(
        control_id="ID-05",
        title="Break-glass accounts excluded from CA and monitored",
        status=status,
        confidence="low",
        reason=reason,
        expected="Two documented emergency accounts, excluded from CA, monitored, and tested at least quarterly.",
        observed=observed,
        evidence={
            "policies_with_exclusions": policies_with_exclusions,
            "recent_signin_sample_count": len(signins),
            "signin_query_error": signin_error,
        },
        remediation_hint="Maintain a documented break-glass register, exclude only those accounts from CA, configure alerting on sign-ins, and record quarterly test evidence.",
        notes="This control needs manual evidence in addition to Graph data.",
    )


def evaluate_compliant_device_required(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    enabled = [p for p in policies if p.get("state") == "enabled"]
    matching = [
        p for p in enabled
        if contains_value(safe_get(p, "grantControls", "builtInControls", default=[]), "compliantDevice")
    ]

    if matching:
        status = "pass"
        reason = "At least one enabled Conditional Access policy requires a compliant device."
        observed = f"{len(matching)} enabled CA policy/policies require compliant device."
    else:
        status = "fail"
        reason = "No enabled Conditional Access policy requiring compliant device was found."
        observed = "0 enabled CA policies with compliantDevice grant control found."

    return result(
        control_id="ID-06",
        title="Conditional Access requires compliant device",
        status=status,
        confidence="medium",
        reason=reason,
        expected="Conditional Access policy requires compliant device for applicable users/apps/platforms.",
        observed=observed,
        evidence={"matching_policies": [summarize_ca_policy(p) for p in matching]},
        remediation_hint="Create or update a CA policy with grant control 'Require device to be marked as compliant'.",
        notes="This does not prove all platforms/users are covered. Intune compliance policies must also exist and be assigned.",
    )


def evaluate_phishing_resistant_mfa_admins(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    enabled = [p for p in policies if p.get("state") == "enabled"]

    strength_policies = []
    role_mfa_no_strength = []

    for p in enabled:
        include_roles = safe_get(p, "conditions", "users", "includeRoles", default=[]) or []
        auth_strength = safe_get(p, "grantControls", "authenticationStrength", default=None)
        built_in = safe_get(p, "grantControls", "builtInControls", default=[]) or []

        if include_roles and auth_strength:
            strength_policies.append(p)
        elif include_roles and contains_value(built_in, "mfa"):
            role_mfa_no_strength.append(p)

    if strength_policies:
        status = "partial"
        reason = "Admin role-scoped CA policy uses authentication strength, but this check does not yet validate exact phishing-resistant strength ID."
        observed = f"{len(strength_policies)} admin role-scoped policy/policies with authentication strength found."
    elif role_mfa_no_strength:
        status = "partial"
        reason = "Admin roles require MFA, but no authentication strength requirement was detected."
        observed = f"{len(role_mfa_no_strength)} admin role-scoped MFA policy/policies found without authentication strength."
    else:
        status = "fail"
        reason = "No enabled admin role-scoped policy requiring phishing-resistant MFA or authentication strength was found."
        observed = "0 admin role-scoped authentication strength policies found."

    return result(
        control_id="ID-07",
        title="Conditional Access requires phishing-resistant MFA for admins",
        status=status,
        confidence="low",
        reason=reason,
        expected="Privileged roles require phishing-resistant authentication, such as FIDO2 or Windows Hello for Business.",
        observed=observed,
        evidence={
            "authentication_strength_policies": [summarize_ca_policy(p) for p in strength_policies],
            "role_mfa_without_strength": [summarize_ca_policy(p) for p in role_mfa_no_strength],
        },
        remediation_hint="Use Conditional Access authentication strengths for privileged roles and require phishing-resistant methods where feasible.",
        notes="Marked partial until exact authentication strength details are validated against tenant policy.",
    )


def evaluate_risk_policies(client: GraphClient) -> ControlResult:
    policies = client.list_all("identity/conditionalAccess/policies")
    enabled = [p for p in policies if p.get("state") == "enabled"]

    sign_in_risk = []
    user_risk = []

    for p in enabled:
        if safe_get(p, "conditions", "signInRiskLevels", default=[]):
            sign_in_risk.append(p)
        if safe_get(p, "conditions", "userRiskLevels", default=[]):
            user_risk.append(p)

    if sign_in_risk and user_risk:
        status = "pass"
        reason = "Enabled Conditional Access policies exist for both sign-in risk and user risk."
        observed = f"{len(sign_in_risk)} sign-in risk policy/policies and {len(user_risk)} user risk policy/policies found."
    elif sign_in_risk or user_risk:
        status = "partial"
        reason = "Risk-based Conditional Access exists, but either sign-in risk or user risk coverage is missing."
        observed = f"sign_in_risk_policy_count={len(sign_in_risk)}; user_risk_policy_count={len(user_risk)}"
    else:
        status = "fail"
        reason = "No enabled Conditional Access policies using sign-in risk or user risk were found."
        observed = "sign_in_risk_policy_count=0; user_risk_policy_count=0"

    return result(
        control_id="ID-08",
        title="Block high sign-in risk and force password reset on high user risk",
        status=status,
        confidence="medium",
        reason=reason,
        expected="Risk-based CA policies handle high sign-in risk and high user risk with block, MFA, or password reset controls.",
        observed=observed,
        evidence={
            "sign_in_risk_policies": [summarize_ca_policy(p) for p in sign_in_risk],
            "user_risk_policies": [summarize_ca_policy(p) for p in user_risk],
        },
        remediation_hint="Create/enable risk-based CA policies for high sign-in risk and high user risk. Validate grant controls and exclusions.",
    )


def evaluate_security_defaults_replaced(client: GraphClient) -> ControlResult:
    try:
        sec_defaults = client.get("policies/identitySecurityDefaultsEnforcementPolicy")
        is_enabled = bool(sec_defaults.get("isEnabled"))
    except Exception as exc:
        return result(
            control_id="ID-16",
            title="Security defaults disabled only if replaced by CA baseline",
            status="partial",
            confidence="low",
            reason="Could not read identity security defaults policy.",
            expected="Security defaults enabled, or disabled only when equivalent Conditional Access baseline policies exist.",
            observed=f"Graph query failed: {exc}",
            evidence={"error": str(exc)},
            remediation_hint="Verify permissions and tenant support for identitySecurityDefaultsEnforcementPolicy. Manually validate Security Defaults in Entra portal.",
        )

    policies = client.list_all("identity/conditionalAccess/policies")
    enabled_ca = [p for p in policies if p.get("state") == "enabled"]

    if is_enabled:
        status = "pass"
        reason = "Security defaults are enabled."
        observed = "securityDefaultsEnabled=true"
        remediation = None
    elif enabled_ca:
        status = "partial"
        reason = "Security defaults are disabled, but enabled Conditional Access policies exist. Equivalence requires review."
        observed = f"securityDefaultsEnabled=false; enabledCAPolicyCount={len(enabled_ca)}"
        remediation = "Validate that CA baseline covers MFA, admin protection, legacy authentication blocking, and risky sign-in handling."
    else:
        status = "fail"
        reason = "Security defaults are disabled and no enabled Conditional Access policies were found."
        observed = "securityDefaultsEnabled=false; enabledCAPolicyCount=0"
        remediation = "Enable Security Defaults or implement equivalent Conditional Access baseline policies."

    return result(
        control_id="ID-16",
        title="Security defaults disabled only if replaced by CA baseline",
        status=status,
        confidence="medium" if is_enabled else "low",
        reason=reason,
        expected="Security defaults enabled or disabled only with equivalent Conditional Access baseline.",
        observed=observed,
        evidence={
            "securityDefaultsEnabled": is_enabled,
            "enabledCAPolicyCount": len(enabled_ca),
            "enabledCAPolicies": [summarize_ca_policy(p) for p in enabled_ca[:25]],
        },
        remediation_hint=remediation,
    )

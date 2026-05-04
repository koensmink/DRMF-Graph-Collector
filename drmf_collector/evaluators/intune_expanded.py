from __future__ import annotations

from typing import Any

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result
from .helpers import compact_items, object_contains_any, try_list_all


def _get_intune_policy_inventory(client: GraphClient) -> dict[str, Any]:
    config_policies, config_policies_error = try_list_all(client, "deviceManagement/configurationPolicies")
    device_configs, device_configs_error = try_list_all(client, "deviceManagement/deviceConfigurations")
    intents, intents_error = try_list_all(client, "deviceManagement/intents")
    templates, templates_error = try_list_all(client, "deviceManagement/templates")

    all_policies = []
    for source, items in [
        ("configurationPolicies", config_policies),
        ("deviceConfigurations", device_configs),
        ("intents", intents),
        ("templates", templates),
    ]:
        for item in items:
            item_copy = dict(item)
            item_copy["_source"] = source
            all_policies.append(item_copy)

    return {
        "policies": all_policies,
        "counts": {
            "configurationPolicies": len(config_policies),
            "deviceConfigurations": len(device_configs),
            "intents": len(intents),
            "templates": len(templates),
        },
        "errors": {
            "configurationPolicies": config_policies_error,
            "deviceConfigurations": device_configs_error,
            "intents": intents_error,
            "templates": templates_error,
        },
    }


def _policy_sample(policies: list[dict[str, Any]], limit: int = 25) -> list[dict[str, Any]]:
    return compact_items(policies, ["id", "name", "displayName", "description", "platforms", "technologies", "_source"], limit)


def _evaluate_policy_presence(
    client: GraphClient,
    control_id: str,
    title: str,
    keywords: list[str],
    expected: str,
    remediation_hint: str,
    confidence: str = "low",
    notes: str | None = None,
) -> ControlResult:
    inventory = _get_intune_policy_inventory(client)
    matches = [p for p in inventory["policies"] if object_contains_any(p, keywords)]

    if matches:
        status = "partial"
        reason = "One or more Intune configuration objects matched the control keywords. Detailed setting-value validation still needs to be implemented."
        observed = f"matching_policy_count={len(matches)}"
    else:
        status = "fail"
        reason = "No Intune configuration object matching the control keywords was found."
        observed = "matching_policy_count=0"

    return result(
        control_id=control_id,
        title=title,
        status=status,
        confidence=confidence,
        reason=reason,
        expected=expected,
        observed=observed,
        evidence={
            "keywords": keywords,
            "matching_policy_count": len(matches),
            "matching_policy_sample": _policy_sample(matches),
            "inventory_counts": inventory["counts"],
            "errors": inventory["errors"],
        },
        remediation_hint=remediation_hint,
        notes=notes or "This is a policy-presence check. It does not yet parse individual Intune setting values.",
    )


def evaluate_mde_onboarding_coverage(client: GraphClient) -> ControlResult:
    devices, devices_error = try_list_all(
        client,
        "deviceManagement/managedDevices",
        params={"$select": "id,deviceName,operatingSystem,complianceState,managementAgent,manufacturer,model"},
    )
    windows_devices = [d for d in devices if (d.get("operatingSystem") or "").lower() == "windows"]

    inventory = _get_intune_policy_inventory(client)
    mde_policies = [
        p for p in inventory["policies"]
        if object_contains_any(p, ["defender for endpoint", "microsoft defender for endpoint", "mde", "endpoint detection", "onboarding"])
    ]

    if windows_devices and mde_policies:
        status = "partial"
        reason = "Windows managed devices and MDE-related policy evidence exist, but Graph did not prove per-device Defender onboarding health."
        observed = f"windows_managed_device_count={len(windows_devices)}; mde_policy_count={len(mde_policies)}"
        confidence = "low"
    elif windows_devices:
        status = "fail"
        reason = "Windows managed devices exist, but no MDE-related Intune policy was found."
        observed = f"windows_managed_device_count={len(windows_devices)}; mde_policy_count=0"
        confidence = "medium"
    else:
        status = "partial"
        reason = "No Windows managed devices were returned, so onboarding coverage cannot be assessed."
        observed = "windows_managed_device_count=0"
        confidence = "low"

    return result(
        control_id="EP-01",
        title="Microsoft Defender for Endpoint onboarded for all supported endpoints",
        status=status,
        confidence=confidence,
        reason=reason,
        expected="All supported endpoints are onboarded to Microsoft Defender for Endpoint and visible/healthy in the endpoint inventory.",
        observed=observed,
        evidence={
            "managed_device_count": len(devices),
            "windows_managed_device_count": len(windows_devices),
            "mde_policy_count": len(mde_policies),
            "mde_policy_sample": _policy_sample(mde_policies),
            "managed_device_error": devices_error,
            "inventory_errors": inventory["errors"],
        },
        remediation_hint="Validate MDE onboarding policies in Intune and confirm endpoint sensor health in Defender XDR.",
        notes="Defender XDR device inventory is the stronger source for actual onboarding and sensor health.",
    )


def evaluate_asr_rules_block(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-03",
        "Attack Surface Reduction rules: critical set in Block",
        ["attack surface reduction", "asr", "defender attack surface", "block abuse", "block executable", "block credential"],
        "Critical ASR rules are deployed in Block mode to in-scope Windows endpoints.",
        "Create or update Intune Endpoint Security ASR policy and set critical rules to Block where business-compatible.",
    )


def evaluate_laps_policy(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-06",
        "Windows LAPS enabled and deployed",
        ["laps", "local admin password solution", "administrator password"],
        "Windows LAPS policy is configured and assigned to in-scope Windows endpoints.",
        "Create or assign Windows LAPS policy via Intune Account Protection and validate password backup.",
    )


def evaluate_local_admin_restrictions(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-07",
        "Local admin restrictions implemented",
        ["local users and groups", "local user group membership", "administrators", "account protection", "local admin"],
        "Local administrator membership is centrally governed and restricted.",
        "Use Intune Account Protection / Local users and groups to enforce approved local admin membership.",
    )


def evaluate_device_compliance_policies(client: GraphClient) -> ControlResult:
    compliance_policies, compliance_error = try_list_all(client, "deviceManagement/deviceCompliancePolicies")
    devices, devices_error = try_list_all(
        client,
        "deviceManagement/managedDevices",
        params={"$select": "id,deviceName,operatingSystem,complianceState"},
    )
    non_compliant = [d for d in devices if str(d.get("complianceState", "")).lower() == "noncompliant"]

    if compliance_policies and devices:
        status = "partial"
        reason = "Compliance policies and managed devices were found; CA enforcement must be correlated separately."
        observed = f"compliance_policy_count={len(compliance_policies)}; managed_device_count={len(devices)}; non_compliant_count={len(non_compliant)}"
        confidence = "medium"
    elif compliance_policies:
        status = "partial"
        reason = "Compliance policies exist, but no managed device inventory was returned."
        observed = f"compliance_policy_count={len(compliance_policies)}; managed_device_count=0"
        confidence = "low"
    else:
        status = "fail"
        reason = "No Intune device compliance policies were found."
        observed = "compliance_policy_count=0"
        confidence = "medium"

    return result(
        control_id="EP-08",
        title="Intune compliance policies defined and enforced via Conditional Access",
        status=status,
        confidence=confidence,
        reason=reason,
        expected="Compliance policies exist for in-scope platforms and are enforced through Conditional Access where applicable.",
        observed=observed,
        evidence={
            "compliance_policy_count": len(compliance_policies),
            "managed_device_count": len(devices),
            "non_compliant_device_count": len(non_compliant),
            "compliance_policy_sample": compact_items(compliance_policies, ["id", "displayName", "description", "version"], 25),
            "non_compliant_device_sample": compact_items(non_compliant, ["id", "deviceName", "operatingSystem", "complianceState"], 25),
            "errors": {
                "deviceCompliancePolicies": compliance_error,
                "managedDevices": devices_error,
            },
        },
        remediation_hint="Create compliance policies per platform and enforce them with Conditional Access grant control 'Require compliant device'.",
        notes="This check validates Intune compliance evidence, not full Conditional Access coverage.",
    )


def evaluate_firewall_managed(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-09",
        "Endpoint firewall enabled and centrally managed",
        ["firewall", "defender firewall", "windows firewall"],
        "Microsoft Defender Firewall is enabled and centrally managed through Intune.",
        "Create or assign Endpoint Security Firewall policy for in-scope Windows endpoints.",
    )


def evaluate_network_web_protection(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-10",
        "Defender web protection / network protection enabled",
        ["network protection", "web protection", "enable network protection", "defender network"],
        "Defender Network Protection/Web Protection is enabled in Block mode where appropriate.",
        "Create or assign Intune policy for Defender Network Protection and validate MDE enforcement.",
    )


def evaluate_device_control(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-11",
        "Device control: USB restrictions for unmanaged media",
        ["device control", "removable storage", "usb", "storage device"],
        "USB/removable media restrictions are configured for unmanaged or high-risk media where required.",
        "Create or assign Defender Device Control / removable storage policy in Intune.",
    )


def evaluate_update_rings(client: GraphClient) -> ControlResult:
    update_configs, update_configs_error = try_list_all(client, "deviceManagement/deviceConfigurations")
    wufb, wufb_error = try_list_all(client, "deviceManagement/windowsUpdateForBusinessConfigurations")
    feature, feature_error = try_list_all(client, "deviceManagement/windowsFeatureUpdateProfiles")
    quality, quality_error = try_list_all(client, "deviceManagement/windowsQualityUpdateProfiles")

    update_like = [
        p for p in update_configs
        if object_contains_any(p, ["update", "windows update", "quality update", "feature update"])
    ]

    count = len(wufb) + len(feature) + len(quality) + len(update_like)

    if count:
        status = "partial"
        reason = "Windows update configuration evidence was found; monitoring/remediation status still requires report data."
        observed = f"update_policy_count={count}"
    else:
        status = "fail"
        reason = "No Windows update ring or update profile evidence was found."
        observed = "update_policy_count=0"

    return result(
        control_id="EP-12",
        title="OS update rings configured and monitored",
        status=status,
        confidence="medium" if count else "low",
        reason=reason,
        expected="OS update rings/profiles are configured for in-scope platforms and monitored for deployment compliance.",
        observed=observed,
        evidence={
            "windowsUpdateForBusinessConfiguration_count": len(wufb),
            "windowsFeatureUpdateProfile_count": len(feature),
            "windowsQualityUpdateProfile_count": len(quality),
            "update_like_device_configuration_count": len(update_like),
            "policy_sample": compact_items(wufb + feature + quality + update_like, ["id", "displayName", "description"], 25),
            "errors": {
                "deviceConfigurations": update_configs_error,
                "windowsUpdateForBusinessConfigurations": wufb_error,
                "windowsFeatureUpdateProfiles": feature_error,
                "windowsQualityUpdateProfiles": quality_error,
            },
        },
        remediation_hint="Configure Windows update rings, feature update profiles, and quality update policies. Add reporting for failed/stale update states.",
        notes="Android/iOS update policy coverage is not yet implemented in this evaluator.",
    )


def evaluate_defender_av_cloud_protection(client: GraphClient) -> ControlResult:
    return _evaluate_policy_presence(
        client,
        "EP-15",
        "Defender Antivirus cloud protection + high cloud block level",
        ["cloud protection", "cloud-delivered protection", "block at first sight", "cloud block", "defender antivirus", "antivirus"],
        "Defender Antivirus cloud protection and appropriate cloud block level are enforced.",
        "Configure Defender Antivirus policy in Intune with cloud-delivered protection and high cloud block level where appropriate.",
    )


def evaluate_security_baselines(client: GraphClient) -> ControlResult:
    inventory = _get_intune_policy_inventory(client)
    baseline_like = [
        p for p in inventory["policies"]
        if object_contains_any(p, ["baseline", "security baseline", "microsoft security baseline", "defender for endpoint baseline"])
    ]

    if baseline_like:
        status = "partial"
        reason = "Security baseline-like Intune objects were found; assignment and setting compliance require deeper validation."
        observed = f"baseline_policy_count={len(baseline_like)}"
    else:
        status = "fail"
        reason = "No Intune security baseline-like objects were found."
        observed = "baseline_policy_count=0"

    return result(
        control_id="EP-16",
        title="Device configuration baseline applied",
        status=status,
        confidence="low",
        reason=reason,
        expected="Microsoft/CIS-aligned security baselines are applied to in-scope devices and monitored for compliance.",
        observed=observed,
        evidence={
            "baseline_policy_count": len(baseline_like),
            "baseline_policy_sample": _policy_sample(baseline_like),
            "inventory_counts": inventory["counts"],
            "errors": inventory["errors"],
        },
        remediation_hint="Assign Microsoft security baseline or equivalent CIS-aligned configuration profiles and monitor device/profile compliance.",
        notes="This check detects baseline-like objects only; it does not compare individual baseline settings.",
    )


def evaluate_mam_byod(client: GraphClient) -> ControlResult:
    managed_app_policies, policies_error = try_list_all(client, "deviceAppManagement/managedAppPolicies")
    app_configs, app_configs_error = try_list_all(client, "deviceAppManagement/mobileAppConfigurations")
    registrations, registrations_error = try_list_all(client, "deviceAppManagement/managedAppRegistrations")

    if managed_app_policies:
        status = "partial"
        reason = "Managed app protection policy evidence exists; BYOD scope and app assignment must still be validated."
        observed = f"managed_app_policy_count={len(managed_app_policies)}; managed_app_registration_count={len(registrations)}"
        confidence = "medium"
    else:
        status = "fail"
        reason = "No Intune managed app protection policies were found."
        observed = "managed_app_policy_count=0"
        confidence = "medium"

    return result(
        control_id="EP-17",
        title="Mobile Application Management for BYOD",
        status=status,
        confidence=confidence,
        reason=reason,
        expected="MAM app protection policies are configured for BYOD/mobile access where applicable.",
        observed=observed,
        evidence={
            "managed_app_policy_count": len(managed_app_policies),
            "mobile_app_configuration_count": len(app_configs),
            "managed_app_registration_count": len(registrations),
            "managed_app_policy_sample": compact_items(managed_app_policies, ["id", "displayName", "description"], 25),
            "errors": {
                "managedAppPolicies": policies_error,
                "mobileAppConfigurations": app_configs_error,
                "managedAppRegistrations": registrations_error,
            },
        },
        remediation_hint="Create and assign Intune App Protection Policies for unmanaged/BYOD mobile access to Microsoft 365 apps.",
    )

from __future__ import annotations

import os
from typing import Any, Dict, Callable

from ..clients.arm_client import ArmClient
from ..models import ControlResult
from ..utils import result


def _arm_result(
    control_id: str,
    title: str,
    status: str,
    confidence: str,
    reason: str,
    expected: str,
    observed: str,
    evidence: Dict[str, Any],
    remediation_hint: str | None = None,
    notes: str | None = None,
) -> ControlResult:
    return result(
        control_id=control_id,
        title=title,
        status=status,
        confidence=confidence,
        reason=reason,
        expected=expected,
        observed=observed,
        evidence=evidence,
        remediation_hint=remediation_hint,
        notes=notes,
        source="arm",
    )


def _safe_call(label: str, func: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return func(), None
    except Exception as exc:  # noqa: BLE001
        return None, f"{label}: {exc}"


def _safe_list(label: str, func: Callable[[], Any]) -> tuple[list[dict[str, Any]], str | None]:
    data, error = _safe_call(label, func)
    if error:
        return [], error
    if isinstance(data, list):
        return data, None
    return [], f"{label}: response was not a list"


def _subscription_ids(client: ArmClient) -> tuple[list[str], str | None]:
    subscriptions, error = _safe_call("list_subscription_ids", client.list_subscription_ids)
    if error:
        return [], error
    return subscriptions or [], None


def _compact_resources(resources: list[dict[str, Any]], limit: int = 25) -> list[dict[str, Any]]:
    output = []
    for item in resources[:limit]:
        resource_id = item.get("id", "")
        output.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "type": item.get("type"),
                "location": item.get("location"),
                "resourceGroup": resource_id.split("/resourceGroups/")[1].split("/")[0]
                if "/resourceGroups/" in resource_id
                else None,
            }
        )
    return output


def evaluate_defender_for_cloud_plans(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    pricing_by_subscription: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        pricings, error = _safe_list(
            f"security_pricings:{subscription_id}",
            lambda sid=subscription_id: client.list_all(
                f"/subscriptions/{sid}/providers/Microsoft.Security/pricings",
                api_version="2024-01-01",
            ),
        )
        pricing_by_subscription[subscription_id] = pricings
        if error:
            errors[subscription_id] = error

    enabled_summary = {}
    disabled_or_free = []

    for subscription_id, pricings in pricing_by_subscription.items():
        enabled = []
        for item in pricings:
            props = item.get("properties") or {}
            entry = {
                "name": item.get("name"),
                "pricingTier": props.get("pricingTier"),
                "subPlan": props.get("subPlan"),
            }
            if str(entry["pricingTier"]).lower() == "standard":
                enabled.append(entry)
            else:
                disabled_or_free.append({"subscriptionId": subscription_id, **entry})
        enabled_summary[subscription_id] = enabled

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif errors and len(errors) == len(subscription_ids):
        status, reason, confidence = "error", "Defender for Cloud pricing endpoints could not be read for any subscription.", "low"
    elif disabled_or_free:
        status, reason, confidence = "partial", "Some Defender for Cloud plan entries are not set to Standard or could not be confirmed.", "medium"
    else:
        status, reason, confidence = "pass", "Defender for Cloud pricing entries are set to Standard for observed subscriptions.", "medium"

    return _arm_result(
        "AZ-01",
        "Defender for Cloud enabled on all subscriptions",
        status,
        confidence,
        reason,
        "Required Microsoft Defender for Cloud plans are enabled and scoped for all in-scope subscriptions.",
        f"subscription_count={len(subscription_ids)}; disabled_or_free_plan_count={len(disabled_or_free)}; error_count={len(errors)}",
        {
            "subscription_ids": subscription_ids,
            "enabled_plans_by_subscription": enabled_summary,
            "disabled_or_free_plans": disabled_or_free[:50],
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Enable required Microsoft Defender for Cloud plans per subscription. Validate plan scope, subplans and exclusions.",
        "This validates pricing tiers. It does not validate every plan's operational configuration or recommendation health.",
    )


def evaluate_azure_policy_assignments(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    assignments_by_subscription: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        assignments, error = _safe_list(
            f"policy_assignments:{subscription_id}",
            lambda sid=subscription_id: client.list_all(
                f"/subscriptions/{sid}/providers/Microsoft.Authorization/policyAssignments",
                api_version="2022-06-01",
            ),
        )
        assignments_by_subscription[subscription_id] = assignments
        if error:
            errors[subscription_id] = error

    total = sum(len(items) for items in assignments_by_subscription.values())
    initiative_like = [
        assignment
        for items in assignments_by_subscription.values()
        for assignment in items
        if "policySetDefinitions" in str((assignment.get("properties") or {}).get("policyDefinitionId", ""))
    ]

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif total == 0 and errors:
        status, reason, confidence = "error", "Azure Policy assignments could not be read or none were returned.", "low"
    elif total == 0:
        status, reason, confidence = "fail", "No Azure Policy assignments were found on observed subscriptions.", "medium"
    elif initiative_like:
        status, reason, confidence = "pass", "Azure Policy assignments exist, including initiative/policy set assignments.", "medium"
    else:
        status, reason, confidence = "partial", "Azure Policy assignments exist, but no initiative/policy set assignments were detected.", "medium"

    sample = []
    for subscription_id, assignments in assignments_by_subscription.items():
        for assignment in assignments[:25]:
            props = assignment.get("properties") or {}
            sample.append(
                {
                    "subscriptionId": subscription_id,
                    "id": assignment.get("id"),
                    "name": assignment.get("name"),
                    "displayName": props.get("displayName"),
                    "scope": props.get("scope"),
                    "policyDefinitionId": props.get("policyDefinitionId"),
                    "enforcementMode": props.get("enforcementMode"),
                }
            )

    return _arm_result(
        "AZ-02",
        "Azure Policy initiatives assigned",
        status,
        confidence,
        reason,
        "Security baseline, tagging, allowed locations and governance initiatives are assigned at subscription or management group scope.",
        f"subscription_count={len(subscription_ids)}; policy_assignment_count={total}; initiative_assignment_count={len(initiative_like)}; error_count={len(errors)}",
        {
            "subscription_ids": subscription_ids,
            "policy_assignment_count": total,
            "initiative_assignment_count": len(initiative_like),
            "assignment_sample": sample[:50],
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Assign relevant Azure Policy initiatives for security baseline, logging, tagging, location restrictions and regulatory compliance.",
        "This checks assignment presence. It does not yet validate compliance state or initiative quality.",
    )


def evaluate_public_ip_usage(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)
    all_public_ips = []
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        resources, error = _safe_list(
            f"public_ips:{subscription_id}",
            lambda sid=subscription_id: client.list_resources_by_type(sid, "Microsoft.Network/publicIPAddresses"),
        )
        if error:
            errors[subscription_id] = error
        for item in resources:
            item["_subscriptionId"] = subscription_id
        all_public_ips.extend(resources)

    unattached = [ip for ip in all_public_ips if not ((ip.get("properties") or {}).get("ipConfiguration"))]
    static_ips = [
        ip
        for ip in all_public_ips
        if str(((ip.get("properties") or {}).get("publicIPAllocationMethod"))).lower() == "static"
    ]

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif errors and len(errors) == len(subscription_ids):
        status, reason, confidence = "error", "Public IP resources could not be read for any subscription.", "low"
    elif len(all_public_ips) == 0:
        status, reason, confidence = "pass", "No Public IP resources were found in observed subscriptions.", "medium"
    else:
        status, reason, confidence = "partial", "Public IP resources exist and require documented exposure review.", "medium"

    return _arm_result(
        "AZ-03",
        "Public IP usage minimized and documented",
        status,
        confidence,
        reason,
        "Public IP usage is minimized, justified and documented; unattached public IPs are removed.",
        f"public_ip_count={len(all_public_ips)}; unattached_public_ip_count={len(unattached)}; static_public_ip_count={len(static_ips)}",
        {
            "subscription_ids": subscription_ids,
            "public_ip_count": len(all_public_ips),
            "unattached_public_ip_count": len(unattached),
            "static_public_ip_count": len(static_ips),
            "public_ip_sample": _compact_resources(all_public_ips, 50),
            "unattached_public_ip_sample": _compact_resources(unattached, 50),
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Review all Public IP resources, remove unattached IPs, and document justified internet exposure.",
        "This does not prove whether attached resources are securely configured. NSG/firewall review is separate.",
    )


def evaluate_private_endpoints(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    private_endpoints = []
    paas_candidates = []
    errors: dict[str, str] = {}

    candidate_types = {
        "Microsoft.Storage/storageAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Sql/servers",
        "Microsoft.DocumentDB/databaseAccounts",
        "Microsoft.ContainerRegistry/registries",
    }

    for subscription_id in subscription_ids:
        pe_resources, pe_error = _safe_list(
            f"private_endpoints:{subscription_id}",
            lambda sid=subscription_id: client.list_resources_by_type(sid, "Microsoft.Network/privateEndpoints"),
        )
        if pe_error:
            errors[f"{subscription_id}:privateEndpoints"] = pe_error

        for item in pe_resources:
            item["_subscriptionId"] = subscription_id
        private_endpoints.extend(pe_resources)

        resources, resource_error = _safe_list(
            f"resources:{subscription_id}",
            lambda sid=subscription_id: client.list_resources(sid),
        )
        if resource_error:
            errors[f"{subscription_id}:resources"] = resource_error

        for item in resources:
            if item.get("type") in candidate_types:
                item["_subscriptionId"] = subscription_id
                paas_candidates.append(item)

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif private_endpoints:
        status, reason, confidence = "partial", "Private Endpoints exist, but per-PaaS coverage still requires resource-level mapping.", "medium"
    elif paas_candidates:
        status, reason, confidence = "fail", "PaaS resources exist but no Private Endpoints were found.", "medium"
    else:
        status, reason, confidence = "partial", "No Private Endpoints or tracked PaaS candidates were found.", "low"

    return _arm_result(
        "AZ-04",
        "Private Endpoints used for PaaS where feasible",
        status,
        confidence,
        reason,
        "Critical PaaS resources use Private Endpoints where feasible, with public network access restricted.",
        f"private_endpoint_count={len(private_endpoints)}; paas_candidate_count={len(paas_candidates)}",
        {
            "subscription_ids": subscription_ids,
            "private_endpoint_count": len(private_endpoints),
            "paas_candidate_count": len(paas_candidates),
            "private_endpoint_sample": _compact_resources(private_endpoints, 50),
            "paas_candidate_sample": _compact_resources(paas_candidates, 50),
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Map critical PaaS resources to Private Endpoints and restrict public network access where feasible.",
        "Coverage is approximate until each PaaS resource is mapped to private endpoint connections and public network access settings.",
    )


def evaluate_key_vault_hardening(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    vaults = []
    enriched_vaults = []
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        resources, error = _safe_list(
            f"key_vaults:{subscription_id}",
            lambda sid=subscription_id: client.list_resources_by_type(sid, "Microsoft.KeyVault/vaults"),
        )
        if error:
            errors[subscription_id] = error
        vaults.extend(resources)

    for vault in vaults:
        vault_id = vault.get("id")
        if not vault_id:
            continue

        detail, error = _safe_call(
            f"key_vault_detail:{vault_id}",
            lambda rid=vault_id: client.get_resource_by_id(rid, api_version="2023-07-01"),
        )

        if error:
            errors[vault_id] = error
            continue

        props = detail.get("properties") or {}
        enriched_vaults.append(
            {
                "id": detail.get("id"),
                "name": detail.get("name"),
                "location": detail.get("location"),
                "enableRbacAuthorization": props.get("enableRbacAuthorization"),
                "enableSoftDelete": props.get("enableSoftDelete"),
                "softDeleteRetentionInDays": props.get("softDeleteRetentionInDays"),
                "enablePurgeProtection": props.get("enablePurgeProtection"),
                "publicNetworkAccess": props.get("publicNetworkAccess"),
            }
        )

    non_compliant = [
        vault
        for vault in enriched_vaults
        if vault.get("enableRbacAuthorization") is not True
        or vault.get("enablePurgeProtection") is not True
        or vault.get("enableSoftDelete") is False
    ]

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif not vaults and errors:
        status, reason, confidence = "error", "Key Vault resources could not be read.", "low"
    elif not vaults:
        status, reason, confidence = "pass", "No Key Vault resources were found in observed subscriptions.", "medium"
    elif non_compliant:
        status, reason, confidence = "fail", "One or more Key Vaults do not meet RBAC, soft delete or purge protection expectations.", "high"
    else:
        status, reason, confidence = "pass", "Observed Key Vaults meet RBAC, soft delete and purge protection expectations.", "high"

    return _arm_result(
        "AZ-05",
        "Key Vault RBAC, soft delete and purge protection enabled",
        status,
        confidence,
        reason,
        "Key Vaults use Azure RBAC authorization and have soft delete and purge protection enabled.",
        f"key_vault_count={len(vaults)}; non_compliant_key_vault_count={len(non_compliant)}; error_count={len(errors)}",
        {
            "subscription_ids": subscription_ids,
            "key_vault_count": len(vaults),
            "vaults": enriched_vaults[:50],
            "non_compliant_vaults": non_compliant[:50],
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Enable Azure RBAC authorization, soft delete and purge protection on Key Vaults. Review public network access separately.",
    )


def evaluate_storage_account_hardening(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    storage_accounts = []
    enriched = []
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        resources, error = _safe_list(
            f"storage_accounts:{subscription_id}",
            lambda sid=subscription_id: client.list_resources_by_type(sid, "Microsoft.Storage/storageAccounts"),
        )
        if error:
            errors[subscription_id] = error
        storage_accounts.extend(resources)

    for account in storage_accounts:
        account_id = account.get("id")
        if not account_id:
            continue

        detail, error = _safe_call(
            f"storage_account_detail:{account_id}",
            lambda rid=account_id: client.get_resource_by_id(rid, api_version="2023-01-01"),
        )

        if error:
            errors[account_id] = error
            continue

        props = detail.get("properties") or {}
        enriched.append(
            {
                "id": detail.get("id"),
                "name": detail.get("name"),
                "location": detail.get("location"),
                "supportsHttpsTrafficOnly": props.get("supportsHttpsTrafficOnly"),
                "allowBlobPublicAccess": props.get("allowBlobPublicAccess"),
                "minimumTlsVersion": props.get("minimumTlsVersion"),
                "publicNetworkAccess": props.get("publicNetworkAccess"),
                "allowSharedKeyAccess": props.get("allowSharedKeyAccess"),
            }
        )

    weak = [
        account
        for account in enriched
        if account.get("supportsHttpsTrafficOnly") is not True
        or account.get("allowBlobPublicAccess") is True
        or str(account.get("minimumTlsVersion") or "").upper() in {"TLS1_0", "TLS1_1", ""}
    ]

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif not storage_accounts and errors:
        status, reason, confidence = "error", "Storage accounts could not be read.", "low"
    elif not storage_accounts:
        status, reason, confidence = "pass", "No Storage Accounts were found in observed subscriptions.", "medium"
    elif weak:
        status, reason, confidence = "fail", "One or more Storage Accounts do not meet basic hardening expectations.", "high"
    else:
        status, reason, confidence = "pass", "Observed Storage Accounts meet basic hardening expectations.", "high"

    return _arm_result(
        "AZ-06",
        "Storage accounts hardened",
        status,
        confidence,
        reason,
        "Storage accounts require secure transfer, disable blob public access and enforce modern TLS.",
        f"storage_account_count={len(storage_accounts)}; weak_storage_account_count={len(weak)}; error_count={len(errors)}",
        {
            "subscription_ids": subscription_ids,
            "storage_account_count": len(storage_accounts),
            "storage_accounts": enriched[:50],
            "weak_storage_accounts": weak[:50],
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Require secure transfer, disable blob public access, enforce TLS 1.2+, and review public network/shared key access.",
        "This does not yet validate Defender for Storage, lifecycle management or private endpoint coverage.",
    )


def evaluate_resource_diagnostic_settings(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    critical_types = {
        "Microsoft.KeyVault/vaults",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.Sql/servers",
    }

    resources = []
    checked = []
    without_diagnostics = []
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        sub_resources, error = _safe_list(
            f"resources:{subscription_id}",
            lambda sid=subscription_id: client.list_resources(sid),
        )
        if error:
            errors[f"{subscription_id}:resources"] = error

        for item in sub_resources:
            if item.get("type") in critical_types:
                resources.append(item)

    max_checks = int(os.getenv("AZURE_DIAGNOSTIC_MAX_RESOURCE_CHECKS", "100"))

    for item in resources[:max_checks]:
        resource_id = item.get("id")
        if not resource_id:
            continue

        settings, error = _safe_list(
            f"diagnostic_settings:{resource_id}",
            lambda rid=resource_id: client.list_diagnostic_settings(rid),
        )

        entry = {
            "id": resource_id,
            "name": item.get("name"),
            "type": item.get("type"),
            "diagnostic_setting_count": len(settings),
            "destinations": [
                {
                    "workspaceId": (setting.get("properties") or {}).get("workspaceId"),
                    "eventHubAuthorizationRuleId": (setting.get("properties") or {}).get("eventHubAuthorizationRuleId"),
                    "storageAccountId": (setting.get("properties") or {}).get("storageAccountId"),
                }
                for setting in settings
            ],
        }
        checked.append(entry)

        if error:
            errors[resource_id] = error
        elif len(settings) == 0:
            without_diagnostics.append(entry)

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif not resources and errors:
        status, reason, confidence = "error", "Critical resources or diagnostic settings could not be read.", "low"
    elif not resources:
        status, reason, confidence = "partial", "No tracked critical resource types were found.", "low"
    elif without_diagnostics:
        status, reason, confidence = "fail", "One or more checked critical resources do not have diagnostic settings.", "medium"
    else:
        status, reason, confidence = "pass", "Checked critical resources have diagnostic settings configured.", "medium"

    return _arm_result(
        "AZ-07",
        "Resource diagnostics enabled for critical services",
        status,
        confidence,
        reason,
        "Critical Azure resources send diagnostics to a central Log Analytics workspace, Event Hub or Storage Account.",
        f"critical_resource_count={len(resources)}; checked_count={len(checked)}; without_diagnostics_count={len(without_diagnostics)}; error_count={len(errors)}",
        {
            "subscription_ids": subscription_ids,
            "critical_resource_types": sorted(critical_types),
            "critical_resource_count": len(resources),
            "checked_count": len(checked),
            "max_checks": max_checks,
            "checked_sample": checked[:50],
            "without_diagnostics_sample": without_diagnostics[:50],
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Enable diagnostic settings for Key Vault, Storage and SQL resources and forward security-relevant logs to the central workspace.",
        "Diagnostic settings API is checked per resource and can be slow. Use AZURE_DIAGNOSTIC_MAX_RESOURCE_CHECKS to cap runtime.",
    )


def evaluate_activity_log_diagnostics(client: ArmClient | None = None) -> ControlResult:
    client = client or ArmClient.from_env()
    subscription_ids, sub_error = _subscription_ids(client)

    settings_by_subscription = {}
    missing = []
    errors: dict[str, str] = {}

    for subscription_id in subscription_ids:
        settings, error = _safe_list(
            f"subscription_diagnostic_settings:{subscription_id}",
            lambda sid=subscription_id: client.list_all(
                f"/subscriptions/{sid}/providers/Microsoft.Insights/diagnosticSettings",
                api_version="2021-05-01-preview",
            ),
        )
        settings_by_subscription[subscription_id] = settings

        if error:
            errors[subscription_id] = error
        elif len(settings) == 0:
            missing.append(subscription_id)

    if not subscription_ids:
        status, reason, confidence = "error", "No Azure subscriptions could be enumerated.", "low"
    elif errors and len(errors) == len(subscription_ids):
        status, reason, confidence = "error", "Subscription-level diagnostic settings could not be read.", "low"
    elif missing:
        status, reason, confidence = "fail", "One or more subscriptions do not have subscription-level diagnostic settings.", "medium"
    else:
        status, reason, confidence = "pass", "Subscription-level diagnostic settings exist for observed subscriptions.", "medium"

    sample = {
        subscription_id: [
            {
                "id": setting.get("id"),
                "name": setting.get("name"),
                "workspaceId": (setting.get("properties") or {}).get("workspaceId"),
                "eventHubAuthorizationRuleId": (setting.get("properties") or {}).get("eventHubAuthorizationRuleId"),
                "storageAccountId": (setting.get("properties") or {}).get("storageAccountId"),
            }
            for setting in settings[:10]
        ]
        for subscription_id, settings in settings_by_subscription.items()
    }

    return _arm_result(
        "AZ-08",
        "Activity Logs forwarded to central workspace",
        status,
        confidence,
        reason,
        "Azure Activity Logs are exported through subscription-level diagnostic settings to central logging.",
        f"subscription_count={len(subscription_ids)}; subscriptions_without_settings={len(missing)}; error_count={len(errors)}",
        {
            "subscription_ids": subscription_ids,
            "subscriptions_without_diagnostic_settings": missing,
            "settings_by_subscription_sample": sample,
            "errors": errors,
            "subscription_error": sub_error,
        },
        "Create subscription-level diagnostic settings for Activity Logs and send them to the central Log Analytics workspace, Event Hub or Storage Account.",
    )


AZURE_EVALUATORS = [
    evaluate_defender_for_cloud_plans,
    evaluate_azure_policy_assignments,
    evaluate_public_ip_usage,
    evaluate_private_endpoints,
    evaluate_key_vault_hardening,
    evaluate_storage_account_hardening,
    evaluate_resource_diagnostic_settings,
    evaluate_activity_log_diagnostics,
]

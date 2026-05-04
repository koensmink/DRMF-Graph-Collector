from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result
from .helpers import compact_items, try_list_all


HIGH_RISK_APP_PERMISSION_HINTS = [
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
]


def evaluate_oauth_app_governance(client: GraphClient) -> ControlResult:
    applications, app_error = try_list_all(
        client,
        "applications",
        params={"$select": "id,displayName,appId,requiredResourceAccess"},
    )
    service_principals, sp_error = try_list_all(
        client,
        "servicePrincipals",
        params={"$select": "id,displayName,appId,appRoleAssignmentRequired,accountEnabled"},
    )
    access_reviews, ar_error = try_list_all("identityGovernance/accessReviews/definitions") if False else ([], None)
    try:
        access_reviews = client.list_all("identityGovernance/accessReviews/definitions")
    except Exception as exc:  # noqa: BLE001
        ar_error = str(exc)
        access_reviews = []

    apps_with_required_access = [
        app for app in applications
        if app.get("requiredResourceAccess")
    ]
    sps_requiring_assignment = [
        sp for sp in service_principals
        if sp.get("appRoleAssignmentRequired") is True
    ]

    review_like = [
        review for review in access_reviews
        if "app" in str(review).lower() or "serviceprincipal" in str(review).lower() or "service principal" in str(review).lower()
    ]

    if applications and access_reviews and sps_requiring_assignment:
        status = "partial"
        reason = "Application inventory, service principals requiring assignment, and Access Review definitions were found; risky permission review still needs deeper consent-grant analysis."
        observed = f"applications={len(applications)}; servicePrincipals={len(service_principals)}; accessReviews={len(access_reviews)}; appRoleAssignmentRequired={len(sps_requiring_assignment)}"
        confidence = "medium"
    elif applications:
        status = "partial"
        reason = "Application inventory exists, but evidence for periodic app permission review or assignment enforcement is incomplete."
        observed = f"applications={len(applications)}; servicePrincipals={len(service_principals)}; accessReviews={len(access_reviews)}"
        confidence = "low"
    else:
        status = "fail"
        reason = "No application registration inventory was returned by Graph."
        observed = "applications=0"
        confidence = "low"

    return result(
        control_id="ID-12",
        title="OAuth app governance: restrict risky permissions + periodic review",
        status=status,
        confidence=confidence,
        reason=reason,
        expected="Application permissions are governed, risky permissions require admin approval, and apps/service principals are periodically reviewed.",
        observed=observed,
        evidence={
            "application_count": len(applications),
            "applications_with_required_resource_access": len(apps_with_required_access),
            "service_principal_count": len(service_principals),
            "service_principals_requiring_assignment": len(sps_requiring_assignment),
            "access_review_definition_count": len(access_reviews),
            "app_related_access_review_count": len(review_like),
            "application_sample": compact_items(applications, ["id", "displayName", "appId"], 25),
            "service_principal_assignment_required_sample": compact_items(sps_requiring_assignment, ["id", "displayName", "appId", "appRoleAssignmentRequired"], 25),
            "errors": {
                "applications": app_error,
                "servicePrincipals": sp_error,
                "accessReviews": ar_error,
            },
        },
        remediation_hint="Restrict user consent, require admin consent for high-risk permissions, enable admin consent workflow, and schedule periodic access reviews for enterprise apps/service principals.",
        notes="This check is intentionally partial until oauth2PermissionGrants/appRoleAssignments are added for full permission-risk scoring.",
    )

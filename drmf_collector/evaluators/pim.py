from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result
from .helpers import compact_items, try_list_all


PRIVILEGED_ROLE_KEYWORDS = [
    "global administrator",
    "privileged role administrator",
    "authentication administrator",
    "privileged authentication administrator",
    "security administrator",
    "conditional access administrator",
    "exchange administrator",
    "sharepoint administrator",
    "intune administrator",
    "cloud application administrator",
    "application administrator",
]


def evaluate_pim_privileged_roles(client: GraphClient) -> ControlResult:
    assignments, assignment_error = try_list_all(client, "policies/roleManagementPolicyAssignments")
    eligible, eligible_error = try_list_all(client, "roleManagement/directory/roleEligibilityScheduleInstances")
    active, active_error = try_list_all(client, "roleManagement/directory/roleAssignmentScheduleInstances")

    eligible_count = len(eligible)
    active_count = len(active)
    assignment_count = len(assignments)

    if assignment_count and eligible_count:
        status = "partial"
        reason = "PIM role management policy assignments and eligible role assignments were found, but role-by-role completeness still requires validation."
        observed = f"roleManagementPolicyAssignments={assignment_count}; eligibleAssignments={eligible_count}; activeAssignments={active_count}"
        confidence = "medium"
    elif assignment_count or eligible_count:
        status = "partial"
        reason = "Some PIM evidence exists, but the collector did not observe both policy assignments and eligible role assignments."
        observed = f"roleManagementPolicyAssignments={assignment_count}; eligibleAssignments={eligible_count}; activeAssignments={active_count}"
        confidence = "low"
    else:
        status = "fail"
        reason = "No PIM policy assignments or eligible role assignments were found through Microsoft Graph."
        observed = "roleManagementPolicyAssignments=0; eligibleAssignments=0"
        confidence = "medium"

    return result(
        control_id="ID-04",
        title="Privileged Identity Management enabled for all privileged roles",
        status=status,
        confidence=confidence,
        reason=reason,
        expected="Privileged Entra roles use eligible just-in-time activation with PIM policy controls instead of broad standing assignments.",
        observed=observed,
        evidence={
            "role_management_policy_assignment_count": assignment_count,
            "eligible_assignment_count": eligible_count,
            "active_assignment_count": active_count,
            "role_management_policy_assignment_sample": compact_items(assignments, ["id", "scopeId", "scopeType", "policyId", "roleDefinitionId"], 25),
            "eligible_assignment_sample": compact_items(eligible, ["id", "principalId", "roleDefinitionId", "directoryScopeId", "startDateTime", "endDateTime"], 25),
            "active_assignment_sample": compact_items(active, ["id", "principalId", "roleDefinitionId", "directoryScopeId", "startDateTime", "endDateTime"], 25),
            "errors": {
                "roleManagementPolicyAssignments": assignment_error,
                "roleEligibilityScheduleInstances": eligible_error,
                "roleAssignmentScheduleInstances": active_error,
            },
        },
        remediation_hint="Enable PIM for all privileged Entra roles. Prefer eligible assignments, require MFA/approval for Tier-0 roles, and reduce permanent active assignments.",
        notes="This check confirms PIM evidence exists. It does not yet prove every privileged role is covered or that activation settings meet policy.",
    )

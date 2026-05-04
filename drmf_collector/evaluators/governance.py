from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result


def evaluate_access_reviews(client: GraphClient) -> ControlResult:
    definitions = client.list_all("identityGovernance/accessReviews/definitions")
    scheduled = []
    unscheduled = []

    for definition in definitions:
        settings = definition.get("settings", {}) or {}
        recurrence = settings.get("recurrence")

        item = {
            "id": definition.get("id"),
            "displayName": definition.get("displayName"),
            "status": definition.get("status"),
            "createdDateTime": definition.get("createdDateTime"),
            "recurrence": recurrence,
            "scope": definition.get("scope"),
        }

        if recurrence:
            scheduled.append(item)
        else:
            unscheduled.append(item)

    if scheduled:
        status = "pass"
        reason = "At least one scheduled Access Review definition exists."
        observed = f"{len(scheduled)} scheduled Access Review definition(s) found."
    elif definitions:
        status = "partial"
        reason = "Access Review definitions exist, but none appear to be recurring/scheduled."
        observed = f"{len(definitions)} Access Review definition(s) found, but 0 recurring/scheduled."
    else:
        status = "fail"
        reason = "No Access Review definitions were found in Entra Identity Governance."
        observed = "definition_count=0; scheduled_reviews=[]"

    return result(
        control_id="ID-17",
        title="Access Reviews scheduled and enforced",
        status=status,
        confidence="medium",
        reason=reason,
        expected="Recurring Access Reviews exist for guests and/or privileged roles, with reviewers, recurrence, decisions, and enforcement configured.",
        observed=observed,
        evidence={
            "definition_count": len(definitions),
            "scheduled_review_count": len(scheduled),
            "scheduled_reviews": scheduled[:25],
            "unscheduled_reviews": unscheduled[:25],
        },
        remediation_hint="Create recurring Access Reviews under Entra Identity Governance for guest access and privileged role assignments. Configure recurrence, reviewers, auto-apply decisions where appropriate, and retain review results.",
        notes="This check confirms scheduling evidence only. Completion quality and reviewer decisions require additional review.",
    )

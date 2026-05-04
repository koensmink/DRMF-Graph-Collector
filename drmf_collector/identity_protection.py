from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result
from .helpers import compact_items, try_list_all


def evaluate_identity_protection_triage(client: GraphClient) -> ControlResult:
    risky_users, risky_users_error = try_list_all(client, "identityProtection/riskyUsers")
    detections, detections_error = try_list_all(client, "identityProtection/riskDetections")
    signins, signins_error = try_list_all(client, "auditLogs/signIns", params={"$top": 50})

    active_risky_users = [
        user for user in risky_users
        if str(user.get("riskState", "")).lower() not in ["remediated", "dismissed"]
    ]

    if detections or risky_users:
        status = "partial" if active_risky_users else "pass"
        reason = "Identity Protection data is available. Active risky users require operational triage validation." if active_risky_users else "Identity Protection data is available and no active risky users were observed."
        observed = f"riskyUsers={len(risky_users)}; activeRiskyUsers={len(active_risky_users)}; riskDetections={len(detections)}"
        confidence = "medium"
    else:
        status = "partial"
        reason = "No risky users or risk detections were returned. This may mean no recent risk, insufficient licensing, or insufficient permissions."
        observed = "riskyUsers=0; riskDetections=0"
        confidence = "low"

    return result(
        control_id="MD-09",
        title="Identity Protection alerts triaged and tracked",
        status=status,
        confidence=confidence,
        reason=reason,
        expected="Risk detections and risky users are reviewed, remediated, dismissed with rationale, or tracked in an incident workflow.",
        observed=observed,
        evidence={
            "risky_user_count": len(risky_users),
            "active_risky_user_count": len(active_risky_users),
            "risk_detection_count": len(detections),
            "recent_signin_sample_count": len(signins),
            "active_risky_user_sample": compact_items(active_risky_users, ["id", "userPrincipalName", "riskLevel", "riskState", "riskDetail"], 25),
            "risk_detection_sample": compact_items(detections, ["id", "riskType", "riskLevel", "riskState", "activityDateTime", "userPrincipalName"], 25),
            "errors": {
                "riskyUsers": risky_users_error,
                "riskDetections": detections_error,
                "signIns": signins_error,
            },
        },
        remediation_hint="Review active risky users and risk detections. Integrate triage with Conditional Access risk policies, Defender incidents, or ITSM tracking.",
        notes="Graph can show risk evidence, but ticket ownership and SLA tracking require integration with the operational process.",
    )

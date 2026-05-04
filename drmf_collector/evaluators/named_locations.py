from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result


def evaluate_named_locations(client: GraphClient) -> ControlResult:
    locations = client.list_all("identity/conditionalAccess/namedLocations")

    if locations:
        status = "pass"
        reason = "Named locations exist in Conditional Access."
        observed = f"{len(locations)} named location(s) found."
    else:
        status = "fail"
        reason = "No Conditional Access named locations were found."
        observed = "0 named locations found."

    return result(
        control_id="ID-14",
        title="Named locations defined",
        status=status,
        confidence="high",
        reason=reason,
        expected="Named locations are defined where geo/IP-based Conditional Access decisions are used or justified.",
        observed=observed,
        evidence={
            "named_location_count": len(locations),
            "locations": [
                {
                    "id": item.get("id"),
                    "displayName": item.get("displayName"),
                    "type": item.get("@odata.type"),
                    "isTrusted": item.get("isTrusted"),
                }
                for item in locations[:50]
            ],
        },
        remediation_hint="Define named locations for trusted IP ranges or blocked/high-risk geographies where this is part of the CA design.",
    )

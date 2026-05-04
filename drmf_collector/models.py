from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ControlResult:
    control_id: str
    title: str
    status: str
    confidence: str
    reason: str
    expected: str
    observed: str
    evidence: Dict[str, Any]
    timestamp_utc: str
    source: str = "graph"
    remediation_hint: Optional[str] = None
    notes: Optional[str] = None

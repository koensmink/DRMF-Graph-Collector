from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import List

import requests

from drmf_collector.graph_client import GraphClient
from drmf_collector.models import ControlResult
from drmf_collector.registry import CONTROL_EVALUATORS
from drmf_collector.utils import utc_now


class GraphCollectorError(Exception):
    pass


def load_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise GraphCollectorError(f"Missing required environment variable: {name}")
    return value


def run() -> List[ControlResult]:
    client = GraphClient(
        tenant_id=load_required_env("TENANT_ID"),
        client_id=load_required_env("CLIENT_ID"),
        client_secret=load_required_env("CLIENT_SECRET"),
        graph_base_url=os.getenv("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0"),
    )

    results: List[ControlResult] = []

    for evaluator in CONTROL_EVALUATORS:
        try:
            results.append(evaluator(client))
        except requests.HTTPError as exc:
            response_text = exc.response.text[:2000] if exc.response is not None else str(exc)
            results.append(
                ControlResult(
                    control_id=getattr(evaluator, "__name__", "unknown"),
                    title=getattr(evaluator, "__name__", "unknown"),
                    status="error",
                    confidence="low",
                    reason="Graph request failed.",
                    expected="Successful Graph response for this control.",
                    observed=f"HTTP error: {exc.response.status_code if exc.response is not None else 'unknown'}",
                    evidence={
                        "http_status": exc.response.status_code if exc.response is not None else None,
                        "response_text": response_text,
                    },
                    timestamp_utc=utc_now(),
                    notes="Check Graph permissions, endpoint availability, tenant licensing, and admin consent.",
                )
            )
        except Exception as exc:
            results.append(
                ControlResult(
                    control_id=getattr(evaluator, "__name__", "unknown"),
                    title=getattr(evaluator, "__name__", "unknown"),
                    status="error",
                    confidence="low",
                    reason="Unhandled exception during control evaluation.",
                    expected="Evaluator should complete and return a control result.",
                    observed=str(exc),
                    evidence={"error": str(exc)},
                    timestamp_utc=utc_now(),
                    notes="Review collector logs and evaluator logic.",
                )
            )

    return results


def main() -> int:
    try:
        results = run()
    except GraphCollectorError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2

    output_path = os.getenv("OUTPUT_PATH", "drmf_output.json")
    payload = {
        "schema_version": "0.3",
        "generated_at_utc": utc_now(),
        "result_count": len(results),
        "summary": {
            "pass": sum(1 for item in results if item.status == "pass"),
            "fail": sum(1 for item in results if item.status == "fail"),
            "partial": sum(1 for item in results if item.status == "partial"),
            "error": sum(1 for item in results if item.status == "error"),
        },
        "results": [asdict(item) for item in results],
    }

    with open(output_path, "w", encoding="utf-8") as file_handle:
        json.dump(payload, file_handle, indent=2, ensure_ascii=False)

    print(f"[ok] wrote {len(results)} control results to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

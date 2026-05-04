from __future__ import annotations

import argparse
import json
import os
import sys
import time
from copy import deepcopy
from typing import Any, Dict, List, Optional

from openai import OpenAI


DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
DEFAULT_BATCH_SIZE = int(os.getenv("AI_BATCH_SIZE", "8"))
DEFAULT_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", "3"))
DEFAULT_SLEEP_SECONDS = int(os.getenv("AI_RETRY_SLEEP_SECONDS", "5"))


SYSTEM_PROMPT = """You are a senior cloud security architect reviewing Microsoft security control evidence.

You receive deterministic control results from a DRMF collector.

Rules:
- Use ONLY the provided input.
- Do NOT invent missing tenant configuration, policy assignments, users, devices, exceptions, or business context.
- Distinguish configuration evidence from effective enforcement.
- If evidence is insufficient, state exactly what is missing.
- Keep output concise, technical, and actionable.
- Never change the original deterministic status.
- Return valid JSON only.

For each control return:
- control_id
- insight
- gap_analysis
- recommended_action
- risk_priority: low | medium | high | unknown
- confidence_adjusted: low | medium | high
- missing_evidence: array of strings
"""


def _strip_large_evidence(control: Dict[str, Any], max_items: int = 10) -> Dict[str, Any]:
    clone = deepcopy(control)
    evidence = clone.get("evidence")

    if isinstance(evidence, dict):
        for key, value in list(evidence.items()):
            if isinstance(value, list) and len(value) > max_items:
                evidence[key] = value[:max_items]
                evidence[f"{key}_truncated"] = True
                evidence[f"{key}_original_count"] = len(value)
            elif isinstance(value, dict):
                for nested_key, nested_value in list(value.items()):
                    if isinstance(nested_value, list) and len(nested_value) > max_items:
                        value[nested_key] = nested_value[:max_items]
                        value[f"{nested_key}_truncated"] = True
                        value[f"{nested_key}_original_count"] = len(nested_value)

    return clone


def _build_batch_prompt(batch: List[Dict[str, Any]]) -> str:
    compact_batch = [_strip_large_evidence(control) for control in batch]

    return json.dumps(
        {
            "task": "Enrich deterministic DRMF control results with security interpretation.",
            "strict_requirements": [
                "Do not modify deterministic status.",
                "Do not invent missing evidence.",
                "Return JSON object with key 'items'.",
                "The number of output items must equal the number of input controls.",
                "Each output item must include the original control_id.",
            ],
            "controls": compact_batch,
        },
        indent=2,
        ensure_ascii=False,
    )


def _fallback_item(control: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "control_id": str(control.get("control_id", "unknown")),
        "insight": "AI enrichment unavailable.",
        "gap_analysis": reason,
        "recommended_action": "Review deterministic result manually.",
        "risk_priority": "unknown",
        "confidence_adjusted": "low",
        "missing_evidence": ["AI enrichment failed or returned invalid output."],
    }


def _validate_ai_items(batch: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = parsed.get("items")
    if not isinstance(items, list):
        raise ValueError("AI response does not contain an 'items' list.")

    by_id = {}
    for item in items:
        if isinstance(item, dict) and item.get("control_id"):
            by_id[str(item["control_id"])] = item

    output = []
    for control in batch:
        control_id = str(control.get("control_id", "unknown"))
        item = by_id.get(control_id)

        if not item:
            output.append(_fallback_item(control, f"No AI item returned for control_id={control_id}."))
            continue

        output.append(
            {
                "control_id": control_id,
                "insight": str(item.get("insight", "")).strip() or "No insight returned.",
                "gap_analysis": str(item.get("gap_analysis", "")).strip() or "No gap analysis returned.",
                "recommended_action": str(item.get("recommended_action", "")).strip() or "Review manually.",
                "risk_priority": item.get("risk_priority") if item.get("risk_priority") in ["low", "medium", "high", "unknown"] else "unknown",
                "confidence_adjusted": item.get("confidence_adjusted") if item.get("confidence_adjusted") in ["low", "medium", "high"] else "low",
                "missing_evidence": item.get("missing_evidence") if isinstance(item.get("missing_evidence"), list) else [],
            }
        )

    return output


def enrich_batch(
    client: OpenAI,
    batch: List[Dict[str, Any]],
    model: str,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_sleep_seconds: int = DEFAULT_SLEEP_SECONDS,
) -> List[Dict[str, Any]]:
    prompt = _build_batch_prompt(batch)
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )

            content = response.choices[0].message.content or "{}"
            parsed = json.loads(content)
            return _validate_ai_items(batch, parsed)

        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < max_retries:
                time.sleep(retry_sleep_seconds * attempt)

    return [_fallback_item(control, f"AI enrichment failed after retries: {last_error}") for control in batch]


def enrich_payload(
    payload: Dict[str, Any],
    model: str = DEFAULT_MODEL,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Dict[str, Any]:
    if "results" not in payload or not isinstance(payload["results"], list):
        raise ValueError("Input JSON must contain a 'results' array.")

    client = OpenAI()
    enriched_payload = deepcopy(payload)
    results = enriched_payload["results"]

    enriched_payload["ai_enrichment"] = {
        "enabled": True,
        "model": model,
        "batch_size": batch_size,
        "mode": "post_processing",
        "note": "AI enrichment is advisory and does not change deterministic control status.",
    }

    for start in range(0, len(results), batch_size):
        batch = results[start:start + batch_size]
        ai_items = enrich_batch(client=client, batch=batch, model=model)
        ai_by_id = {item["control_id"]: item for item in ai_items}

        for control in batch:
            control_id = str(control.get("control_id", "unknown"))
            control["ai"] = ai_by_id.get(control_id, _fallback_item(control, "AI item missing after batch enrichment."))

    enriched_payload["ai_enrichment"]["completed"] = True
    enriched_payload["ai_enrichment"]["result_count"] = len(results)

    return enriched_payload


def enrich_file(input_path: str, output_path: str, model: str, batch_size: int) -> None:
    with open(input_path, "r", encoding="utf-8") as file_handle:
        payload = json.load(file_handle)

    enriched = enrich_payload(payload=payload, model=model, batch_size=batch_size)

    with open(output_path, "w", encoding="utf-8") as file_handle:
        json.dump(enriched, file_handle, indent=2, ensure_ascii=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI enrichment post-processor for DRMF collector output.")
    parser.add_argument("--input", default=os.getenv("AI_INPUT_PATH", "/output/drmf_output.json"))
    parser.add_argument("--output", default=os.getenv("AI_OUTPUT_PATH", "/output/drmf_enriched.json"))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        print("[fatal] OPENAI_API_KEY is required for AI enrichment.", file=sys.stderr)
        return 2

    try:
        enrich_file(
            input_path=args.input,
            output_path=args.output,
            model=args.model,
            batch_size=args.batch_size,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[fatal] AI enrichment failed: {exc}", file=sys.stderr)
        return 1

    print(f"[ok] AI enriched output written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# DRMF AI Enrichment Integration

## Architectuur

```text
Graph → Evaluators → drmf_output.json → AI Enricher → drmf_enriched.json
```

De AI-laag is post-processing. De deterministische status/scoring wordt niet aangepast.

## Run

Eerst de deterministische collector:

```bash
docker compose run --rm drmf-graph-collector
```

Daarna AI enrichment:

```bash
docker compose -f docker-compose.yml -f docker-compose.ai.yml run --rm drmf-ai-enricher
```

Output:

```text
output/drmf_enriched.json
```

## Output

Per control wordt toegevoegd:

```json
"ai": {
  "control_id": "EP-03",
  "insight": "...",
  "gap_analysis": "...",
  "recommended_action": "...",
  "risk_priority": "high",
  "confidence_adjusted": "medium",
  "missing_evidence": []
}
```

## Batching

Standaard:

```env
AI_BATCH_SIZE=8
```

Aanbevolen:
- 3–5 bij grote evidence payloads
- 8–10 als default
- 10–15 als kosten/latency belangrijker is dan precisie

## Belangrijke waarborg

AI wijzigt nooit:

```text
status
reason
expected
observed
evidence
```

De AI-output komt alleen onder:

```text
ai
```

## Failure behavior

Als AI faalt, blijft de output bruikbaar. Elke control krijgt dan:

```json
"ai": {
  "insight": "AI enrichment unavailable.",
  "recommended_action": "Review deterministic result manually.",
  "risk_priority": "unknown",
  "confidence_adjusted": "low"
}
```

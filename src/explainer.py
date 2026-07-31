from __future__ import annotations

import json
import os
from typing import Any

import httpx

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"

SYSTEM_PROMPT = """You are GuardScan's grounded explanation layer for smart-contract findings.

HARD RULES:
1. Explain ONLY the detector findings provided in the JSON payload.
2. Do NOT invent new vulnerabilities, detectors, or line numbers.
3. If asked about anything outside the provided findings, say you cannot add findings beyond the detector output.
4. For each finding, briefly explain risk and a concrete fix suggestion.
5. Cite the provided evidence text when explaining.
6. Keep the tone professional and concise (security tooling, not marketing).
"""


def _template_result(findings: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {
        "summary": (
            f"Explained {len(findings)} finding(s) from a fixed sentence template "
            f"({reason}). No language model was called."
        ),
        "findings": _template_explanations(findings),
        "explanation_mode": "template",
        "template_reason": reason,
    }


def _template_explanations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build per-finding explanations from detector output, without calling a model."""
    explained = []
    for finding in findings:
        explained.append(
            {
                **finding,
                "explanation": (
                    f"Why this matters: {finding['title'].rstrip('.')}. "
                    f"The detector matched `{finding['evidence']}` at line {finding['line']}. "
                    f"How to fix it: {finding['recommendation']}"
                ),
            }
        )
    return explained


def explain_findings(
    source: str,
    findings: list[dict[str, Any]],
    *,
    model: str | None = None,
    use_mock: bool | None = None,
) -> dict[str, Any]:
    """Explain detector findings via OpenRouter, or mock if no API key.

    The LLM is constrained to the provided findings only.
    """
    if not findings:
        return {
            "summary": "No detector findings. GuardScan will not invent vulnerabilities.",
            "findings": [],
            "explanation_mode": "none",
        }

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if use_mock is None:
        use_mock = not bool(api_key)

    if use_mock:
        return _template_result(
            findings, "requested" if api_key else "no OPENROUTER_API_KEY set"
        )

    payload_findings = [
        {
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "line": f.get("line"),
            "evidence": f.get("evidence"),
            "recommendation": f.get("recommendation"),
            "detector": f.get("detector"),
        }
        for f in findings
    ]
    user_prompt = (
        "Explain these GuardScan detector findings. Do not add new findings.\n\n"
        f"FINDINGS_JSON:\n{json.dumps(payload_findings, indent=2)}\n\n"
        "SOURCE_EXCERPT (for context only; do not invent issues from it):\n"
        f"{source[:4000]}\n\n"
        "Return a short overall summary, then one explanation bullet per finding id."
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/raghavendraprasath/guardscan",
        "X-Title": "GuardScan",
    }
    body = {
        "model": model or os.getenv("OPENROUTER_MODEL", DEFAULT_MODEL),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
    }

    # Free-tier models rate-limit routinely, so any transport or payload failure
    # degrades to template text instead of surfacing a traceback to the user.
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(OPENROUTER_URL, headers=headers, json=body)
            response.raise_for_status()
            data = response.json()
        content = data["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        detail = "rate limited" if status == 429 else f"HTTP {status}"
        return _template_result(findings, f"model call failed: {detail}")
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        return _template_result(findings, f"model call failed: {type(exc).__name__}")

    if not content or not content.strip():
        return _template_result(findings, "model returned an empty response")

    # The model returns one narrative covering every finding, so it belongs in
    # `summary` rather than duplicated onto each finding.
    return {
        "summary": content,
        "findings": list(findings),
        "explanation_mode": "ai",
        "model": body["model"],
    }

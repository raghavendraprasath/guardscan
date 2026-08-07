import type { Explanation, Finding } from "./types";

const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";
export const DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b:free";

const SYSTEM_PROMPT = `You are GuardScan's grounded explanation layer for smart-contract findings.

HARD RULES:
1. Explain ONLY the detector findings provided in the JSON payload.
2. Do NOT invent new vulnerabilities, detectors, or line numbers.
3. If asked about anything outside the provided findings, say you cannot add findings beyond the detector output.
4. For each finding, briefly explain risk and a concrete fix suggestion.
5. Cite the provided evidence text when explaining.
6. Keep the tone professional and concise (security tooling, not marketing).`;

function templateExplanations(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({
    ...finding,
    explanation: `Why this matters: ${finding.title.replace(/\.$/, "")}. The detector matched \`${finding.evidence}\` at line ${finding.line}. How to fix it: ${finding.recommendation}`,
  }));
}

export function templateResult(findings: Finding[], reason: string): Explanation {
  return {
    summary: `Explained ${findings.length} finding(s) from a fixed sentence template (${reason}). No language model was called.`,
    findings: templateExplanations(findings),
    explanation_mode: "template",
    template_reason: reason,
  };
}

export async function explainFindings(
  source: string,
  findings: Finding[],
  opts: { useMock?: boolean } = {},
): Promise<Explanation> {
  if (findings.length === 0) {
    return {
      summary: "No detector findings. GuardScan will not invent vulnerabilities.",
      findings: [],
      explanation_mode: "none",
    };
  }

  const apiKey = (process.env.OPENROUTER_API_KEY ?? "").trim();
  const useMock = opts.useMock ?? !apiKey;

  if (useMock) {
    return templateResult(
      findings,
      apiKey ? "requested" : "no OPENROUTER_API_KEY set",
    );
  }

  const model = process.env.OPENROUTER_MODEL?.trim() || DEFAULT_MODEL;
  const payload = findings.map((f) => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    line: f.line,
    evidence: f.evidence,
    recommendation: f.recommendation,
    detector: f.detector,
  }));

  const userPrompt = `Explain these GuardScan detector findings. Do not add new findings.

FINDINGS_JSON:
${JSON.stringify(payload, null, 2)}

SOURCE_EXCERPT (for context only; do not invent issues from it):
${source.slice(0, 4000)}

Return a short overall summary, then one explanation bullet per finding id.`;

  try {
    const response = await fetch(OPENROUTER_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/raghavendraprasath/guardscan",
        "X-Title": "GuardScan",
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        temperature: 0.1,
      }),
    });

    if (!response.ok) {
      const detail =
        response.status === 429 ? "rate limited" : `HTTP ${response.status}`;
      return templateResult(findings, `model call failed: ${detail}`);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = data.choices?.[0]?.message?.content?.trim() ?? "";
    if (!content) {
      return templateResult(findings, "model returned an empty response");
    }

    return {
      summary: content,
      findings: [...findings],
      explanation_mode: "ai",
      model,
    };
  } catch (err) {
    const name = err instanceof Error ? err.constructor.name : "Error";
    return templateResult(findings, `model call failed: ${name}`);
  }
}

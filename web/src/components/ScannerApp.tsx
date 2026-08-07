"use client";

import { useMemo, useState, useTransition } from "react";

import { FindingList } from "@/components/FindingList";
import { SeverityChart } from "@/components/SeverityChart";
import { DETECTOR_COUNT, runDetectors } from "@/lib/detectors";
import { FIXTURES, type FixtureId, fixtureById } from "@/lib/fixtures";
import type { ScanReport } from "@/lib/types";

export function ScannerApp() {
  const [fixtureId, setFixtureId] = useState<FixtureId>("VulnerableVault.sol");
  const [source, setSource] = useState(() => fixtureById("VulnerableVault.sol").source);
  const [explainWithAi, setExplainWithAi] = useState(true);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const activeFixture = useMemo(() => fixtureById(fixtureId), [fixtureId]);

  function onFixtureChange(id: FixtureId) {
    setFixtureId(id);
    setSource(fixtureById(id).source);
    setReport(null);
    setError(null);
  }

  function scan() {
    setError(null);
    const trimmed = source.trim();
    if (!trimmed) {
      setError("Paste Solidity source or pick an example contract.");
      return;
    }

    startTransition(async () => {
      try {
        // Detectors always run locally first so AI-off stays instant / offline.
        const localFindings = runDetectors(trimmed);
        if (!explainWithAi) {
          setReport({
            file: activeFixture.id === "paste" ? "<pasted source>" : activeFixture.id,
            finding_count: localFindings.length,
            findings: localFindings,
          });
          return;
        }

        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source: trimmed,
            fileLabel:
              activeFixture.id === "paste" ? "<pasted source>" : activeFixture.id,
            explain: true,
          }),
        });
        const data = (await res.json()) as ScanReport & { error?: string };
        if (!res.ok) {
          setError(data.error ?? "Scan failed.");
          return;
        }
        setReport(data);
      } catch {
        setError("Network error while explaining findings. Detectors still ran locally.");
        const localFindings = runDetectors(trimmed);
        setReport({
          file: activeFixture.id === "paste" ? "<pasted source>" : activeFixture.id,
          finding_count: localFindings.length,
          findings: localFindings,
        });
      }
    });
  }

  const perFinding = useMemo(() => {
    const map: Record<string, string> = {};
    for (const f of report?.explanation?.findings ?? []) {
      if (f.explanation) map[f.id] = f.explanation;
    }
    return map;
  }, [report]);

  const explanation = report?.explanation;

  return (
    <div className="relative mx-auto max-w-6xl px-4 pb-20 pt-10 sm:px-6 lg:px-8">
      <header className="animate-rise mb-10 max-w-3xl">
        <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.22em] text-signal">
          INFO7500 · Blockchain Security
        </p>
        <h1 className="text-5xl font-semibold tracking-tight text-ink sm:text-6xl">
          GuardScan
        </h1>
        <p className="mt-4 max-w-xl text-lg leading-relaxed text-ink/70">
          Deterministic Solidity detectors with grounded AI explanations. The model
          explains only what the detectors report — it never invents findings.
        </p>
        <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 font-mono text-xs text-ink/50">
          <span>{DETECTOR_COUNT} detectors</span>
          <span>offline detection</span>
          <span>OpenRouter explanations</span>
        </div>
      </header>

      <div className="grid gap-8 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
        <section className="animate-rise-delay space-y-4">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.18em] text-ink/45">
              Start from an example
            </span>
            <div className="grid gap-2 sm:grid-cols-2">
              {FIXTURES.map((f) => {
                const active = f.id === fixtureId;
                return (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => onFixtureChange(f.id)}
                    className={`rounded-xl border px-3 py-3 text-left transition ${
                      active
                        ? "border-signal bg-white/80 shadow-[0_0_0_1px_rgba(15,118,110,0.25)]"
                        : "border-ink/10 bg-white/40 hover:border-ink/25 hover:bg-white/70"
                    }`}
                  >
                    <span className="block text-sm font-medium text-ink">{f.label}</span>
                    <span className="mt-0.5 block text-xs text-ink/50">{f.hint}</span>
                  </button>
                );
              })}
            </div>
          </label>

          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.18em] text-ink/45">
              Solidity source
            </span>
            <textarea
              value={source}
              onChange={(e) => {
                setSource(e.target.value);
                setFixtureId("paste");
              }}
              spellCheck={false}
              className="h-[420px] w-full resize-y rounded-2xl border border-ink/10 bg-ink p-4 font-mono text-[12.5px] leading-relaxed text-[#d7e0d4] shadow-inner outline-none ring-signal/30 focus:ring-2"
              placeholder="// Paste Solidity here…"
            />
          </label>

          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex cursor-pointer items-center gap-3 select-none">
              <button
                type="button"
                role="switch"
                aria-checked={explainWithAi}
                onClick={() => setExplainWithAi((v) => !v)}
                className={`relative h-7 w-12 rounded-full transition ${
                  explainWithAi ? "bg-signal" : "bg-ink/20"
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white transition ${
                    explainWithAi ? "translate-x-5" : ""
                  }`}
                />
              </button>
              <span className="text-sm text-ink/80">
                Explain findings with AI
              </span>
            </label>

            <button
              type="button"
              onClick={scan}
              disabled={pending}
              className={`ml-auto rounded-full bg-ink px-7 py-3 text-sm font-semibold text-paper transition hover:bg-ink-soft disabled:opacity-60 ${
                pending ? "scan-pulse" : ""
              }`}
            >
              {pending ? "Scanning…" : "Scan"}
            </button>
          </div>

          <p className="text-xs leading-relaxed text-ink/50">
            {explainWithAi
              ? "On: findings are sent to a language model for risk and fix guidance. If the model is unreachable, template text is used instead."
              : "Off: raw detector findings only, instantly — no network call. Proves detectors, not the model, produce findings."}
          </p>

          {error ? (
            <p className="rounded-xl bg-alert/10 px-3 py-2 text-sm text-alert">{error}</p>
          ) : null}
        </section>

        <section className="animate-rise-late">
          {!report ? (
            <div className="flex h-full min-h-[320px] flex-col justify-center rounded-3xl border border-dashed border-ink/15 bg-white/35 px-6 py-10 text-center">
              <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-ink/40">
                Report
              </p>
              <p className="mt-3 text-lg text-ink/65">
                Run a scan to see severity-ranked findings grounded in source evidence.
              </p>
            </div>
          ) : (
            <div className="space-y-6 rounded-3xl border border-ink/10 bg-white/70 p-5 shadow-[0_20px_60px_-40px_rgba(16,21,28,0.45)] backdrop-blur sm:p-6">
              <div className="flex items-end justify-between gap-3">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-ink/40">
                    Findings
                  </p>
                  <h2 className="mt-1 text-3xl font-semibold tracking-tight text-ink">
                    {report.finding_count}
                  </h2>
                </div>
                <p className="max-w-[12rem] text-right font-mono text-[11px] text-ink/40">
                  {report.file}
                </p>
              </div>

              {report.finding_count === 0 ? (
                <p className="rounded-2xl bg-mist/50 px-4 py-3 text-sm leading-relaxed text-ink-soft">
                  Nothing matched GuardScan&apos;s {DETECTOR_COUNT} detectors. That means
                  none of the specific patterns it checks for are present — it is not a
                  proof that this contract is safe.
                </p>
              ) : (
                <>
                  <SeverityChart findings={report.findings} />
                  <FindingList findings={report.findings} explanations={perFinding} />
                </>
              )}

              {explanation && explanation.explanation_mode !== "none" ? (
                <div className="border-t border-ink/10 pt-5">
                  {explanation.explanation_mode === "template" ? (
                    <>
                      <h3 className="text-sm font-semibold text-ink">Template explanation</h3>
                      <p className="mt-2 rounded-xl bg-warn/10 px-3 py-2 text-sm text-warn">
                        AI explanation unavailable ({explanation.template_reason}). Showing
                        built-in template text — findings above are unchanged.
                      </p>
                    </>
                  ) : (
                    <>
                      <h3 className="text-sm font-semibold text-ink">AI explanation</h3>
                      {explanation.model ? (
                        <p className="mt-1 font-mono text-[11px] text-ink/40">
                          Model: {explanation.model}
                        </p>
                      ) : null}
                      <div className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-ink/80">
                        {explanation.summary}
                      </div>
                    </>
                  )}
                </div>
              ) : null}

              <details className="group border-t border-ink/10 pt-4">
                <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-ink/40 transition group-open:text-ink/70">
                  Raw JSON report
                </summary>
                <pre className="mt-3 max-h-64 overflow-auto rounded-xl bg-ink p-3 font-mono text-[11px] text-[#d7e0d4]">
                  {JSON.stringify(report, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </section>
      </div>

      <footer className="mt-16 border-t border-ink/10 pt-6 text-xs text-ink/45">
        GuardScan is an educational INFO7500 project — not a professional audit. Detectors
        are heuristic; zero findings is never a safety claim.
      </footer>
    </div>
  );
}

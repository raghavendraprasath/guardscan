"use client";

import type { Finding, Severity } from "@/lib/types";

const SEVERITY_STYLE: Record<Severity, string> = {
  Critical: "bg-alert/15 text-alert ring-alert/25",
  High: "bg-warn/15 text-warn ring-warn/25",
  Medium: "bg-signal/15 text-signal ring-signal/25",
  Info: "bg-ink/10 text-ink/70 ring-ink/15",
};

export function FindingList({
  findings,
  explanations,
}: {
  findings: Finding[];
  explanations?: Record<string, string>;
}) {
  return (
    <ul className="space-y-3">
      {findings.map((f, i) => (
        <li
          key={f.id}
          className="animate-rise border-b border-ink/10 pb-4 last:border-0"
          style={{ animationDelay: `${0.04 * i}s` }}
        >
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide ring-1 ${SEVERITY_STYLE[f.severity]}`}
            >
              {f.severity}
            </span>
            <span className="font-mono text-[11px] text-ink/45">
              line {f.line ?? "—"} · {f.detector}
            </span>
          </div>
          <p className="text-[15px] font-medium leading-snug text-ink">{f.title}</p>
          <pre className="mt-2 overflow-x-auto rounded-lg bg-ink px-3 py-2 font-mono text-[12px] leading-relaxed text-[#d7e0d4]">
            {f.evidence}
          </pre>
          <p className="mt-2 text-sm leading-relaxed text-ink/70">
            <span className="font-medium text-ink">Fix:</span> {f.recommendation}
          </p>
          {explanations?.[f.id] ? (
            <p className="mt-2 rounded-lg bg-signal/10 px-3 py-2 text-sm leading-relaxed text-ink-soft">
              {explanations[f.id]}
            </p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

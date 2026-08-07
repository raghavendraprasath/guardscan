import { NextResponse } from "next/server";

import { runDetectors } from "@/lib/detectors";
import { explainFindings } from "@/lib/explain";
import type { ScanReport } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 60;

type Body = {
  source?: string;
  fileLabel?: string;
  explain?: boolean;
  useMock?: boolean;
};

export async function POST(request: Request) {
  let body: Body;
  try {
    body = (await request.json()) as Body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const source = (body.source ?? "").trim();
  if (!source) {
    return NextResponse.json(
      { error: "Paste Solidity source to scan." },
      { status: 400 },
    );
  }

  const findings = runDetectors(source);
  const report: ScanReport = {
    file: body.fileLabel ?? "<pasted source>",
    finding_count: findings.length,
    findings,
  };

  if (body.explain !== false) {
    report.explanation = await explainFindings(source, findings, {
      useMock: body.useMock === true,
    });
  }

  return NextResponse.json(report);
}

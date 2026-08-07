export type Severity = "Critical" | "High" | "Medium" | "Info";

export type Finding = {
  id: string;
  detector: string;
  severity: Severity;
  title: string;
  line: number | null;
  evidence: string;
  recommendation: string;
  explanation?: string;
};

export type ExplanationMode = "ai" | "template" | "none";

export type Explanation = {
  summary: string;
  findings: Finding[];
  explanation_mode: ExplanationMode;
  template_reason?: string;
  model?: string;
};

export type ScanReport = {
  file: string;
  finding_count: number;
  findings: Finding[];
  explanation?: Explanation;
};

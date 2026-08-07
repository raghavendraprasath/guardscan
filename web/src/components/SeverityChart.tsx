"use client";

import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { Finding, Severity } from "@/lib/types";

const COLORS: Record<Severity, string> = {
  Critical: "#c2410c",
  High: "#b45309",
  Medium: "#0f766e",
  Info: "#64748b",
};

export function SeverityChart({ findings }: { findings: Finding[] }) {
  const order: Severity[] = ["Critical", "High", "Medium", "Info"];
  const counts = Object.fromEntries(order.map((s) => [s, 0])) as Record<
    Severity,
    number
  >;
  for (const f of findings) counts[f.severity] += 1;
  const data = order
    .filter((s) => counts[s] > 0)
    .map((s) => ({ name: s, count: counts[s] }));

  if (data.length === 0) return null;

  return (
    <div className="h-36 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 12 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={72}
            tick={{ fill: "#1a2330", fontSize: 12, fontFamily: "var(--font-geist-mono)" }}
          />
          <Tooltip
            cursor={{ fill: "rgba(15,118,110,0.08)" }}
            contentStyle={{
              background: "#f7f3ea",
              border: "1px solid rgba(16,21,28,0.12)",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
          <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={14}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name as Severity]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

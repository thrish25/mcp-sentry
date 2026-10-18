"use client";

import React from "react";
import { AggregateMetricsResponse } from "../lib/types";

interface OverviewCardsProps {
  metrics: AggregateMetricsResponse | null;
  loading: boolean;
  error?: string | null;
}

export function OverviewCards({ metrics, loading, error }: OverviewCardsProps) {
  if (loading && !metrics) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="h-28 rounded-xl bg-slate-900/60 border border-slate-800/80 animate-pulse p-4 flex flex-col justify-between"
          >
            <div className="h-3 w-20 bg-slate-800 rounded" />
            <div className="h-7 w-12 bg-slate-800 rounded" />
            <div className="h-2.5 w-28 bg-slate-800 rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40 text-rose-300 text-xs font-mono">
        Telemetry sync failed: {error}
      </div>
    );
  }

  const cards = [
    {
      title: "TOTAL TOOL CALLS",
      value: metrics?.total_events ?? 0,
      subtext: `${metrics?.executed_count ?? 0} executed in sandbox`,
      badge: "INBOUND",
      badgeColor: "bg-slate-800 text-slate-300 border-slate-700",
      accent: "from-slate-500/10 to-transparent",
      valueColor: "text-slate-100",
    },
    {
      title: "POLICY ALLOWED",
      value: metrics?.allow_count ?? 0,
      subtext: "Verified under strict allowlist",
      badge: "PERMITTED",
      badgeColor: "bg-emerald-950/60 text-emerald-300 border-emerald-800/60",
      accent: "from-emerald-500/10 to-transparent",
      valueColor: "text-emerald-400",
    },
    {
      title: "POLICY BLOCKED",
      value: metrics?.block_count ?? 0,
      subtext: "Zero sandbox execution",
      badge: "DEFAULT-DENY",
      badgeColor: "bg-rose-950/60 text-rose-300 border-rose-800/60",
      accent: "from-rose-500/10 to-transparent",
      valueColor: "text-rose-400",
    },
    {
      title: "PENDING APPROVAL",
      value: metrics?.pending_approval_count ?? 0,
      subtext: "Awaiting supervisor sign-off",
      badge: metrics?.pending_approval_count ? "ACTION NEEDED" : "CLEAR",
      badgeColor:
        (metrics?.pending_approval_count ?? 0) > 0
          ? "bg-amber-950/80 text-amber-300 border-amber-700/80 animate-pulse"
          : "bg-slate-800/60 text-slate-400 border-slate-700",
      accent: "from-amber-500/10 to-transparent",
      valueColor:
        (metrics?.pending_approval_count ?? 0) > 0
          ? "text-amber-300"
          : "text-slate-300",
    },
    {
      title: "CANARY FINDINGS",
      value: metrics?.total_findings ?? 0,
      subtext: `${metrics?.findings_by_severity?.CRITICAL ?? 0} Critical • ${
        metrics?.findings_by_severity?.HIGH ?? 0
      } High`,
      badge: `${metrics?.active_canaries_count ?? 3} ACTIVE TRAPS`,
      badgeColor: "bg-cyan-950/80 text-cyan-300 border-cyan-800/80",
      accent: "from-cyan-500/10 to-transparent",
      valueColor:
        (metrics?.total_findings ?? 0) > 0 ? "text-cyan-400" : "text-slate-300",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
      {cards.map((c, idx) => (
        <div
          key={idx}
          className={`relative overflow-hidden rounded-xl bg-slate-900/70 border border-slate-800/80 p-4 flex flex-col justify-between transition hover:border-slate-700/80 ${
            idx === 4 && (metrics?.total_findings ?? 0) > 0
              ? "border-cyan-800/60 shadow-[0_0_15px_rgba(6,182,212,0.08)]"
              : ""
          }`}
        >
          {/* Subtle top gradient accent */}
          <div
            className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${c.accent}`}
          />

          <div className="flex items-center justify-between gap-1 mb-2">
            <span className="text-[10px] font-mono tracking-wider font-semibold text-slate-400 uppercase">
              {c.title}
            </span>
            <span
              className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase font-medium ${c.badgeColor}`}
            >
              {c.badge}
            </span>
          </div>

          <div className="my-1">
            <span className={`text-2xl sm:text-3xl font-mono font-bold tracking-tight ${c.valueColor}`}>
              {c.value.toLocaleString()}
            </span>
          </div>

          <p className="text-[11px] text-slate-400 font-mono truncate mt-1">
            {c.subtext}
          </p>
        </div>
      ))}
    </div>
  );
}

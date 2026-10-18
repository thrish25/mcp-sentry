"use client";

import React from "react";
import { CanaryTokenItem, SecurityFindingItem } from "../lib/types";

interface CanaryFindingsProps {
  findings: SecurityFindingItem[];
  tokens: CanaryTokenItem[];
  loading: boolean;
}

export function CanaryFindings({ findings, tokens, loading }: CanaryFindingsProps) {
  return (
    <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-4 flex flex-col h-full space-y-4">
      {/* Header */}
      <div className="border-b border-slate-800 pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            Synthetic Canary Tokens & Forensics
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Zero-Knowledge Honeypot Traps Embedded in Synthetic Files
          </p>
        </div>

        <span className="text-[11px] font-mono text-slate-400">
          Incidents Detected:{" "}
          <strong
            className={
              findings.length > 0 ? "text-cyan-400 font-bold" : "text-slate-300"
            }
          >
            {findings.length}
          </strong>
        </span>
      </div>

      {/* Active Honeytokens Reference Cards */}
      <div>
        <span className="text-[10px] font-mono font-semibold uppercase text-slate-400 block mb-2">
          Registered Synthetic Honeypots ({tokens.length})
        </span>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {tokens.map((t) => (
            <div
              key={t.token_value}
              className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1"
            >
              <div className="flex items-center justify-between gap-1">
                <span className="font-semibold text-slate-200 truncate">
                  {t.name}
                </span>
                <span
                  className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                    t.severity === "CRITICAL"
                      ? "bg-rose-950 text-rose-300 border border-rose-800"
                      : "bg-amber-950 text-amber-300 border border-amber-800"
                  }`}
                >
                  {t.severity}
                </span>
              </div>

              <div className="text-[10px] text-cyan-400 truncate">
                {t.token_value}
              </div>

              <div className="text-[10px] text-slate-500 truncate">
                File: {t.file_path}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Forensic Incidents Feed */}
      <div className="flex-1 flex flex-col min-h-0">
        <span className="text-[10px] font-mono font-semibold uppercase text-slate-400 block mb-2">
          Canary Access & Exfiltration Alert History
        </span>

        <div className="flex-1 overflow-y-auto max-h-[300px] space-y-2 pr-1">
          {loading && findings.length === 0 ? (
            <div className="py-8 text-center text-slate-500 font-mono text-xs">
              Loading forensic incident logs...
            </div>
          ) : findings.length === 0 ? (
            <div className="py-8 rounded-lg bg-slate-950/40 border border-slate-800/60 text-center text-slate-500 font-mono text-xs">
              No canary tokens have been touched or exfiltrated yet. Trigger scenario &quot;Read System Partition Info&quot; or an exfiltration attempt to test traps.
            </div>
          ) : (
            findings.map((f) => (
              <div
                key={f.finding_id}
                className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono space-y-1.5 hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase ${
                        f.severity === "CRITICAL"
                          ? "bg-rose-950 text-rose-300 border border-rose-800"
                          : "bg-amber-950 text-amber-300 border border-amber-800"
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="font-bold text-slate-200">
                      {f.event_type}
                    </span>
                  </div>

                  <span className="text-[10px] text-slate-500">
                    {new Date(f.created_at).toLocaleTimeString()}
                  </span>
                </div>

                <div className="text-[11px] text-slate-300 leading-snug">
                  {f.evidence}
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
                  <span className="text-cyan-400">Trap: {f.canary_name}</span>
                  <span>req: {f.request_id}</span>
                  <span>dec: {f.decision_id}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

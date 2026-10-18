"use client";

import React from "react";
import { AuditRecordItem, SecurityFindingItem } from "../lib/types";

interface EvidencePanelProps {
  event: AuditRecordItem | null;
  findings: SecurityFindingItem[];
}

export function EvidencePanel({ event, findings }: EvidencePanelProps) {
  if (!event) {
    return (
      <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-5 h-full flex flex-col items-center justify-center text-center">
        <div className="h-10 w-10 rounded-full bg-slate-800/60 border border-slate-700/60 flex items-center justify-center text-slate-500 mb-3">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
          Security Evidence & Policy Rationale
        </h3>
        <p className="text-[11px] text-slate-500 font-mono mt-1 max-w-xs">
          Select an event from the audit ledger to review policy engine rules, decision rationale, and forensic canary telemetry.
        </p>
      </div>
    );
  }

  // Filter canary findings correlated to this event
  const matchingFindings = findings.filter(
    (f) => f.request_id === event.request_id || f.decision_id === event.decision_id
  );

  return (
    <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-4 flex flex-col h-full space-y-3">
      {/* Header */}
      <div className="border-b border-slate-800 pb-2.5">
        <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400" />
          Security Evidence & Policy Arbitration
        </h2>
        <p className="text-[11px] text-slate-400 font-mono mt-0.5">
          Deterministic Rule Proof & Sandbox Outcome Ledger
        </p>
      </div>

      {/* Policy Rule Block */}
      <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase text-slate-500">
            Enforced Policy Rule
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
            {event.rule_id}
          </span>
        </div>

        <div className="text-xs font-mono text-slate-300 leading-relaxed pt-1">
          {event.reason}
        </div>
      </div>

      {/* Canary Trap Forensic Telemetry (if triggered) */}
      {matchingFindings.length > 0 && (
        <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-900/40 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-rose-400 font-bold flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-rose-500 animate-ping" />
              Canary Token Alert Detected ({matchingFindings.length})
            </span>
          </div>

          {matchingFindings.map((f) => (
            <div
              key={f.finding_id}
              className="p-2 rounded bg-slate-950/80 border border-rose-800/40 text-xs font-mono space-y-1"
            >
              <div className="flex items-center justify-between gap-1 text-[11px]">
                <span className="font-bold text-rose-300">{f.canary_name}</span>
                <span
                  className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                    f.severity === "CRITICAL"
                      ? "bg-rose-950 text-rose-300 border border-rose-800"
                      : "bg-amber-950 text-amber-300 border border-amber-800"
                  }`}
                >
                  {f.severity}
                </span>
              </div>
              <div className="text-[10px] text-cyan-400/90 font-mono">
                Token: {f.canary_token} • Event: {f.event_type}
              </div>
              <div className="text-[11px] text-slate-300 leading-snug">
                {f.evidence}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Sandbox Execution Result */}
      <div className="flex-1 flex flex-col min-h-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-[10px] font-mono font-semibold uppercase text-slate-400">
            Mock Sandbox Result Payload
          </span>
          <span className="text-[10px] font-mono text-slate-500">
            {event.status}
          </span>
        </div>

        <div className="flex-1 p-2.5 rounded-lg bg-slate-950/90 border border-slate-800/90 overflow-auto font-mono text-xs text-slate-300 max-h-[180px]">
          {event.result ? (
            <pre className="text-[11px] leading-relaxed">
              {JSON.stringify(event.result, null, 2)}
            </pre>
          ) : (
            <span className="text-slate-500 italic text-[11px]">
              No sandbox output was produced (execution blocked or pending authorization).
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

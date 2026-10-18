"use client";

import React, { useState } from "react";
import { AuditRecordItem } from "../lib/types";

interface ToolCallInspectorProps {
  event: AuditRecordItem | null;
}

export function ToolCallInspector({ event }: ToolCallInspectorProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(label);
    setTimeout(() => setCopiedId(null), 1800);
  };

  if (!event) {
    return (
      <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-5 h-full flex flex-col items-center justify-center text-center">
        <div className="h-10 w-10 rounded-full bg-slate-800/60 border border-slate-700/60 flex items-center justify-center text-slate-500 mb-3">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
          </svg>
        </div>
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
          Tool-Call Inspector
        </h3>
        <p className="text-[11px] text-slate-500 font-mono mt-1 max-w-xs">
          Select an event from the audit timeline or trigger an agent scenario to inspect raw tool arguments and metadata.
        </p>
      </div>
    );
  }

  let decisionBadge = "bg-slate-800 text-slate-300 border-slate-700";
  if (event.decision === "ALLOW") {
    decisionBadge = "bg-emerald-950/80 text-emerald-300 border-emerald-800";
  } else if (event.decision === "BLOCK") {
    decisionBadge = "bg-rose-950/80 text-rose-300 border-rose-800";
  } else if (event.decision === "REQUIRE_APPROVAL") {
    decisionBadge = "bg-amber-950/80 text-amber-300 border-amber-800";
  }

  return (
    <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-4 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
        <div>
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            Tool-Call Inspector
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Verified Inbound MCP Request Metadata
          </p>
        </div>

        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${decisionBadge}`}>
          {event.decision}
        </span>
      </div>

      {/* Primary Details Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mb-3 text-xs font-mono">
        <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <span className="text-[10px] uppercase text-slate-500 block mb-1">
            MCP Tool Name
          </span>
          <span className="text-cyan-300 font-bold text-sm">
            {event.tool_name}
          </span>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <span className="text-[10px] uppercase text-slate-500 block mb-1">
            Execution Status
          </span>
          <span className="text-slate-200 font-semibold">
            {event.status}
          </span>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <span className="text-[10px] uppercase text-slate-500 block mb-1">
            Origin Agent (Untrusted)
          </span>
          <span className="text-slate-300">
            {event.origin}
          </span>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <span className="text-[10px] uppercase text-slate-500 block mb-1">
            Target Destination
          </span>
          <span className="text-slate-300">
            {event.destination}
          </span>
        </div>
      </div>

      {/* Correlation IDs */}
      <div className="mb-3 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-1.5 text-[11px] font-mono">
        <div className="flex items-center justify-between gap-2">
          <span className="text-slate-500">Request ID:</span>
          <button
            type="button"
            onClick={() => handleCopy(event.request_id, "req")}
            className="text-slate-300 hover:text-cyan-300 transition flex items-center gap-1"
            title="Click to copy"
          >
            <span className="truncate max-w-[200px]">{event.request_id}</span>
            <span className="text-[9px] text-cyan-500/80">
              {copiedId === "req" ? "COPIED" : "COPY"}
            </span>
          </button>
        </div>

        <div className="flex items-center justify-between gap-2">
          <span className="text-slate-500">Decision ID:</span>
          <button
            type="button"
            onClick={() => handleCopy(event.decision_id, "dec")}
            className="text-slate-300 hover:text-cyan-300 transition flex items-center gap-1"
            title="Click to copy"
          >
            <span className="truncate max-w-[200px]">{event.decision_id}</span>
            <span className="text-[9px] text-cyan-500/80">
              {copiedId === "dec" ? "COPIED" : "COPY"}
            </span>
          </button>
        </div>
      </div>

      {/* Arguments Viewer */}
      <div className="flex-1 flex flex-col min-h-0">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[10px] font-mono font-semibold uppercase text-slate-400">
            Inbound Arguments Payload
          </span>
          <span className="text-[10px] font-mono text-slate-500">
            {Object.keys(event.arguments || {}).length} params
          </span>
        </div>

        <div className="flex-1 p-3 rounded-lg bg-slate-950/90 border border-slate-800/90 overflow-auto font-mono text-xs text-slate-300 max-h-[220px]">
          <pre className="text-[11px] leading-relaxed">
            {JSON.stringify(event.arguments, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

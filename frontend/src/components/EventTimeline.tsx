"use client";

import React, { useState } from "react";
import { resolveApproval } from "../lib/api";
import { AuditRecordItem } from "../lib/types";

interface EventTimelineProps {
  events: AuditRecordItem[];
  selectedEvent: AuditRecordItem | null;
  onSelectEvent: (event: AuditRecordItem) => void;
  loading: boolean;
  onApprovalResolved: () => void;
  page: number;
  totalPages: number;
  totalEvents: number;
  onPageChange: (newPage: number) => void;
  filterDecision: string | null;
  onFilterDecisionChange: (decision: string | null) => void;
}

export function EventTimeline({
  events,
  selectedEvent,
  onSelectEvent,
  loading,
  onApprovalResolved,
  page,
  totalPages,
  totalEvents,
  onPageChange,
  filterDecision,
  onFilterDecisionChange,
}: EventTimelineProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const handleApproval = async (
    e: React.MouseEvent,
    requestId: string,
    approved: boolean
  ) => {
    e.stopPropagation();
    try {
      setActionLoading(requestId);
      setActionError(null);
      await resolveApproval(
        requestId,
        "security-supervisor",
        approved,
        approved ? "Authorized by security console operator" : "Denied by security console operator"
      );
      onApprovalResolved();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionLoading(null);
    }
  };

  const filteredEvents = events.filter((ev) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      ev.tool_name.toLowerCase().includes(term) ||
      ev.request_id.toLowerCase().includes(term) ||
      ev.rule_id.toLowerCase().includes(term) ||
      ev.origin.toLowerCase().includes(term)
    );
  });

  return (
    <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-4 flex flex-col h-full">
      {/* Header & Filter Controls */}
      <div className="border-b border-slate-800 pb-3 mb-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 mb-3">
          <div>
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-cyan-400" />
              Runtime Audit Events Timeline
            </h2>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">
              Live chronological record of MCP tool invocations, policy decisions, and execution outcomes
            </p>
          </div>

          <span className="text-[11px] font-mono text-slate-500 self-start sm:self-auto">
            Total Logged: <strong className="text-slate-300">{totalEvents}</strong>
          </span>
        </div>

        {/* Filter Pills & Search */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2">
          {/* Decision Filter Pills */}
          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] font-mono">
            <button
              type="button"
              onClick={() => onFilterDecisionChange(null)}
              className={`px-2 py-0.5 rounded transition ${
                filterDecision === null
                  ? "bg-slate-800 text-slate-200 font-semibold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              ALL
            </button>
            <button
              type="button"
              onClick={() => onFilterDecisionChange("ALLOW")}
              className={`px-2 py-0.5 rounded transition ${
                filterDecision === "ALLOW"
                  ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60 font-semibold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              ALLOW
            </button>
            <button
              type="button"
              onClick={() => onFilterDecisionChange("BLOCK")}
              className={`px-2 py-0.5 rounded transition ${
                filterDecision === "BLOCK"
                  ? "bg-rose-950 text-rose-300 border border-rose-800/60 font-semibold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              BLOCK
            </button>
            <button
              type="button"
              onClick={() => onFilterDecisionChange("REQUIRE_APPROVAL")}
              className={`px-2 py-0.5 rounded transition ${
                filterDecision === "REQUIRE_APPROVAL"
                  ? "bg-amber-950 text-amber-300 border border-amber-800/60 font-semibold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              APPROVAL
            </button>
          </div>

          {/* Quick Search Input */}
          <div className="relative">
            <input
              type="text"
              placeholder="Filter by tool or req-id..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full sm:w-48 text-xs font-mono bg-slate-950/90 border border-slate-800 focus:border-cyan-500/60 rounded px-2.5 py-1 text-slate-200 placeholder:text-slate-600 focus:outline-none transition"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm("")}
                className="absolute right-2 top-1.5 text-slate-500 hover:text-slate-300 text-xs"
              >
                ✕
              </button>
            )}
          </div>
        </div>
      </div>

      {actionError && (
        <div className="mb-2 p-2 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs font-mono flex items-center justify-between">
          <span>Approval Action Error: {actionError}</span>
          <button
            type="button"
            onClick={() => setActionError(null)}
            className="text-slate-400 hover:text-white ml-2 text-xs"
          >
            ✕
          </button>
        </div>
      )}

      {/* Events List / Table */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[300px] max-h-[500px]">
        {loading && events.length === 0 ? (
          <div className="space-y-2 py-2">
            {[...Array(5)].map((_, i) => (
              <div
                key={i}
                className="h-14 rounded-lg bg-slate-950/40 border border-slate-800/60 animate-pulse"
              />
            ))}
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-slate-500 font-mono text-xs">
            No audit records matching criteria.
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isSelected = selectedEvent?.request_id === ev.request_id;
            const isPending = ev.status === "PENDING_APPROVAL";
            const isActionBusy = actionLoading === ev.request_id;

            let decisionBadgeStyle = "bg-slate-800 text-slate-300 border-slate-700";
            if (ev.decision === "ALLOW") {
              decisionBadgeStyle = "bg-emerald-950/80 text-emerald-300 border-emerald-800";
            } else if (ev.decision === "BLOCK") {
              decisionBadgeStyle = "bg-rose-950/80 text-rose-300 border-rose-800";
            } else if (ev.decision === "REQUIRE_APPROVAL") {
              decisionBadgeStyle = "bg-amber-950/80 text-amber-300 border-amber-800";
            }

            return (
              <div
                key={ev.request_id}
                onClick={() => onSelectEvent(ev)}
                className={`group p-3 rounded-lg border transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 ${
                  isSelected
                    ? "bg-slate-800/80 border-cyan-500/80 shadow-[0_0_12px_rgba(6,182,212,0.12)]"
                    : "bg-slate-950/40 border-slate-800/70 hover:border-slate-700 hover:bg-slate-900/60"
                }`}
              >
                {/* Left: Decision, Tool Name, Origin -> Dest */}
                <div className="flex items-start sm:items-center gap-2.5 min-w-0">
                  <span
                    className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-bold shrink-0 ${decisionBadgeStyle}`}
                  >
                    {ev.decision}
                  </span>

                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold text-slate-200 truncate group-hover:text-cyan-300 transition">
                        {ev.tool_name}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500 truncate hidden md:inline">
                        {ev.rule_id}
                      </span>
                    </div>

                    <div className="text-[10px] font-mono text-slate-400 truncate flex items-center gap-1.5 mt-0.5">
                      <span className="text-slate-500">{ev.origin}</span>
                      <span className="text-cyan-500/60">→</span>
                      <span className="text-slate-400">{ev.destination}</span>
                    </div>
                  </div>
                </div>

                {/* Right: Status badge, inline actions for pending, timestamp */}
                <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                  {/* Inline approval controls if pending */}
                  {isPending && (
                    <div className="flex items-center gap-1 mr-1">
                      <button
                        type="button"
                        onClick={(e) => handleApproval(e, ev.request_id, true)}
                        disabled={isActionBusy}
                        className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 disabled:opacity-50 transition"
                        title="Authorize execution"
                      >
                        {isActionBusy ? "..." : "APPROVE"}
                      </button>
                      <button
                        type="button"
                        onClick={(e) => handleApproval(e, ev.request_id, false)}
                        disabled={isActionBusy}
                        className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 disabled:opacity-50 transition"
                        title="Reject execution"
                      >
                        {isActionBusy ? "..." : "REJECT"}
                      </button>
                    </div>
                  )}

                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                      ev.status === "EXECUTED" || ev.status === "APPROVED_EXECUTED"
                        ? "bg-emerald-950/50 text-emerald-400 border-emerald-800/40"
                        : ev.status === "BLOCKED"
                        ? "bg-rose-950/50 text-rose-400 border-rose-800/40"
                        : ev.status === "PENDING_APPROVAL"
                        ? "bg-amber-950/50 text-amber-400 border-amber-800/40 animate-pulse"
                        : "bg-slate-800 text-slate-400 border-slate-700"
                    }`}
                  >
                    {ev.status}
                  </span>

                  <span className="text-[10px] font-mono text-slate-500">
                    {ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : "--:--:--"}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Pagination Footer */}
      <div className="mt-3 pt-2.5 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
        <span>
          Page <strong className="text-slate-200">{page}</strong> of{" "}
          <strong className="text-slate-200">{totalPages || 1}</strong>
        </span>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1 || loading}
            className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-800 transition text-[11px]"
          >
            PREV
          </button>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages || loading}
            className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-800 transition text-[11px]"
          >
            NEXT
          </button>
        </div>
      </div>
    </div>
  );
}

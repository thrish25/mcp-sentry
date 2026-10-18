"use client";

import React from "react";
import { GatewayHealth } from "../lib/types";

interface HeaderProps {
  health: GatewayHealth | null;
  loading: boolean;
  onRefresh: () => void;
  autoRefresh: boolean;
  onToggleAutoRefresh: () => void;
  lastUpdated: Date | null;
}

export function Header({
  health,
  loading,
  onRefresh,
  autoRefresh,
  onToggleAutoRefresh,
  lastUpdated,
}: HeaderProps) {
  const isHealthy = health?.status === "healthy";

  return (
    <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 px-4 sm:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Brand & Datathon Badge */}
        <div className="flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500/20 via-indigo-600/20 to-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-mono font-bold shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight flex items-center gap-2">
                MCP-Sentry
                <span className="text-[10px] font-mono tracking-widest uppercase px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50 text-cyan-300">
                  IBM Z Runtime Gateway
                </span>
              </h1>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Deterministic Security Arbitration & Canary Detection for AI Agents
            </p>
          </div>
        </div>

        {/* Live Status Indicators & Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Health Status Pill */}
          <div
            className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono border ${
              isHealthy
                ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-300"
                : "bg-rose-950/40 border-rose-800/60 text-rose-300"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                isHealthy ? "bg-emerald-400 animate-pulse" : "bg-rose-500"
              }`}
            />
            <span>{isHealthy ? "GATEWAY ACTIVE" : "GATEWAY UNREACHABLE"}</span>
            {health?.version && (
              <span className="text-[10px] text-slate-500">v{health.version}</span>
            )}
          </div>

          {/* Auto Refresh Toggle */}
          <button
            type="button"
            onClick={onToggleAutoRefresh}
            className={`text-xs font-mono px-2.5 py-1 rounded border transition flex items-center gap-1.5 ${
              autoRefresh
                ? "bg-cyan-950/50 border-cyan-800/60 text-cyan-300 hover:bg-cyan-900/50"
                : "bg-slate-900 border-slate-800 text-slate-400 hover:bg-slate-800/60"
            }`}
            title="Toggle live telemetry refresh"
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                autoRefresh ? "bg-cyan-400" : "bg-slate-600"
              }`}
            />
            {autoRefresh ? "AUTO (10s)" : "MANUAL"}
          </button>

          {/* Manual Refresh Button */}
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="text-xs font-mono px-3 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-300 disabled:opacity-50 transition flex items-center gap-1.5"
          >
            <svg
              className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            <span>{loading ? "SYNCING..." : "SYNC"}</span>
          </button>

          {lastUpdated && (
            <span className="text-[11px] text-slate-500 font-mono hidden lg:inline">
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>
    </header>
  );
}

"use client";

import React, { useState } from "react";
import { FakeEmail, FakeNetworkLog, SyntheticFile } from "../lib/types";

interface SandboxViewProps {
  files: SyntheticFile[];
  emails: FakeEmail[];
  networkLogs: FakeNetworkLog[];
  loading: boolean;
}

export function SandboxView({
  files,
  emails,
  networkLogs,
  loading,
}: SandboxViewProps) {
  const [activeTab, setActiveTab] = useState<"files" | "emails" | "network">("files");

  return (
    <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-4 flex flex-col h-full">
      {/* Header & Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-3">
        <div>
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            Isolated Mock Tool Sandbox
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Synthetic Datasets, Fake Local Outbox, and Zero-Traffic Network Simulation
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] font-mono self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setActiveTab("files")}
            className={`px-2.5 py-1 rounded transition flex items-center gap-1.5 ${
              activeTab === "files"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
            </svg>
            Files ({files.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("emails")}
            className={`px-2.5 py-1 rounded transition flex items-center gap-1.5 ${
              activeTab === "emails"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            Fake Outbox ({emails.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("network")}
            className={`px-2.5 py-1 rounded transition flex items-center gap-1.5 ${
              activeTab === "network"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
            Fake Network Logs ({networkLogs.length})
          </button>
        </div>
      </div>

      {/* Tab Content Area */}
      <div className="flex-1 overflow-y-auto max-h-[360px] pr-1">
        {loading && files.length === 0 && emails.length === 0 && networkLogs.length === 0 ? (
          <div className="py-8 text-center text-slate-500 font-mono text-xs">
            Loading sandbox telemetry...
          </div>
        ) : activeTab === "files" ? (
          /* Tab 1: Synthetic Files */
          <div className="space-y-2">
            <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Host filesystem isolation: <strong className="text-emerald-400">ENFORCED</strong></span>
              <span className="text-slate-500">Stored strictly in SQLite mock database</span>
            </div>

            <div className="divide-y divide-slate-800/60 rounded-lg border border-slate-800 bg-slate-950/40">
              {files.map((file) => {
                const isCanaryFile =
                  file.path.includes("system_info.json") ||
                  file.path.includes("security_report.txt") ||
                  file.path.includes("user_directory.csv");

                return (
                  <div
                    key={file.path}
                    className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-slate-900/40 transition"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-semibold text-slate-200 truncate">
                          {file.path}
                        </span>
                        {isCanaryFile && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-semibold shrink-0">
                            SEEDED CANARY
                          </span>
                        )}
                        {Boolean(file.is_scratch) && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 shrink-0">
                            SCRATCH BUFFER
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 block mt-0.5">
                        Updated: {new Date(file.updated_at).toLocaleString()}
                      </span>
                    </div>

                    <span className="text-[10px] font-mono text-emerald-400 shrink-0 bg-emerald-950/30 border border-emerald-900/40 px-2 py-0.5 rounded">
                      MOCK SANDBOX ONLY
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : activeTab === "emails" ? (
          /* Tab 2: Fake Email Outbox */
          <div className="space-y-2">
            <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>External SMTP Sockets: <strong className="text-emerald-400">DISABLED (0 live packets)</strong></span>
              <span className="text-slate-500">Only authorized emails write to local outbox</span>
            </div>

            {emails.length === 0 ? (
              <div className="py-8 text-center text-slate-500 font-mono text-xs">
                Fake email outbox is currently empty. Trigger an approved email scenario to inspect dispatch records.
              </div>
            ) : (
              <div className="space-y-2">
                {emails.map((m) => (
                  <div
                    key={m.id}
                    className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-slate-200">
                        To: {m.to_address}
                      </span>
                      <span className="text-[10px] text-slate-500">
                        {new Date(m.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-[11px] text-cyan-300 font-semibold">
                      Subject: {m.subject}
                    </div>
                    <div className="p-2 rounded bg-slate-900/80 border border-slate-800/80 text-[11px] text-slate-300 font-sans whitespace-pre-wrap">
                      {m.body}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between">
                      <span>req: {m.request_id}</span>
                      <span className="text-emerald-400 font-semibold">STATUS: HELD IN LOCAL DB</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          /* Tab 3: Fake Network Logs */
          <div className="space-y-2">
            <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Simulated Network: <strong className="text-emerald-400">ISOLATED LOOPBACK</strong></span>
              <span className="text-slate-500">External internet endpoints are blocked by policy</span>
            </div>

            {networkLogs.length === 0 ? (
              <div className="py-8 text-center text-slate-500 font-mono text-xs">
                No simulated network requests logged yet. Trigger an internal fetch scenario to generate mock telemetry.
              </div>
            ) : (
              <div className="space-y-2">
                {networkLogs.map((log) => (
                  <div
                    key={log.id}
                    className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-bold">
                          {log.method}
                        </span>
                        <span className="text-slate-200 font-mono text-xs truncate max-w-sm">
                          {log.url}
                        </span>
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                        {log.status_code} OK
                      </span>
                    </div>

                    {log.payload && (
                      <div className="text-[10px] text-slate-400 truncate">
                        Payload: {log.payload}
                      </div>
                    )}

                    <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-[10px] text-slate-300 truncate">
                      Response: {log.response_body}
                    </div>

                    <div className="text-[10px] text-slate-500 flex items-center justify-between pt-1">
                      <span>req: {log.request_id}</span>
                      <span>{new Date(log.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

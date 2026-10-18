"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  fetchAuditEvents,
  fetchCanaryTokens,
  fetchFakeNetworkLogs,
  fetchFakeOutbox,
  fetchGatewayHealth,
  fetchMetrics,
  fetchSecurityFindings,
  fetchSyntheticFiles,
} from "../lib/api";
import {
  AggregateMetricsResponse,
  AuditRecordItem,
  CanaryTokenItem,
  ExecutionResponse,
  FakeEmail,
  FakeNetworkLog,
  GatewayHealth,
  SecurityFindingItem,
  SyntheticFile,
} from "../lib/types";

import { CanaryFindings } from "../components/CanaryFindings";
import { DemoControlPanel } from "../components/DemoControlPanel";
import { EventTimeline } from "../components/EventTimeline";
import { EvidencePanel } from "../components/EvidencePanel";
import { Header } from "../components/Header";
import { OverviewCards } from "../components/OverviewCards";
import { SandboxView } from "../components/SandboxView";
import { ToolCallInspector } from "../components/ToolCallInspector";

export default function SecurityConsolePage() {
  // Global state
  const [health, setHealth] = useState<GatewayHealth | null>(null);
  const [metrics, setMetrics] = useState<AggregateMetricsResponse | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditRecordItem[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AuditRecordItem | null>(null);
  const [findings, setFindings] = useState<SecurityFindingItem[]>([]);
  const [canaryTokens, setCanaryTokens] = useState<CanaryTokenItem[]>([]);
  const [syntheticFiles, setSyntheticFiles] = useState<SyntheticFile[]>([]);
  const [outbox, setOutbox] = useState<FakeEmail[]>([]);
  const [networkLogs, setNetworkLogs] = useState<FakeNetworkLog[]>([]);

  // Telemetry status
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Pagination & Filtering
  const [auditPage, setAuditPage] = useState(1);
  const [totalAuditPages, setTotalAuditPages] = useState(1);
  const [totalAuditEvents, setTotalAuditEvents] = useState(0);
  const [filterDecision, setFilterDecision] = useState<string | null>(null);

  // Section view toggle for lower area
  const [activeBottomView, setActiveBottomView] = useState<"sandbox" | "canaries">("sandbox");

  // Load all dashboard telemetry
  const loadDashboardData = useCallback(async () => {
    try {
      // Concurrent data fetching
      const [
        healthRes,
        metricsRes,
        eventsRes,
        findingsRes,
        canariesRes,
        filesRes,
        outboxRes,
        netRes,
      ] = await Promise.allSettled([
        fetchGatewayHealth(),
        fetchMetrics(),
        fetchAuditEvents({
          page: auditPage,
          page_size: 15,
          decision: filterDecision || undefined,
        }),
        fetchSecurityFindings({ page: 1, page_size: 20 }),
        fetchCanaryTokens(),
        fetchSyntheticFiles(),
        fetchFakeOutbox(),
        fetchFakeNetworkLogs(),
      ]);

      if (healthRes.status === "fulfilled") setHealth(healthRes.value);
      if (metricsRes.status === "fulfilled") setMetrics(metricsRes.value);

      if (eventsRes.status === "fulfilled") {
        setAuditEvents(eventsRes.value.items);
        setTotalAuditPages(eventsRes.value.total_pages);
        setTotalAuditEvents(eventsRes.value.total);

        // Auto-select latest event if none selected
        setSelectedEvent((prev) => prev ?? (eventsRes.value.items[0] || null));
      }

      if (findingsRes.status === "fulfilled") setFindings(findingsRes.value.items);
      if (canariesRes.status === "fulfilled") setCanaryTokens(canariesRes.value);
      if (filesRes.status === "fulfilled") setSyntheticFiles(filesRes.value.files);
      if (outboxRes.status === "fulfilled") setOutbox(outboxRes.value.emails);
      if (netRes.status === "fulfilled") setNetworkLogs(netRes.value.network_logs);

      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [auditPage, filterDecision]);

  // Manual refresh handler with visual loading indicator
  const handleManualRefresh = useCallback(() => {
    setLoading(true);
    loadDashboardData();
  }, [loadDashboardData]);

  // Initial fetch and auto-refresh polling
  useEffect(() => {
    let active = true;

    Promise.resolve().then(() => {
      if (active) {
        void loadDashboardData();
      }
    });

    if (!autoRefresh) {
      return () => {
        active = false;
      };
    }

    const interval = setInterval(() => {
      if (active) {
        void loadDashboardData();
      }
    }, 10000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [loadDashboardData, autoRefresh]);

  // Handle scenario execution from DemoControlPanel (Tasks 3, 4, 5)
  const handleScenarioExecuted = useCallback(
    async (response: ExecutionResponse) => {
      // Refresh dashboard telemetry after scenario execution
      await loadDashboardData();

      // Ensure the inspector points to the newly executed event
      setAuditEvents((current) => {
        const found = current.find((item) => item.request_id === response.request_id);
        if (found) {
          setSelectedEvent(found);
        } else if (current.length > 0) {
          setSelectedEvent(current[0]);
        }
        return current;
      });
    },
    [loadDashboardData]
  );

  return (
    <div className="min-h-screen bg-[#070d1e] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Header Bar */}
      <Header
        health={health}
        loading={loading}
        onRefresh={handleManualRefresh}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={() => setAutoRefresh(!autoRefresh)}
        lastUpdated={lastUpdated}
      />

      {/* Main Console Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-5">
        {/* Error Banner */}
        {error && (
          <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
              <span>Gateway Telemetry Sync Notice: {error}</span>
            </div>
            <button
              type="button"
              onClick={handleManualRefresh}
              className="text-[11px] underline hover:text-white"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* Section 1: Overview Cards */}
        <section aria-label="Security Metrics Overview">
          <OverviewCards metrics={metrics} loading={loading} error={error} />
        </section>

        {/* Section 2: Demo Control Panel */}
        <section aria-label="Agent Demonstration Controls">
          <DemoControlPanel onScenarioExecuted={handleScenarioExecuted} />
        </section>

        {/* Section 3: Dual Column Operations Center */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left Column: Timeline Feed (7 Cols) */}
          <div className="lg:col-span-7 flex flex-col gap-5">
            <EventTimeline
              events={auditEvents}
              selectedEvent={selectedEvent}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              loading={loading}
              onApprovalResolved={loadDashboardData}
              page={auditPage}
              totalPages={totalAuditPages}
              totalEvents={totalAuditEvents}
              onPageChange={(p) => setAuditPage(p)}
              filterDecision={filterDecision}
              onFilterDecisionChange={(d) => {
                setFilterDecision(d);
                setAuditPage(1);
              }}
            />
          </div>

          {/* Right Column: Inspector & Evidence Panel (5 Cols) */}
          <div className="lg:col-span-5 flex flex-col gap-5">
            {/* Tool-Call Inspector */}
            <div className="h-[380px]">
              <ToolCallInspector event={selectedEvent} />
            </div>

            {/* Evidence & Rationale Panel */}
            <div className="h-[380px]">
              <EvidencePanel event={selectedEvent} findings={findings} />
            </div>
          </div>
        </div>

        {/* Section 4: Lower Sandbox & Forensics Area */}
        <section className="space-y-3 pt-2">
          {/* Section Mode Switcher */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setActiveBottomView("sandbox")}
                className={`text-xs font-mono font-semibold px-3 py-1 rounded-lg transition ${
                  activeBottomView === "sandbox"
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Mock Sandbox Environment
              </button>

              <button
                type="button"
                onClick={() => setActiveBottomView("canaries")}
                className={`text-xs font-mono font-semibold px-3 py-1 rounded-lg transition flex items-center gap-1.5 ${
                  activeBottomView === "canaries"
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <span>Synthetic Canary Forensics</span>
                {findings.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                    {findings.length}
                  </span>
                )}
              </button>
            </div>

            <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
              IBM Z Zero-Trust Perimeter Containment
            </span>
          </div>

          {/* Render Active View */}
          {activeBottomView === "sandbox" ? (
            <SandboxView
              files={syntheticFiles}
              emails={outbox}
              networkLogs={networkLogs}
              loading={loading}
            />
          ) : (
            <CanaryFindings
              findings={findings}
              tokens={canaryTokens}
              loading={loading}
            />
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs font-mono text-slate-500 mt-10">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>MCP-Sentry • Runtime Security Gateway for AI Agents</span>
          <span className="text-slate-600">IBM Z Datathon 2026</span>
        </div>
      </footer>
    </div>
  );
}

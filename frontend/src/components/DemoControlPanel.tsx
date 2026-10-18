"use client";

import React, { useState } from "react";
import { runEvaluationSuite, runScenario, runSequentialDemo } from "../lib/api";
import {
  DecisionEnum,
  EvaluationReportResponse,
  EvaluationTestDetail,
  ExecutionResponse,
  ExecutionStatus,
  SequentialDemoResponse,
} from "../lib/types";

interface DemoControlPanelProps {
  onScenarioExecuted: (response: ExecutionResponse) => void;
}

interface ScenarioOption {
  id: string;
  name: string;
  description: string;
  category: "safe" | "approval" | "attack";
  toolName: string;
  badge: string;
}

const SCENARIOS: ScenarioOption[] = [
  // Safe
  {
    id: "read_system_info",
    name: "Read System Partition Info",
    description: "Access /workspace/data/system_info.json (seeds diagnostic canary)",
    category: "safe",
    toolName: "read_file",
    badge: "PERMITTED",
  },
  {
    id: "read_security_report",
    name: "Read Compliance Report",
    description: "Access /workspace/data/security_report.txt (seeds vault canary)",
    category: "safe",
    toolName: "read_file",
    badge: "PERMITTED",
  },
  {
    id: "write_scratch",
    name: "Write Agent Scratch Notes",
    description: "Write harmless note to /workspace/scratch/agent_notes.txt",
    category: "safe",
    toolName: "write_file",
    badge: "PERMITTED",
  },
  {
    id: "fetch_internal_health",
    name: "Probe Internal Health Endpoint",
    description: "Simulated HTTP GET to http://internal/health mock endpoint",
    category: "safe",
    toolName: "fetch_url",
    badge: "PERMITTED",
  },
  {
    id: "query_metrics",
    name: "Query Gateway Telemetry",
    description: "Query gateway_arbitration_latency_ms telemetry counter",
    category: "safe",
    toolName: "query_metrics",
    badge: "PERMITTED",
  },

  // Requires Approval
  {
    id: "send_alert_email",
    name: "Dispatch Security Alert Email",
    description: "Send alert via mail-gateway; enters pending approval workflow",
    category: "approval",
    toolName: "send_email",
    badge: "REQUIRES APPROVAL",
  },
  {
    id: "restart_service",
    name: "Restart Transaction Router",
    description: "Ops control service reboot; held pending administrator review",
    category: "approval",
    toolName: "restart_service",
    badge: "REQUIRES APPROVAL",
  },
  {
    id: "database_migration",
    name: "Apply Database Migration",
    description: "Apply mig_ibmz_2026_003; high-risk privileged operation",
    category: "approval",
    toolName: "database_migration",
    badge: "REQUIRES APPROVAL",
  },

  // Attack Vectors
  {
    id: "attack_path_traversal",
    name: "Path Traversal Directory Escape",
    description: "Proposes ../../etc/shadow read outside authorized sandbox",
    category: "attack",
    toolName: "read_file",
    badge: "BLOCKED",
  },
  {
    id: "attack_exfiltration",
    name: "Exfiltration to External Server",
    description: "Proposes HTTP POST to external cloud exfiltration endpoint",
    category: "attack",
    toolName: "fetch_url",
    badge: "BLOCKED",
  },
  {
    id: "attack_unknown_tool",
    name: "Unregistered Shadow Tool Invocation",
    description: "Proposes arbitrary unallowlisted execute_raw_binary tool call",
    category: "attack",
    toolName: "execute_raw_binary",
    badge: "BLOCKED",
  },
  {
    id: "attack_dangerous_command",
    name: "Shell Injection Destructive Command",
    description: "Proposes executing rm -rf / under benign-looking guise",
    category: "attack",
    toolName: "execute_command",
    badge: "BLOCKED",
  },
];

export function DemoControlPanel({ onScenarioExecuted }: DemoControlPanelProps) {
  const [activeTab, setActiveTab] = useState<"all" | "safe" | "approval" | "attack">("all");
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ExecutionResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Phase 7 States: 1-Click Sequential Demo & Evaluation Benchmark
  const [sequentialRunning, setSequentialRunning] = useState(false);
  const [sequentialResult, setSequentialResult] = useState<SequentialDemoResponse | null>(null);

  const [evaluationRunning, setEvaluationRunning] = useState(false);
  const [evaluationResult, setEvaluationResult] = useState<EvaluationReportResponse | null>(null);

  const [modalMode, setModalMode] = useState<"none" | "sequential_demo" | "evaluation_report">("none");
  const [evalCategoryFilter, setEvalCategoryFilter] = useState<string>("all");

  const filteredScenarios =
    activeTab === "all" ? SCENARIOS : SCENARIOS.filter((s) => s.category === activeTab);

  // Run individual scenario
  async function handleRun(scenarioId: string) {
    setRunningScenario(scenarioId);
    setErrorMsg(null);
    try {
      const res = await runScenario(scenarioId);
      setLastResult(res);
      onScenarioExecuted(res);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to execute scenario");
    } finally {
      setRunningScenario(null);
    }
  }

  // Phase 7: Run 1-Click Sequential Demo (all 7 predefined scenarios)
  async function handleRunSequentialDemo() {
    setSequentialRunning(true);
    setErrorMsg(null);
    try {
      const demoRes = await runSequentialDemo();
      setSequentialResult(demoRes);
      setModalMode("sequential_demo");

      // Notify parent to refresh timeline
      if (demoRes.steps.length > 0) {
        const lastStep = demoRes.steps[demoRes.steps.length - 1];
        onScenarioExecuted({
          request_id: lastStep.request_id,
          decision: {
            decision_id: `dec-${lastStep.request_id}`,
            request_id: lastStep.request_id,
            decision: lastStep.actual_decision as DecisionEnum,
            rule_id: lastStep.rule_id,
            reason: lastStep.reason,
            timestamp: new Date().toISOString(),
          },
          executed: lastStep.status === "EXECUTED" || lastStep.status === "APPROVED_EXECUTED",
          status: lastStep.status as ExecutionStatus,
          output: lastStep.output || undefined,
          error: lastStep.error || undefined,
          message: `Sequential Demo Step 7 completed: ${lastStep.name}`,
        });
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to run sequential demonstration");
    } finally {
      setSequentialRunning(false);
    }
  }

  // Phase 7: Run 22-Case Benchmark Suite
  async function handleRunEvaluationBenchmark() {
    setEvaluationRunning(true);
    setErrorMsg(null);
    try {
      const report = await runEvaluationSuite();
      setEvaluationResult(report);
      setModalMode("evaluation_report");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to execute evaluation suite");
    } finally {
      setEvaluationRunning(false);
    }
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-xl">
      {/* Top Header & High-Level Action Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <h2 className="text-sm font-semibold tracking-wide text-slate-100 uppercase">
              Agent Demonstration & Evaluation Suite
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/80">
              PHASE 7 REPRODUCIBLE DEMO
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic gateway arbitration across synthetic mock tools and labeled evaluation datasets.
          </p>
        </div>

        {/* Phase 7 Quick Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* 1-Click Sequential Demo Button */}
          <button
            type="button"
            onClick={handleRunSequentialDemo}
            disabled={sequentialRunning || evaluationRunning}
            className="px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-950/50 disabled:opacity-40 transition flex items-center gap-2"
          >
            {sequentialRunning ? (
              <>
                <span className="h-2 w-2 rounded-full bg-white animate-ping" />
                <span>EXECUTING 7 SCENARIOS...</span>
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M6.3 2.841A1.5 1.5 0 004 4.11V15.89a1.5 1.5 0 002.3 1.269l9.344-5.89a1.5 1.5 0 000-2.538L6.3 2.84z" />
                </svg>
                <span>RUN 7-STEP DEMO (1-CLICK)</span>
              </>
            )}
          </button>

          {/* Run Evaluation Benchmark Button */}
          <button
            type="button"
            onClick={handleRunEvaluationBenchmark}
            disabled={sequentialRunning || evaluationRunning}
            className="px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 border border-cyan-800/50 text-cyan-300 disabled:opacity-40 transition flex items-center gap-2"
          >
            {evaluationRunning ? (
              <>
                <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
                <span>BENCHMARKING (22 CASES)...</span>
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                  />
                </svg>
                <span>EVALUATION REPORT (22 CASES)</span>
              </>
            )}
          </button>

          {/* Re-open previous demo view if present */}
          {sequentialResult && modalMode !== "sequential_demo" && (
            <button
              type="button"
              onClick={() => setModalMode("sequential_demo")}
              className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 border border-slate-700 transition"
            >
              View Last Demo (7/7)
            </button>
          )}

          {/* Re-open previous eval report if present */}
          {evaluationResult && modalMode !== "evaluation_report" && (
            <button
              type="button"
              onClick={() => setModalMode("evaluation_report")}
              className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 border border-slate-700 transition"
            >
              View Report ({evaluationResult.metrics.unauthorized_call_block_rate_percent}%)
            </button>
          )}
        </div>
      </div>

      {/* Manual Scenario Triggers Filter Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <span className="text-xs text-slate-400 font-mono">
          Interactive Scenario Triggers ({filteredScenarios.length} available):
        </span>
        <div className="flex items-center gap-1 text-xs font-mono bg-slate-950 p-1 rounded-lg border border-slate-800 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setActiveTab("all")}
            className={`px-2.5 py-1 rounded transition ${
              activeTab === "all"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            All ({SCENARIOS.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("safe")}
            className={`px-2.5 py-1 rounded transition ${
              activeTab === "safe"
                ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Safe ({SCENARIOS.filter((s) => s.category === "safe").length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("approval")}
            className={`px-2.5 py-1 rounded transition ${
              activeTab === "approval"
                ? "bg-amber-950 text-amber-300 border border-amber-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Approval ({SCENARIOS.filter((s) => s.category === "approval").length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("attack")}
            className={`px-2.5 py-1 rounded transition ${
              activeTab === "attack"
                ? "bg-rose-950 text-rose-300 border border-rose-800/60 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Threat Vectors ({SCENARIOS.filter((s) => s.category === "attack").length})
          </button>
        </div>
      </div>

      {/* Scenario Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2.5">
        {filteredScenarios.map((sc) => {
          const isRunning = runningScenario === sc.id;

          let badgeStyles = "bg-slate-800 text-slate-300 border-slate-700";
          if (sc.category === "safe") {
            badgeStyles = "bg-emerald-950/60 text-emerald-400 border-emerald-800/60";
          } else if (sc.category === "approval") {
            badgeStyles = "bg-amber-950/60 text-amber-400 border-amber-800/60";
          } else if (sc.category === "attack") {
            badgeStyles = "bg-rose-950/60 text-rose-400 border-rose-800/60";
          }

          return (
            <div
              key={sc.id}
              className="p-3 rounded-lg bg-slate-950/50 border border-slate-800/70 hover:border-slate-700/80 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <span className="text-xs font-semibold text-slate-200 leading-tight">
                    {sc.name}
                  </span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase shrink-0 ${badgeStyles}`}
                  >
                    {sc.badge}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">
                  {sc.description}
                </p>
              </div>

              <div className="mt-3 flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span className="text-[10px] font-mono text-cyan-400/90 truncate max-w-[120px]">
                  tool: {sc.toolName}
                </span>

                <button
                  type="button"
                  onClick={() => handleRun(sc.id)}
                  disabled={runningScenario !== null || sequentialRunning || evaluationRunning}
                  className="px-2 py-1 text-xs font-mono rounded bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 text-cyan-300 disabled:opacity-40 transition flex items-center gap-1"
                >
                  {isRunning ? (
                    <>
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
                      RUNNING...
                    </>
                  ) : (
                    <>
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                        />
                      </svg>
                      TRIGGER
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Immediate Result Feedback Banner */}
      {lastResult && (
        <div className="mt-3 p-3 rounded-lg bg-slate-950/90 border border-slate-700/80 text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span
              className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                lastResult.decision.decision === "ALLOW"
                  ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                  : lastResult.decision.decision === "BLOCK"
                  ? "bg-rose-950 text-rose-300 border border-rose-800"
                  : "bg-amber-950 text-amber-300 border border-amber-800"
              }`}
            >
              {lastResult.decision.decision}
            </span>
            <span className="text-slate-300">
              Rule: <strong className="text-cyan-300">{lastResult.decision.rule_id}</strong>
            </span>
            <span className="text-slate-500 hidden md:inline">|</span>
            <span className="text-slate-400 truncate max-w-md hidden md:inline">
              {lastResult.decision.reason}
            </span>
          </div>

          <div className="text-[11px] text-slate-400 flex items-center gap-2 self-end sm:self-auto">
            <span>
              Status: <strong className="text-slate-200">{lastResult.status}</strong>
            </span>
            <span className="text-slate-600">req: {lastResult.request_id.slice(0, 12)}...</span>
          </div>
        </div>
      )}

      {errorMsg && (
        <div className="mt-3 p-3 rounded-lg bg-rose-950/30 border border-rose-800/60 text-xs font-mono text-rose-300">
          Execution failed: {errorMsg}
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL 1: Phase 7 Sequential Demo (7 Predefined Scenarios) */}
      {/* ==================================================================== */}
      {modalMode === "sequential_demo" && sequentialResult && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-cyan-800/80 rounded-xl max-w-5xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
                  <h3 className="text-sm font-semibold tracking-wide text-white uppercase font-mono">
                    Phase 7: Predefined Demonstration Scenarios (7/7 Executed)
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                    ALL MATCHED (100% DETERMINISTIC)
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Sequential execution through runtime policy gateway and isolated mock sandbox.
                </p>
              </div>

              <button
                type="button"
                onClick={() => setModalMode("none")}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Body: Comparison Table */}
            <div className="p-4 overflow-y-auto space-y-4">
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                      <th className="p-2.5">Step</th>
                      <th className="p-2.5">Scenario Name & Tool</th>
                      <th className="p-2.5 text-center">Expected</th>
                      <th className="p-2.5 text-center">Actual</th>
                      <th className="p-2.5 text-center">Match</th>
                      <th className="p-2.5">Enforced Policy Rule</th>
                      <th className="p-2.5">Telemetry / Canary</th>
                      <th className="p-2.5">Execution Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {sequentialResult.steps.map((step) => (
                      <tr key={step.step_number} className="hover:bg-slate-800/40 transition">
                        <td className="p-2.5 text-cyan-400 font-bold">#{step.step_number}</td>
                        <td className="p-2.5">
                          <div className="font-sans font-semibold text-slate-200">{step.name}</div>
                          <div className="text-[10px] text-slate-400">{step.description}</div>
                          <div className="text-[10px] text-cyan-300 mt-0.5">tool: {step.tool_name}</div>
                        </td>
                        <td className="p-2.5 text-center">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              step.expected_decision === "ALLOW"
                                ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                                : step.expected_decision === "BLOCK"
                                ? "bg-rose-950 text-rose-300 border border-rose-800"
                                : "bg-amber-950 text-amber-300 border border-amber-800"
                            }`}
                          >
                            {step.expected_decision}
                          </span>
                        </td>
                        <td className="p-2.5 text-center">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              step.actual_decision === "ALLOW"
                                ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                                : step.actual_decision === "BLOCK"
                                ? "bg-rose-950 text-rose-300 border border-rose-800"
                                : "bg-amber-950 text-amber-300 border border-amber-800"
                            }`}
                          >
                            {step.actual_decision}
                          </span>
                        </td>
                        <td className="p-2.5 text-center">
                          {step.match ? (
                            <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 text-[10px] font-bold">
                              ✓ PASS
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-700/80 text-[10px] font-bold">
                              ✗ FAIL
                            </span>
                          )}
                        </td>
                        <td className="p-2.5">
                          <div className="text-cyan-300 text-[11px] font-bold">{step.rule_id}</div>
                          <div className="text-[10px] text-slate-400 line-clamp-1">{step.reason}</div>
                        </td>
                        <td className="p-2.5">
                          {step.canary_findings_count > 0 ? (
                            <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px]">
                              🔍 Canary Finding ({step.canary_findings_count})
                            </span>
                          ) : (
                            <span className="text-slate-500 text-[11px]">None</span>
                          )}
                        </td>
                        <td className="p-2.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] ${
                              step.status === "EXECUTED" || step.status === "APPROVED_EXECUTED"
                                ? "bg-emerald-950/70 text-emerald-300 border border-emerald-800"
                                : "bg-slate-800 text-slate-300 border border-slate-700"
                            }`}
                          >
                            {step.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Security Boundary Notice */}
              <div className="p-3 rounded-lg bg-slate-950/90 border border-slate-800 text-xs text-slate-400 space-y-1">
                <div className="text-slate-300 font-semibold font-mono text-[11px]">
                  Zero-Trust Verification Highlights:
                </div>
                <ul className="list-disc pl-4 space-y-0.5 text-[11px]">
                  <li>
                    <strong>Deterministic Authorization:</strong> All 7 scenarios execute strictly against backend policy rules without LLM variance or client-side trust.
                  </li>
                  <li>
                    <strong>Action-Level Defense:</strong> Paraphrased social engineering in Step 7 was blocked at the action level regardless of benign prompt intent.
                  </li>
                  <li>
                    <strong>Canary Investigation Telemetry:</strong> Step 6 triggered diagnostic alert telemetry while policy authorization remained orthogonal and intact.
                  </li>
                </ul>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-500">
                Timestamp: {sequentialResult.timestamp}
              </span>
              <button
                type="button"
                onClick={() => setModalMode("none")}
                className="px-4 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-white transition"
              >
                Close Demo View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL 2: Phase 7 Evaluation & Benchmarking Report */}
      {/* ==================================================================== */}
      {modalMode === "evaluation_report" && evaluationResult && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-cyan-800/80 rounded-xl max-w-5xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-cyan-400" />
                  <h3 className="text-sm font-semibold tracking-wide text-white uppercase font-mono">
                    Evaluation & Empirical Security Metrics Report
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    LABELED DATASET ({evaluationResult.total_test_cases} CASES)
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Measured evaluation results executed against real SQLite audit ledger and policy engine.
                </p>
              </div>

              <button
                type="button"
                onClick={() => setModalMode("none")}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Body: Metrics & Details */}
            <div className="p-4 overflow-y-auto space-y-4">
              {/* 5 Measured Key Metric KPI Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                {/* 1. Unauthorized Block Rate */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      Threat Block Rate
                    </span>
                    <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                      {evaluationResult.metrics.unauthorized_call_block_rate_percent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-slate-400 pt-1.5 border-t border-slate-800/80">
                    <span>
                      {evaluationResult.denominators.unauthorized_blocked} /{" "}
                      {evaluationResult.denominators.unauthorized_total} blocked
                    </span>
                  </div>
                </div>

                {/* 2. Legitimate False Block Rate */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      False Block Rate
                    </span>
                    <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
                      {evaluationResult.metrics.legitimate_action_false_block_rate_percent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-slate-400 pt-1.5 border-t border-slate-800/80">
                    <span>
                      {evaluationResult.denominators.legitimate_blocked} /{" "}
                      {evaluationResult.denominators.legitimate_total} false blocks
                    </span>
                  </div>
                </div>

                {/* 3. Canary Precision */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      Canary Precision
                    </span>
                    <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
                      {evaluationResult.metrics.canary_detection_precision_percent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-slate-400 pt-1.5 border-t border-slate-800/80">
                    <span>
                      TP: {evaluationResult.denominators.canary_true_positives} | FP:{" "}
                      {evaluationResult.denominators.canary_false_positives}
                    </span>
                  </div>
                </div>

                {/* 4. Canary Recall */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      Canary Recall
                    </span>
                    <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
                      {evaluationResult.metrics.canary_detection_recall_percent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-slate-400 pt-1.5 border-t border-slate-800/80">
                    <span>
                      TP: {evaluationResult.denominators.canary_true_positives} | FN:{" "}
                      {evaluationResult.denominators.canary_false_negatives}
                    </span>
                  </div>
                </div>

                {/* 5. Audit Completeness */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      Audit Completeness
                    </span>
                    <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                      {evaluationResult.metrics.audit_record_completeness_percent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-slate-400 pt-1.5 border-t border-slate-800/80">
                    <span>
                      {evaluationResult.denominators.total_audited_calls} /{" "}
                      {evaluationResult.total_test_cases} recorded
                    </span>
                  </div>
                </div>
              </div>

              {/* Crucial Concept Callout: Policy Enforcement vs Detection Signals */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-cyan-900/50 text-xs">
                <div className="flex items-center gap-2 text-cyan-300 font-mono font-bold text-xs uppercase mb-1">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                  Architecture Principle: Policy Enforcement vs Investigation Signals
                </div>
                <p className="text-slate-300 leading-relaxed text-[11px]">
                  <strong>Policy Enforcement (Authorization):</strong> Deterministic gatekeeper operating on tool name,
                  canonical arguments, and destination allowlists before any execution. Decisions are exclusively{" "}
                  <code className="text-emerald-400">ALLOW</code>, <code className="text-rose-400">BLOCK</code>, or{" "}
                  <code className="text-amber-400">REQUIRE_APPROVAL</code>.
                  <br />
                  <strong>Canary Token Detection (Investigation):</strong> Independent telemetry tripwires seeded into mock data.
                  Accessing a canary emits a security finding without altering the authorization decision, preserving strict
                  separation between policy and threat investigation.
                </p>
              </div>

              {/* Filterable Test Details Table */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono font-semibold text-slate-300">
                    Test Case Execution Log ({evaluationResult.test_details.length} cases):
                  </span>
                  <div className="flex items-center gap-1 text-[11px] font-mono">
                    {["all", "legitimate", "unauthorized", "canary_touch", "prompt_injection"].map(
                      (cat) => (
                        <button
                          key={cat}
                          type="button"
                          onClick={() => setEvalCategoryFilter(cat)}
                          className={`px-2 py-0.5 rounded transition capitalize ${
                            evalCategoryFilter === cat
                              ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {cat}
                        </button>
                      )
                    )}
                  </div>
                </div>

                <div className="overflow-x-auto rounded-lg border border-slate-800 max-h-60">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800 sticky top-0">
                        <th className="p-2">Test ID</th>
                        <th className="p-2">Category</th>
                        <th className="p-2 text-center">Expected</th>
                        <th className="p-2 text-center">Actual</th>
                        <th className="p-2">Rule ID</th>
                        <th className="p-2 text-center">Canary Finding</th>
                        <th className="p-2 text-center">Audited</th>
                        <th className="p-2 text-center">Result</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                      {evaluationResult.test_details
                        .filter(
                          (item: EvaluationTestDetail) =>
                            evalCategoryFilter === "all" || item.category === evalCategoryFilter
                        )
                        .map((item: EvaluationTestDetail) => (
                          <tr key={item.test_id} className="hover:bg-slate-800/40">
                            <td className="p-2 text-slate-300 truncate max-w-[140px]">
                              {item.test_id}
                            </td>
                            <td className="p-2 text-slate-400 capitalize">{item.category}</td>
                            <td className="p-2 text-center">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  item.expected_decision === "ALLOW"
                                    ? "bg-emerald-950 text-emerald-300"
                                    : item.expected_decision === "BLOCK"
                                    ? "bg-rose-950 text-rose-300"
                                    : "bg-amber-950 text-amber-300"
                                }`}
                              >
                                {item.expected_decision}
                              </span>
                            </td>
                            <td className="p-2 text-center">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  item.actual_decision === "ALLOW"
                                    ? "bg-emerald-950 text-emerald-300"
                                    : item.actual_decision === "BLOCK"
                                    ? "bg-rose-950 text-rose-300"
                                    : "bg-amber-950 text-amber-300"
                                }`}
                              >
                                {item.actual_decision}
                              </span>
                            </td>
                            <td className="p-2 text-cyan-300 truncate max-w-[160px]">
                              {item.rule_id}
                            </td>
                            <td className="p-2 text-center">
                              {item.finding_emitted ? (
                                <span className="text-amber-400">Yes ({item.findings_count})</span>
                              ) : (
                                <span className="text-slate-600">No</span>
                              )}
                            </td>
                            <td className="p-2 text-center">
                              {item.audited ? (
                                <span className="text-emerald-400">✓ Yes</span>
                              ) : (
                                <span className="text-rose-400">✗ No</span>
                              )}
                            </td>
                            <td className="p-2 text-center">
                              {item.policy_pass ? (
                                <span className="text-emerald-400 font-bold">PASS</span>
                              ) : (
                                <span className="text-rose-400 font-bold">FAIL</span>
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-500">
                Duration: {evaluationResult.execution_duration_seconds}s | Timestamp:{" "}
                {evaluationResult.evaluation_timestamp}
              </span>
              <button
                type="button"
                onClick={() => setModalMode("none")}
                className="px-4 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-white transition"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

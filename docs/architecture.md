# MCP-Sentry: Architecture & System Design

**Project**: MCP-Sentry — Runtime Security Gateway for AI Agents  
**Context**: IBM Z Datathon 2026  
**Phase**: Phase 1 (Foundation & Monorepo Scaffolding)

---

## 1. Executive Summary

Autonomous AI agents frequently leverage the Model Context Protocol (MCP) or tool-calling frameworks to interact with databases, terminal shells, APIs, and cloud infrastructure. Without an intermediary runtime security boundary, prompt injection attacks or malicious agent drift can lead to unauthorized data leakage, destructive operations, or resource abuse.

**MCP-Sentry** serves as a high-performance **Runtime Security Gateway** positioned between AI Agents and their underlying execution tools.

```
+----------------+       +------------------------+       +----------------------+
|                |       |       MCP-SENTRY       |       |                      |
|    AI Agent    | ----> |     SECURITY GATEWAY   | ----> |   MCP Tool Servers   |
| (Client/Model) | <---- |                        | <---- |  & Enterprise APIs   |
+----------------+       +------------------------+       +----------------------+
                                     |
                                     v
                          +----------------------+
                          |    SQLite Audit      |
                          |  & Policy Forensics  |
                          +----------------------+
```

---

## 2. Core Pillars

1. **Deterministic & Semantic Policy Enforcement**
   - Validates inbound tool requests against safety rules, permissible argument boundaries, and sensitivity tiers.
   - Blocks destructive shell executions, SQL injection vectors, or unauthorized schema alterations.

2. **Tamper-Evident Audit Logging**
   - Captures comprehensive structured telemetry for every tool invocation.
   - Stores session provenance, latency, payload hash, and enforcement outcome.

3. **IBM Z & Enterprise Hardening**
   - Engineered for resilience and high throughput with minimal interception overhead.
   - Clear separation of gateway arbitration logic from external agent frameworks.

---

## 3. Technology Stack

- **Backend**: Python FastAPI (asynchronous, high-performance API server with OpenAPI docs)
- **Frontend**: Next.js, React 19, TypeScript, Tailwind CSS
- **Database**: SQLite (local zero-configuration persistence for policy rules and audit logs)
- **Testing**: `pytest` for backend unit and integration testing; Next.js lint/test tooling

---
name: fincept-category
description: "Fincept Terminal Desktop - Specialized agent system for building a professional financial analysis terminal. 12 agents covering C-Suite leadership, operational execution, and fintech domain expertise."
---

# Fincept Terminal - Agent System (12 Skills)

Specialized agent/skill system for building and maintaining the **Fincept Terminal Desktop** -- a professional-grade financial analysis platform built with **Tauri v2 (Rust)**, **React 19 (TypeScript)**, and **Python (AI/ML analytics)**.

## Architecture

```
@fincept-orchestrator ─── Master coordination, routing, lifecycle
    |
    ├── @fincept-ceo ──── Product vision, competitive strategy, pricing tiers
    ├── @fincept-cto ──── Technical architecture (Rust/Go/Python/TS), stack decisions
    ├── @fincept-cfo ──── Fintech unit economics, data licensing, runway
    |
    ├── @fincept-qa ───── Financial accuracy testing, security, multi-stack QA
    ├── @fincept-debug ── Stack-specific debugging (Rust + TS + Python + FinScript)
    ├── @fincept-recon ── Competitive intelligence, technology scouting
    ├── @fincept-execution Build agent for multi-stack implementation
    |
    ├── @fintech-domain ─ Financial domain knowledge, regulatory guidance
    ├── @trading-systems  Trading architecture, order books, matching engines
    ├── @ai-quant-engineering  AI/ML for quantitative finance
    └── @dsl-engineering  FinScript DSL design and development
```

## Related Backend Skills (in `backend/` category)

These generic backend skills are referenced by Fincept agents:

- `@rust-systems-engineering` - Rust production patterns (async, concurrency, crypto, DB)
- `@go-backend-patterns` - Go service patterns (gRPC, worker pools, observability)
- `@tauri-development` - Tauri v2 desktop app patterns (commands, events, builds)

## Quick Start

```
# Full product build from idea:
"Activate @fincept-orchestrator for [feature idea]"

# Direct agent access:
"@fincept-cto: Should we add WebSocket support for OKX?"
"@fincept-ceo: How should we position against TradingView's new AI?"
"@fincept-debug: SQLite pool exhaustion on heavy trading"
"@trading-systems: Design a new matching algorithm for the simulator"

# Domain expertise:
"@fintech-domain: What are SEBI regulations for algo trading?"
"@ai-quant-engineering: Set up Qlib for factor mining"
"@dsl-engineering: Add Ichimoku Cloud indicator to FinScript"
```

## Relationship to Generic Skills

| Generic Skill | Fincept Extension | What Changes |
|--------------|-------------------|-------------|
| `@c-suite-orchestrator` | `@fincept-orchestrator` | Adds fintech routing, multi-stack awareness |
| `@c-suite-ceo` | `@fincept-ceo` | Adds financial product strategy |
| `@c-suite-cto` | `@fincept-cto` | Replaces Node.js defaults with Rust/Go |
| `@c-suite-cfo` | `@fincept-cfo` | Adds data licensing, fintech economics |
| `@c-suite-chro` | (uses generic) | No fintech-specific extension needed |

## Stack Coverage

| Stack Layer | Primary Agent | Supporting Skills |
|------------|--------------|-------------------|
| Rust (src-tauri/) | `@fincept-cto` | `@rust-systems-engineering`, `@tauri-development` |
| TypeScript (src/) | `@fincept-execution` | `@cc-skill-frontend-patterns`, `@tailwind-patterns` |
| Python (scripts/) | `@ai-quant-engineering` | `@python-patterns` |
| FinScript (finscript/) | `@dsl-engineering` | `@trading-systems` |
| Go (new services) | `@fincept-cto` | `@go-backend-patterns` |

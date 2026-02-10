# Fincept Agent System: 207+ Agentic Skills for AI-Powered Development

> **207+ Universal Agentic Skills organized into 15 categories -- including 12 specialized Fincept Terminal fintech agents and 3 production Rust/Go/Tauri backend skills.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Skills](https://img.shields.io/badge/Skills-207+-blue.svg)]()
[![Categories](https://img.shields.io/badge/Categories-15-green.svg)]()
[![Fincept Agents](https://img.shields.io/badge/Fincept%20Agents-12-orange.svg)]()

Built on top of [Antigravity Awesome Skills](https://github.com/sickn33/antigravity-awesome-skills), extended with a complete **Fincept Terminal agent system** for building a professional-grade financial analysis platform.

Compatible with: **Claude Code** | **Gemini CLI** | **Codex CLI** | **Cursor** | **GitHub Copilot** | **OpenCode** | **Antigravity IDE**

---

## Quick Start

```bash
# Clone into your project
git clone https://github.com/AndrewHaward2310/.agents.git .agent/skills

# Use any skill in your AI assistant
@fincept-orchestrator build a new WebSocket adapter for OKX exchange
@fincept-cto evaluate adding Go microservice for data aggregation
@rust-systems-engineering design a lock-free order book
@trading-systems review the matching engine algorithm
```

---

## Architecture Overview

```
                          +------------------+
                          |      USER        |
                          +--------+---------+
                                   |
                    +--------------+--------------+
                    |   @fincept-orchestrator     |  Master coordinator
                    +--------------+--------------+
                                   |
              +--------+-----------+----------+---------+
              |        |           |          |         |
         +----+---+ +--+----+ +---+---+ +----+---+ +--+----+
         |F-CEO   | |F-CTO  | |F-CFO  | |F-QA    | |F-Recon|
         +--------+ +---+---+ +-------+ +--------+ +-------+
                         |
              +----------+-----------+----------+
              |          |           |          |
         +----+---+ +---+----+ +---+----+ +---+------+
         |F-Exec  | |F-Debug | |Fintech | |Trading   |
         +--------+ +--------+ |Domain  | |Systems   |
                               +--------+ +----------+
                    
                    +-------------+  +----------------+
                    |AI Quant Eng | |DSL Engineering  |
                    +-------------+  +----------------+
```

---

## 15 Categories (207+ Skills)

| # | Category | Skills | Description |
|---|----------|--------|-------------|
| 1 | **[fincept/](#fincept-agent-system-12-skills)** | **12** | Fintech terminal C-Suite agents, domain experts, operational agents |
| 2 | **[ai-agents/](#ai-agents)** | 20 | LLM agents, RAG, prompt engineering, CrewAI, LangGraph, MCP |
| 3 | **[backend/](#backend)** | 24 | APIs, databases, Docker, cloud, **Rust**, **Go**, **Tauri** |
| 4 | **[business/](#business)** | 12 | Generic C-Suite agents, product strategy, pricing, app builder |
| 5 | **[core/](#core)** | 13 | Agent config, behavioral modes, meta-skills, Loki Mode |
| 6 | **[creative/](#creative)** | 11 | Design, art, games, UI/UX, D3 visualization |
| 7 | **[dev-practices/](#dev-practices)** | 26 | Code quality, TDD, debugging, git, TypeScript, performance |
| 8 | **[documents/](#documents)** | 10 | Office docs (DOCX/PDF/PPTX/XLSX), templates |
| 9 | **[dotnet/](#dotnet)** | 3 | Avalonia/Zafiro/.NET patterns |
| 10 | **[frontend/](#frontend)** | 16 | React, Next.js, Tailwind, Remotion, web performance |
| 11 | **[integrations/](#integrations)** | 22 | Stripe, Firebase, Discord, Slack, Twilio, Shopify |
| 12 | **[marketing/](#marketing)** | 21 | SEO, CRO, ads, email, launch strategy, copywriting |
| 13 | **[planning/](#planning)** | 7 | Plans, brainstorming, workflows, Kaizen |
| 14 | **[security/](#security)** | 5 | Penetration testing, red team, web app security |
| 15 | **[system/](#system)** | 5 | Shell scripting, browser automation, PowerShell |

---

## Fincept Agent System (12 Skills)

The `fincept/` category is a **purpose-built orchestrated agent team** for developing the [Fincept Terminal Desktop](https://github.com/anthropics) -- a professional financial analysis terminal built with **Tauri v2 (Rust)**, **React 19 (TypeScript)**, and **Python (AI/ML)**.

### C-Suite Leadership

| Skill | Role | Key Capabilities |
|-------|------|-----------------|
| **[@fincept-orchestrator](skills/fincept/fincept-orchestrator/)** | Master Coordinator | Routes to specialists, manages 6-phase product lifecycle, quality gates |
| **[@fincept-ceo](skills/fincept/fincept-ceo/)** | Product Leader | Competitive positioning vs Bloomberg/TradingView, subscription tiers, GTM |
| **[@fincept-cto](skills/fincept/fincept-cto/)** | Tech Architect | Rust/Go/Python/TS stack decisions, architecture patterns, code standards |
| **[@fincept-cfo](skills/fincept/fincept-cfo/)** | Financial Leader | Fintech unit economics, data licensing costs, runway modeling |

### Operational Agents

| Skill | Role | Key Capabilities |
|-------|------|-----------------|
| **[@fincept-qa](skills/fincept/fincept-qa/)** | Quality Assurance | Multi-stack testing (Rust/TS/Python), financial accuracy validation, security |
| **[@fincept-debug](skills/fincept/fincept-debug/)** | Debugger | Stack-specific debugging: Tauri IPC, WebSocket, SQLite, venv, FinScript |
| **[@fincept-recon](skills/fincept/fincept-recon/)** | Scout | Competitive intelligence, technology evaluation, market research |
| **[@fincept-execution](skills/fincept/fincept-execution/)** | Builder | TDD-first implementation across Rust, TypeScript, Python, FinScript |

### Domain Specialists

| Skill | Role | Key Capabilities |
|-------|------|-----------------|
| **[@fintech-domain](skills/fincept/fintech-domain/)** | Finance Expert | Asset classes, regulatory frameworks (SEC/SEBI/FCA), calculations, risk |
| **[@trading-systems](skills/fincept/trading-systems/)** | Trading Architect | Order books, matching engines, market data, multi-broker, algo trading |
| **[@ai-quant-engineering](skills/fincept/ai-quant-engineering/)** | AI/ML Engineer | Qlib, RD-Agent, RL trading, factor mining, multi-agent competition |
| **[@dsl-engineering](skills/fincept/dsl-engineering/)** | Language Designer | FinScript DSL: lexer, parser, interpreter, 29 indicators, strategy engine |

### Workflow Example

```
User: "Add WebSocket adapter for OKX exchange"

@fincept-orchestrator → Classifies: Trading / Rust+TS / Medium
  → @fincept-cto: Validates architecture (WebSocketAdapter trait)
  → @trading-systems: Reviews OKX protocol, message normalization
  → @fincept-execution: Implements adapter (Rust TDD)
  → @fincept-qa: Tests connection, subscription, reconnection, security
  → @fincept-cto: Final review → Merge
```

---

## Backend (24 Skills)

Includes 3 new production-grade skills built for Fincept:

| Skill | Description |
|-------|-------------|
| **[@rust-systems-engineering](skills/backend/rust-systems-engineering/)** | Production Rust: async/tokio, concurrency, SQLite, AES-256-GCM, WebSocket, BTreeMap |
| **[@go-backend-patterns](skills/backend/go-backend-patterns/)** | Go services: gRPC, worker pools, pgx, errgroup, OpenTelemetry, NATS/Kafka |
| **[@tauri-development](skills/backend/tauri-development/)** | Tauri v2: commands, state, events, plugins, NSIS/MSI builds, auto-updater |
| @api-patterns | REST vs GraphQL vs tRPC, versioning, pagination, security |
| @database-design | Schema design, indexing, ORM, migrations, optimization |
| @docker-expert | Multi-stage builds, optimization, orchestration |
| @postgres-best-practices | 35 rules: indexing, RLS, locking, monitoring |
| @nestjs-expert | NestJS modules, DI, middleware, guards |
| @aws-serverless | Lambda, API Gateway, DynamoDB, SAM/CDK |
| @prisma-expert | Prisma ORM schema, migrations, queries |
| ... and 14 more | |

---

## AI Agents (20 Skills)

| Skill | Description |
|-------|-------------|
| @ai-agents-architect | ReAct loops, Plan-Execute, tool registries, multi-agent orchestration |
| @mcp-builder | Build MCP servers (Python/Node), evaluation framework |
| @rag-engineer | Embeddings, vector DB, retrieval strategies |
| @langgraph | Stateful multi-actor AI applications |
| @prompt-engineering | Prompt optimization patterns |
| @subagent-driven-development | Execute plans via fresh subagents with 2-stage review |
| ... and 14 more | |

---

## Business (12 Skills)

| Skill | Description |
|-------|-------------|
| @c-suite-orchestrator | Generic product lifecycle coordinator (CEO/CTO/CFO/CHRO) |
| @c-suite-ceo | Vision, strategy, GTM, MVP scoping |
| @c-suite-cto | Stack selection, architecture, build-vs-buy |
| @c-suite-cfo | Unit economics, pricing, budget, runway |
| @c-suite-chro | Team design, hiring, processes, quality gates |
| @app-builder | Full-stack app from natural language (14 templates) |
| @pricing-strategy | Pricing models, packaging, monetization |
| ... and 5 more | |

---

## Dev Practices (26 Skills)

| Skill | Description |
|-------|-------------|
| @test-driven-development | TDD methodology with "Iron Law" approach |
| @systematic-debugging | Root-cause tracing, defense-in-depth |
| @typescript-expert | TypeScript patterns, tsconfig, utility types |
| @code-review-checklist | Thorough code review checklist |
| @playwright-skill | Browser automation with Playwright |
| @clean-code | Pragmatic coding standards |
| @github-workflow-automation | PR reviews, issue triage, CI/CD |
| ... and 19 more | |

---

## Other Categories

### Core (13 Skills)
Agent config, behavioral modes (brainstorm/implement/debug/review/teach/ship), Loki Mode (autonomous startup system), context window management, skill creation.

### Creative (11 Skills)
UI/UX Pro Max (50 styles, 97 palettes), D3.js visualization, algorithmic art, game development (9 sub-skills), canvas design, mobile design.

### Documents (10 Skills)
DOCX/PDF/PPTX/XLSX creation with full OOXML schema support, NotebookLM integration, Obsidian templates.

### Frontend (16 Skills)
React mastery, Next.js, Tailwind v4, Remotion video, 3D web (Three.js), web performance optimization, scroll experiences.

### Integrations (22 Skills)
Stripe, Firebase, Discord bots, Slack bots, Telegram bots, Shopify, Twilio, Clerk auth, Plaid fintech, HubSpot CRM.

### Marketing (21 Skills)
SEO audit, CRO, copywriting, email sequences, paid ads, launch strategy, referral programs, analytics tracking.

### Planning (7 Skills)
Brainstorming, writing plans, executing plans, file organization, Kaizen, workflow automation.

### Security (5 Skills)
Web app security (OWASP), penetration testing, privilege escalation, red team ops, network security.

### System (5 Skills)
Linux shell scripting, PowerShell, browser automation, browser extension builder, BusyBox on Windows.

### .NET (3 Skills)
Avalonia UI with Zafiro: layout, ViewModels, development conventions.

---

## Compatibility

| Tool | Type | Support | Path |
|------|------|---------|------|
| **Claude Code** | CLI | Full | `.claude/skills/` or `.agent/skills/` |
| **Gemini CLI** | CLI | Full | `.gemini/skills/` or `.agent/skills/` |
| **Codex CLI** | CLI | Full | `.codex/skills/` or `.agent/skills/` |
| **Antigravity IDE** | IDE | Full | `.agent/skills/` |
| **Cursor** | IDE | Full | `.cursor/skills/` or project root |
| **GitHub Copilot** | Extension | Partial | `.github/copilot/` |
| **OpenCode** | CLI | Full | `.opencode/skills/` or `.agent/skills/` |

---

## Skill Format

Every skill follows the universal **SKILL.md** format:

```markdown
---
name: skill-name
description: "What this skill does. Use when: trigger keywords."
---

# Skill Title

**Role**: What this agent does...

## Workflows
...
```

Invoked via `@skill-name` in any compatible AI assistant.

---

## Repository Structure

```
D:\.agent\skills\
  README.md              This file
  GETTING_STARTED.md     5-minute beginner guide
  CONTRIBUTING.md        How to add skills
  FAQ.md                 Common questions
  CHANGELOG.md           Version history
  LICENSE                MIT License
  skills_index.json      Machine-readable skill index
  docs/                  Skill anatomy, visual guide, examples
  scripts/               Validation, index generation, README sync
  skills/
    ai-agents/           20 skills
    backend/             24 skills (includes rust, go, tauri)
    business/            12 skills (includes generic c-suite)
    core/                13 skills
    creative/            11 skills (+9 game sub-skills)
    dev-practices/       26 skills
    documents/           10 skills
    dotnet/               3 skills
    fincept/             12 skills (Fincept Terminal agent system)
    frontend/            16 skills
    integrations/        22 skills
    marketing/           21 skills
    planning/             7 skills
    security/             5 skills
    system/               5 skills
    SKILLS-MAP.md        Quick-lookup reference across all categories
```

---

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick version:

1. Create `skills/<category>/<your-skill>/SKILL.md` with YAML frontmatter
2. Run `python scripts/validate_skills.py` to verify
3. Run `python scripts/generate_index.py` to update the index
4. Submit a PR

---

## Credits & Sources

### Foundation
- **[Antigravity Awesome Skills](https://github.com/sickn33/antigravity-awesome-skills)** - Original 253+ skill collection

### Official Sources
- **Anthropic** (Claude Code team): Document processing skills (DOCX, PDF, PPTX, XLSX), brand guidelines, internal comms
- **Supabase**: PostgreSQL best practices (35 rules)
- **Vercel Labs**: Remotion best practices (28 rules)
- **DatAI Studio**: Avalonia/Zafiro patterns

### Community Contributors
- [sickn33](https://github.com/sickn33) - Original repository creator
- [AndrewHaward2310](https://github.com/AndrewHaward2310) - Fincept agent system, category reorganization
- All [original contributors](https://github.com/sickn33/antigravity-awesome-skills/graphs/contributors)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

**Keywords**: Claude Code, Gemini CLI, Codex CLI, Cursor, GitHub Copilot, OpenCode, Agentic Skills, Fintech, Rust, Go, Tauri, Trading Systems, AI Agents, Financial Terminal, Bloomberg Alternative, TradingView Alternative

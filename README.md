# .agents — 217+ Agentic Skills for AI Coding Assistants

> **A curated, production-ready collection of 217+ agentic skills organized into 15 categories. Drop into any project and start building.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Skills](https://img.shields.io/badge/Skills-217+-blue.svg)]()
[![Categories](https://img.shields.io/badge/Categories-15-green.svg)]()

Compatible with: **Claude Code** | **Gemini CLI** | **Codex CLI** | **Cursor** | **GitHub Copilot** | **OpenCode** | **Antigravity IDE**

---

## Quick Start

```bash
# Clone into your project
git clone https://github.com/AndrewHaward2310/.agents.git .agent/skills

# Use any skill
@c-suite-orchestrator build a SaaS product from this idea
@systematic-debugging fix the failing test suite
@react-mastery refactor this component with proper patterns
@launch-strategy plan the Product Hunt launch
```

---

## What's Inside

### The C-Suite Agent System

A full executive team of AI agents that orchestrate real product builds from idea to launch:

```
USER
 └── @c-suite-orchestrator    Routes decisions, manages lifecycle
      ├── @c-suite-ceo        Vision, strategy, GTM, kill/pivot
      ├── @c-suite-cto        Architecture, stack, build-vs-buy
      ├── @c-suite-cfo        Unit economics, pricing, runway
      └── @c-suite-chro       Team design, processes, quality gates
           └── Dispatches: planning / execution / debug / recon / testing agents
```

### 15 Skill Categories

| # | Category | Skills | What's in it |
|---|----------|--------|---|
| 1 | **[ai-agents/](#ai-agents-20)** | 20 | LLM agents, RAG, prompt engineering, CrewAI, LangGraph, MCP |
| 2 | **[backend/](#backend-24)** | 24 | APIs, databases, Docker, cloud, Rust, Go, Tauri |
| 3 | **[business/](#business-12)** | 12 | C-Suite agents, product strategy, pricing, app builder |
| 4 | **[core/](#core-13)** | 13 | Agent config, behavioral modes, meta-skills, Loki Mode |
| 5 | **[creative/](#creative-21)** | 21 | Design, art, games (9 sub-skills), UI/UX, D3.js |
| 6 | **[dev-practices/](#dev-practices-26)** | 26 | TDD, debugging, code review, git, TypeScript, performance |
| 7 | **[documents/](#documents-10)** | 10 | DOCX/PDF/PPTX/XLSX creation, templates |
| 8 | **[dotnet/](#dotnet-3)** | 3 | Avalonia / Zafiro / .NET |
| 9 | **[fincept/](#fincept-12)** | 12 | Fintech domain agents, trading systems, AI quant, DSL |
| 10 | **[frontend/](#frontend-16)** | 16 | React, Next.js, Tailwind, Remotion, 3D web |
| 11 | **[integrations/](#integrations-22)** | 22 | Stripe, Firebase, Discord, Slack, Twilio, Shopify |
| 12 | **[marketing/](#marketing-21)** | 21 | SEO, CRO, ads, email, launch strategy, copywriting |
| 13 | **[planning/](#planning-7)** | 7 | Plans, brainstorming, workflows, Kaizen |
| 14 | **[security/](#security-5)** | 5 | Pentest, red team, OWASP, web app security |
| 15 | **[system/](#system-5)** | 5 | Shell scripting, browser automation, PowerShell |

> See **[SKILLS-MAP.md](skills/SKILLS-MAP.md)** for a complete quick-lookup reference with "I need to..." table.

---

## Category Details

### AI Agents (20)

Build, orchestrate, and evaluate AI agents and LLM applications.

| Skill | Description |
|-------|-------------|
| `@ai-agents-architect` | Design autonomous agents: tool use, memory, planning, multi-agent |
| `@rag-engineer` | Embeddings, vector DB, retrieval strategies |
| `@langgraph` | Stateful multi-actor AI applications |
| `@mcp-builder` | Build MCP (Model Context Protocol) servers |
| `@prompt-engineering` | Prompt optimization patterns & best practices |
| `@subagent-driven-development` | Execute plans via fresh subagents + 2-stage review |
| `@crewai` | Multi-agent framework (role-based) |
| `@parallel-agents` | Multi-agent orchestration patterns |
| `@voice-ai-development` | Real-time voice agents and voice-enabled apps |
| ... and 11 more | Agent evaluation, memory, caching, research, etc. |

### Backend (24)

APIs, databases, server infrastructure, and cloud services.

| Skill | Description |
|-------|-------------|
| `@rust-systems-engineering` | Production Rust: async/tokio, concurrency, SQLite, AES-256-GCM |
| `@go-backend-patterns` | Go services: gRPC, worker pools, pgx, OpenTelemetry |
| `@tauri-development` | Tauri v2: commands, state, events, plugins, builds |
| `@api-patterns` | REST vs GraphQL vs tRPC, versioning, pagination |
| `@database-design` | Schema design, indexing, ORM, migrations |
| `@docker-expert` | Multi-stage builds, optimization, orchestration |
| `@postgres-best-practices` | 35 rules: indexing, RLS, locking, monitoring |
| `@aws-serverless` | Lambda, API Gateway, DynamoDB, SAM/CDK |
| `@prisma-expert` | Prisma ORM schema, migrations, queries |
| ... and 15 more | NestJS, BullMQ, GraphQL, GCP, Azure, etc. |

### Business (12)

Product strategy and C-Suite agent system for building real products.

| Skill | Description |
|-------|-------------|
| `@c-suite-orchestrator` | Master coordinator: routes CEO/CTO/CFO/CHRO, full product lifecycle |
| `@c-suite-ceo` | Vision, strategy, GTM, MVP scoping, kill/pivot decisions |
| `@c-suite-cto` | Stack selection, architecture, build-vs-buy, tech estimates |
| `@c-suite-cfo` | Unit economics, pricing, budget, runway, ROI |
| `@c-suite-chro` | Team/agent design, hiring, processes, quality gates |
| `@app-builder` | Full-stack app from natural language (14 templates) |
| `@micro-saas-launcher` | Ship micro-SaaS in weeks: validation, MVP, pricing, launch |
| `@pricing-strategy` | Pricing models, packaging, monetization |
| `@product-manager-toolkit` | RICE prioritization, customer interviews, PRDs |
| ... and 3 more | AI product patterns, competitor analysis, app builder |

### Core (13)

Agent configuration and meta-skills that control how the AI operates.

| Skill | Description |
|-------|-------------|
| `@loki-mode` | Multi-agent autonomous startup system (100+ skills) |
| `@behavioral-modes` | Switch modes: brainstorm, implement, debug, review, teach, ship |
| `@skill-creator` | Create new skills |
| `@context-window-management` | Manage LLM context: summarization, trimming, routing |
| `@verification-before-completion` | Verify work before claiming it's done |
| ... and 8 more | Claude Code guide, environment setup, superpowers, etc. |

### Creative (21)

Design, art, games, and visual experiences.

| Skill | Description |
|-------|-------------|
| `@ui-ux-pro-max` | 50 styles, 21 palettes, 50 font pairings, 20 charts, 9 stacks |
| `@game-development` | 9 sub-skills: 2D, 3D, mobile, PC, web, VR/AR, multiplayer, art, audio |
| `@claude-d3js-skill` | Interactive data visualizations with D3.js |
| `@algorithmic-art` | Generative art with p5.js |
| `@canvas-design` | Visual art in PNG/PDF |
| ... and 6 more | Mobile design, themes, brand guidelines, 3D web, etc. |

### Dev Practices (26)

Code quality, testing, debugging, and engineering best practices.

| Skill | Description |
|-------|-------------|
| `@test-driven-development` | TDD: write tests before implementation |
| `@systematic-debugging` | Root-cause debugging methodology |
| `@typescript-expert` | TypeScript patterns, tsconfig, utility types |
| `@code-review-checklist` | Thorough code review checklist |
| `@clean-code` | Pragmatic coding standards |
| `@playwright-skill` | Browser automation with Playwright |
| `@production-code-audit` | Deep-scan entire codebase for issues |
| `@github-workflow-automation` | PR reviews, issue triage, CI/CD |
| ... and 18 more | Git, deployment, Python, JavaScript, performance, etc. |

### Documents (10)

Office document creation and template management.

| Skill | Description |
|-------|-------------|
| `@docx-official` | Create/edit Word documents with full OOXML support |
| `@xlsx-official` | Create/edit Excel spreadsheets with formulas |
| `@pdf-official` | Create/edit/merge PDFs |
| `@pptx-official` | Create/edit PowerPoint presentations |
| ... and 6 more | Copy editing, documentation templates, NotebookLM, etc. |

### Dotnet (3)

.NET / Avalonia / Zafiro desktop application patterns.

| Skill | Description |
|-------|-------------|
| `@avalonia-zafiro-development` | Avalonia UI conventions with Zafiro toolkit |
| `@avalonia-layout-zafiro` | Layout patterns with shared styles |
| `@avalonia-viewmodels-zafiro` | ViewModel & Wizard patterns (ReactiveUI) |

### Fincept (12)

Financial technology domain agents: trading systems, quantitative engineering, and fintech expertise.

| Skill | Description |
|-------|-------------|
| `@fincept-orchestrator` | Fintech project coordinator |
| `@fincept-ceo` | Fintech product strategy |
| `@fincept-cto` | Fintech technical architecture (Rust/Go/Python/TS) |
| `@fincept-cfo` | Fintech financial modeling |
| `@trading-systems` | Order books, matching engines, market data |
| `@ai-quant-engineering` | Qlib, RL trading, factor mining |
| `@fintech-domain` | Asset classes, regulations, calculations |
| `@dsl-engineering` | FinScript DSL design (lexer, parser, interpreter) |
| ... and 4 more | QA, debugging, recon, execution agents |

### Frontend (16)

React, Next.js, web UI, and browser-side development.

| Skill | Description |
|-------|-------------|
| `@react-mastery` | Complete React: hooks, state, performance, patterns |
| `@nextjs-best-practices` | Next.js App Router, Server Components |
| `@tailwind-patterns` | Tailwind CSS v4, container queries, design tokens |
| `@web-performance-optimization` | Core Web Vitals, bundle optimization |
| `@3d-web-experience` | Three.js, React Three Fiber, WebGL |
| ... and 11 more | Remotion, scroll, i18n, Supabase auth, portfolios, etc. |

### Integrations (22)

Third-party service integrations and API connectors.

| Skill | Description |
|-------|-------------|
| `@stripe-integration` | Payments, subscriptions, webhooks, Checkout |
| `@firebase` | Auth, Firestore, Storage, Functions, Hosting |
| `@discord-bot-architect` | Production Discord bots |
| `@slack-bot-builder` | Slack Bolt apps (Python, JS, Java) |
| `@telegram-bot-builder` | Telegram bots for automation & AI |
| `@clerk-auth` | Clerk auth, middleware, organizations |
| ... and 16 more | Twilio, Shopify, Algolia, HubSpot, Plaid, etc. |

### Marketing (21)

SEO, conversion optimization, growth, and launch strategies.

| Skill | Description |
|-------|-------------|
| `@launch-strategy` | Product launch: ORB framework, 5-phase approach |
| `@conversion-optimization` | CRO for pages, forms, popups, onboarding, paywalls |
| `@seo-audit` | Diagnose & fix SEO issues |
| `@copywriting` | Marketing copywriting |
| `@email-sequence` | Drip campaigns, automated email flows |
| `@paid-ads` | Google Ads, Meta, LinkedIn campaigns |
| ... and 15 more | Content, social, referrals, analytics, ASO, etc. |

### Planning (7)

Strategic planning, brainstorming, and workflow management.

| Skill | Description |
|-------|-------------|
| `@brainstorming` | Turn ideas into designs before coding |
| `@writing-plans` | Write implementation plans before touching code |
| `@executing-plans` | Execute plans with review checkpoints |
| `@workflow-automation` | Durable execution for reliable agents |
| `@kaizen` | Continuous improvement & error proofing |
| `@planning-with-files` | File-based planning (task_plan.md, findings.md) |
| `@file-organizer` | Organize files by context, find duplicates |

### Security (5)

Penetration testing and security assessment (consolidated with reference docs).

| Skill | Description |
|-------|-------------|
| `@web-app-security` | OWASP Top 10, SQLi, XSS, auth bypass, Burp Suite |
| `@pentest-methodology` | Ethical hacking methodology, checklists, commands |
| `@privilege-escalation` | Linux, Windows, AD, cloud privilege escalation |
| `@red-team-ops` | Red team tactics, Metasploit, scanning tools |
| `@network-security` | Network scanning, Wireshark, SMTP, SSH, Shodan |

### System (5)

Operating system tools, shell scripting, and browser automation.

| Skill | Description |
|-------|-------------|
| `@browser-automation` | Playwright/Puppeteer for testing & scraping |
| `@browser-extension-builder` | Chrome/Firefox extensions (Manifest V3) |
| `@linux-shell-scripting` | Bash scripts, Linux automation |
| `@powershell-windows` | PowerShell patterns, operators, error handling |
| `@busybox-on-windows` | Unix commands on Windows via BusyBox |

---

## Common Workflows

### Build a Product (Idea to Launch)

```
@c-suite-orchestrator  → Full C-Suite activation
  ├→ @c-suite-ceo      → Vision, MVP scope
  ├→ @c-suite-cto      → Stack, architecture
  ├→ @c-suite-cfo      → Pricing, budget
  ├→ @writing-plans     → Implementation plan
  ├→ @subagent-driven-development → Agent execution
  └→ @launch-strategy   → Ship it
```

### Build a Feature

```
@brainstorming → @writing-plans → @test-driven-development → @code-review-checklist → @git-pushing
```

### Debug & Fix

```
@systematic-debugging → @test-fixing → @test-driven-development
```

### Launch Marketing

```
@launch-strategy → @copywriting → @seo-fundamentals → @email-sequence → @conversion-optimization
```

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

## Repository Structure

```
.agents/
├── README.md                This file
├── GETTING_STARTED.md       5-minute beginner guide
├── CONTRIBUTING.md          How to add skills
├── FAQ.md                   Common questions
├── CHANGELOG.md             Version history
├── LICENSE                  MIT License
├── docs/                    Skill anatomy, visual guide, examples
├── scripts/                 Validation, index generation
└── skills/
    ├── SKILLS-MAP.md        Quick-lookup reference for all 217 skills
    ├── ai-agents/      (20)
    ├── backend/         (24)
    ├── business/        (12)
    ├── core/            (13)
    ├── creative/        (21)
    ├── dev-practices/   (26)
    ├── documents/       (10)
    ├── dotnet/           (3)
    ├── fincept/         (12)
    ├── frontend/        (16)
    ├── integrations/    (22)
    ├── marketing/       (21)
    ├── planning/         (7)
    ├── security/         (5)
    └── system/           (5)
```

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

Invoke with `@skill-name` in any compatible AI assistant.

---

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick version:

1. Create `skills/<category>/<your-skill>/SKILL.md` with YAML frontmatter
2. Run `python scripts/validate_skills.py` to verify
3. Submit a PR

---

## Credits & Sources

### Foundation
- **[Antigravity Awesome Skills](https://github.com/sickn33/antigravity-awesome-skills)** — Original 253+ skill collection

### Official Sources
- **Anthropic** (Claude Code team): Document processing skills, brand guidelines
- **Supabase**: PostgreSQL best practices
- **Vercel Labs**: Remotion best practices
- **DatAI Studio**: Avalonia/Zafiro patterns

### Contributors
- [sickn33](https://github.com/sickn33) — Original repository creator
- [AndrewHaward2310](https://github.com/AndrewHaward2310) — Category reorganization, C-Suite agents, domain extensions
- All [original contributors](https://github.com/sickn33/antigravity-awesome-skills/graphs/contributors)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

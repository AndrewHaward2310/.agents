# SKILLS MAP - Quick Reference

> **203 skills / 14 categories** | Last updated: 2026-02-10
>
> Use: `@skill-name` to activate any skill. Skills load from `skills/<category>/<skill-name>/SKILL.md`

---

## Directory Structure

```
skills/
├── core/          (13)  Agent config, modes, meta-skills
├── ai-agents/     (20)  LLM agents, RAG, prompt engineering
├── backend/       (21)  APIs, databases, server, cloud
├── business/      (12)  C-Suite agents, product strategy, pricing
├── creative/      (11)  Design, art, games, UI/UX
├── dev-practices/ (26)  Code quality, testing, debugging, git
├── documents/     (10)  Office docs, templates, editing
├── dotnet/         (3)  Avalonia / Zafiro / .NET
├── frontend/      (16)  React, Next.js, Tailwind, web
├── integrations/  (22)  Stripe, Firebase, bots, APIs
├── marketing/     (21)  SEO, CRO, ads, email, launch
├── planning/       (7)  Plans, brainstorm, workflows
├── security/       (5)  Pentest, red team, vulnerabilities
└── system/         (5)  Shell, browser, OS tools
```

---

## QUICK LOOKUP - "I need to..."

| I need to... | Use this skill | Category |
|---|---|---|
| Build a product from idea to launch | `@c-suite-orchestrator` | business |
| Make product/business decisions | `@c-suite-ceo` | business |
| Choose tech stack / architecture | `@c-suite-cto` | business |
| Model pricing / finances | `@c-suite-cfo` | business |
| Design team / processes | `@c-suite-chro` | business |
| Launch a micro-SaaS | `@micro-saas-launcher` | business |
| Brainstorm before building | `@brainstorming` | planning |
| Write an implementation plan | `@writing-plans` | planning |
| Execute a plan with agents | `@subagent-driven-development` | ai-agents |
| Debug something broken | `@systematic-debugging` | dev-practices |
| Write tests first (TDD) | `@test-driven-development` | dev-practices |
| Review code quality | `@code-review-checklist` | dev-practices |
| Build a React app | `@react-mastery` | frontend |
| Build a Next.js app | `@nextjs-best-practices` | frontend |
| Set up Stripe payments | `@stripe-integration` | integrations |
| Set up auth | `@clerk-auth` or `@nextjs-supabase-auth` | integrations/frontend |
| Write marketing copy | `@copywriting` | marketing |
| Optimize conversions | `@conversion-optimization` | marketing |
| Plan a launch | `@launch-strategy` | marketing |
| SEO audit | `@seo-audit` | marketing |
| Build a Discord/Slack bot | `@discord-bot-architect` / `@slack-bot-builder` | integrations |
| Build an AI agent | `@ai-agents-architect` | ai-agents |
| Build a RAG system | `@rag-engineer` | ai-agents |
| Create Word/Excel/PDF/PPT | `@docx-official` / `@xlsx-official` / etc | documents |
| Pentest a web app | `@web-app-security` | security |
| Automate workflows | `@workflow-automation` | planning |

---

## 1. CORE (13) - Agent Configuration & Meta-Skills

Skills that configure how the AI agent itself operates.

| Skill | What it does |
|---|---|
| `agent-manager-skill` | Manage multiple CLI agents via tmux (start/stop/monitor) |
| `behavioral-modes` | Switch AI modes: brainstorm, implement, debug, review, teach, ship |
| `cc-skill-continuous-learning` | Continuous learning patterns |
| `cc-skill-project-guidelines-example` | Example project guidelines template |
| `cc-skill-strategic-compact` | Strategic compact development patterns |
| `claude-code-guide` | Master guide for using Claude Code effectively |
| `context-window-management` | Manage LLM context: summarization, trimming, routing |
| `environment-setup-guide` | Set up dev environments with proper tools |
| `loki-mode` | Multi-agent autonomous startup system (100+ skills orchestration) |
| `skill-creator` | Create new skills |
| `using-superpowers` | How to find and use skills effectively |
| `verification-before-completion` | Verify work before claiming it's done |
| `writing-skills` | Create, edit, verify skills before deployment |

---

## 2. AI-AGENTS (20) - LLM Agents & AI Engineering

Build, orchestrate, and evaluate AI agents and LLM applications.

| Skill | What it does |
|---|---|
| `agent-evaluation` | Benchmark and test LLM agents |
| `agent-memory-mcp` | Persistent memory system for AI agents |
| `ai-agents-architect` | Design autonomous AI agents (tool use, memory, planning) |
| `autonomous-agent-patterns` | Patterns for autonomous coding agents |
| `computer-use-agents` | Agents that interact with screens like humans |
| `context7-auto-research` | Auto-fetch latest docs via Context7 API |
| `crewai` | CrewAI multi-agent framework |
| `langfuse` | LLM observability (tracing, prompt management) |
| `langgraph` | LangGraph stateful multi-actor AI apps |
| `llm-app-patterns` | Production LLM patterns: RAG, agents, evals |
| `mcp-builder` | Build MCP (Model Context Protocol) servers |
| `parallel-agents` | Multi-agent orchestration patterns |
| `personal-tool-builder` | Build custom tools from your own problems |
| `prompt-caching` | Cache strategies for LLM prompts |
| `prompt-engineering` | Prompt engineering patterns & optimization |
| `prompt-library` | Curated prompt collection for various tasks |
| `rag-engineer` | Build RAG systems (embeddings, vector DB, retrieval) |
| `research-engineer` | Academic research with scientific rigor |
| `subagent-driven-development` | Execute plans via fresh subagent per task + 2-stage review |
| `voice-ai-development` | Build voice AI apps (real-time voice agents) |

---

## 3. BACKEND (21) - Server, APIs, Databases, Cloud

| Skill | What it does |
|---|---|
| `api-documentation-generator` | Generate API docs from code |
| `api-patterns` | REST vs GraphQL vs tRPC, pagination, versioning |
| `aws-serverless` | Lambda, API Gateway, DynamoDB, SAM/CDK |
| `azure-functions` | Azure Functions, Durable Functions |
| `backend-dev-guidelines` | Node.js/Express/TypeScript microservice patterns |
| `bullmq-specialist` | Redis-backed job queues (BullMQ) |
| `bun-development` | Bun runtime development |
| `cc-skill-backend-patterns` | Backend architecture patterns for Node.js |
| `cc-skill-clickhouse-io` | ClickHouse analytics & data engineering |
| `database-design` | Schema design, indexing, ORM selection |
| `docker-expert` | Multi-stage builds, optimization, orchestration |
| `email-systems` | Transactional email, deliverability, ESP patterns |
| `gcp-cloud-run` | GCP Cloud Run serverless |
| `graphql` | GraphQL schema, resolvers, subscriptions |
| `neon-postgres` | Neon serverless Postgres, branching |
| `nestjs-expert` | NestJS modules, DI, middleware, guards |
| `nodejs-best-practices` | Node.js framework selection, async, security |
| `nosql-expert` | Cassandra, DynamoDB patterns |
| `postgres-best-practices` | Postgres performance optimization (Supabase) |
| `prisma-expert` | Prisma ORM schema, migrations, queries |
| `server-management` | Process management, monitoring, scaling |

---

## 4. BUSINESS (12) - Product Strategy & C-Suite Agents

Build real products from idea to launch with agent-powered C-Suite.

| Skill | What it does |
|---|---|
| **`c-suite-orchestrator`** | **Master coordinator: routes CEO/CTO/CFO/CHRO for full product lifecycle** |
| `c-suite-ceo` | Vision, strategy, GTM, MVP scoping, kill/pivot decisions |
| `c-suite-cto` | Stack selection, architecture, build-vs-buy, tech estimates |
| `c-suite-cfo` | Unit economics, pricing, budget, runway, ROI |
| `c-suite-chro` | Team/agent design, hiring, processes, quality gates |
| `ai-product` | LLM integration patterns, RAG, AI UX, cost optimization |
| `ai-wrapper-product` | Build products wrapping AI APIs |
| `app-builder` | Full-stack app orchestrator from natural language |
| `competitor-alternatives` | Create competitor comparison pages |
| `micro-saas-launcher` | Ship micro-SaaS in weeks (validation, MVP, pricing, launch) |
| `pricing-strategy` | Pricing models, packaging, monetization |
| `product-manager-toolkit` | RICE prioritization, interviews, PRDs, discovery |

---

## 5. CREATIVE (11 + 9 game sub-skills) - Design, Art, Games

| Skill | What it does |
|---|---|
| `algorithmic-art` | Generative art with p5.js |
| `blockrun` | Access external AI models (DALL-E, Grok, GPT) |
| `brand-guidelines-anthropic` | Anthropic brand colors & typography |
| `canvas-design` | Visual art in PNG/PDF with design philosophy |
| `claude-d3js-skill` | Interactive data visualizations with D3.js |
| `design-orchestration` | Design workflow coordination |
| `game-development/` | **9 sub-skills**: 2D, 3D, mobile, PC, web, VR/AR, multiplayer, art, audio, design |
| `mobile-design` | Mobile-first iOS/Android design patterns |
| `slack-gif-creator` | Animated GIFs optimized for Slack |
| `theme-factory` | Style artifacts with themes (slides, docs, HTML) |
| `ui-ux-pro-max` | 50 styles, 21 palettes, 50 fonts, 20 charts, 9 stacks |

---

## 6. DEV-PRACTICES (26) - Code Quality, Testing, Git

| Skill | What it does |
|---|---|
| `address-github-comments` | Respond to PR review comments via gh CLI |
| `cc-skill-coding-standards` | Universal coding standards (TS, JS, React, Node) |
| `clean-code` | Pragmatic coding standards, no over-engineering |
| `code-review-checklist` | Thorough code review checklist |
| `deployment-procedures` | Safe deployment, rollback strategies |
| `finishing-a-development-branch` | Integrate work when implementation is complete |
| `git-pushing` | Stage, commit, push with conventional commits |
| `github-workflow-automation` | PR reviews, issue triage, CI/CD with AI |
| `javascript-mastery` | 33+ essential JS concepts reference |
| `lint-and-validate` | Auto quality control after code changes |
| `performance-profiling` | Measure, analyze, optimize performance |
| `playwright-skill` | Browser automation with Playwright |
| `production-code-audit` | Deep-scan entire codebase for issues |
| `python-patterns` | Python frameworks, async, type hints |
| `receiving-code-review` | Handle code review feedback |
| `requesting-code-review` | Request code review before merging |
| `senior-architect` | System design with ReactJS, Node.js, AWS |
| `senior-fullstack` | Full-stack React/Next.js/Supabase/TypeScript |
| `systematic-debugging` | Root-cause debugging methodology |
| `test-driven-development` | TDD: write tests before implementation |
| `test-fixing` | Fix all failing tests with smart error grouping |
| `testing-patterns` | Jest patterns, mocking, factories |
| `typescript-expert` | TypeScript patterns and best practices |
| `using-git-worktrees` | Git worktrees for isolated feature work |
| `vercel-deployment` | Deploy to Vercel with Next.js |
| `webapp-testing` | Test local web apps with Playwright |

---

## 7. DOCUMENTS (10) - Office Documents & Templates

| Skill | What it does |
|---|---|
| `copy-editing` | Edit & improve marketing copy |
| `doc-coauthoring` | Structured doc co-authoring workflow |
| `documentation-templates` | README, API docs, code comments templates |
| `docx-official` | Create/edit Word documents (.docx) |
| `internal-comms-anthropic` | Internal communications templates |
| `notebooklm` | Query Google NotebookLM from Claude Code |
| `obsidian-clipper-template-creator` | Obsidian Web Clipper templates |
| `pdf-official` | Create/edit/merge PDFs |
| `pptx-official` | Create/edit PowerPoint presentations |
| `xlsx-official` | Create/edit Excel spreadsheets with formulas |

---

## 8. DOTNET (3) - .NET / Avalonia / Zafiro

| Skill | What it does |
|---|---|
| `avalonia-layout-zafiro` | Avalonia UI layout with Zafiro shared styles |
| `avalonia-viewmodels-zafiro` | ViewModel & Wizard patterns (Zafiro + ReactiveUI) |
| `avalonia-zafiro-development` | Avalonia development conventions with Zafiro toolkit |

---

## 9. FRONTEND (16) - React, Next.js, Web, UI

| Skill | What it does |
|---|---|
| `3d-web-experience` | Three.js, React Three Fiber, WebGL |
| `cc-skill-frontend-patterns` | React/Next.js patterns, state, performance |
| `core-components` | Component library & design system patterns |
| `frontend-design` | Production-grade frontend interfaces |
| `frontend-dev-guidelines` | React/TypeScript guidelines (Suspense, RSC) |
| `i18n-localization` | Internationalization & localization |
| `interactive-portfolio` | Portfolios that land jobs & clients |
| `nextjs-best-practices` | Next.js App Router, Server Components |
| `nextjs-supabase-auth` | Supabase Auth + Next.js App Router |
| `react-mastery` | Complete React: hooks, state, performance, patterns |
| `remotion-best-practices` | Video creation in React with Remotion |
| `scroll-experience` | Scroll-driven parallax & animations |
| `tailwind-patterns` | Tailwind CSS v4, container queries, tokens |
| `web-artifacts-builder` | Multi-component HTML artifacts |
| `web-design-guidelines` | UI review for Web Interface Guidelines |
| `web-performance-optimization` | Core Web Vitals, bundle optimization |

---

## 10. INTEGRATIONS (22) - Third-Party Services & APIs

| Skill | What it does |
|---|---|
| `algolia-search` | Algolia search, indexing, InstantSearch |
| `clerk-auth` | Clerk auth, middleware, organizations |
| `discord-bot-architect` | Production Discord bots (Discord.js / Pycord) |
| `exa-search` | Semantic search via Exa API |
| `firebase` | Auth, Firestore, Storage, Functions, Hosting |
| `firecrawl-scraper` | Web scraping, screenshots, PDF parsing |
| `hubspot-integration` | HubSpot CRM, OAuth, associations |
| `inngest` | Serverless background jobs, event-driven workflows |
| `moodle-external-api-development` | Moodle LMS web service APIs |
| `notion-template-business` | Build & sell Notion templates |
| `plaid-fintech` | Plaid API for fintech (Link, transactions, identity) |
| `salesforce-development` | LWC, Apex, triggers, SOQL |
| `shopify-development` | Shopify apps & themes |
| `slack-bot-builder` | Slack Bolt apps (Python, JS, Java) |
| `stripe-integration` | Payments, subscriptions, webhooks, Checkout |
| `tavily-web` | Web search & extraction via Tavily |
| `telegram-bot-builder` | Telegram bots for automation & AI |
| `telegram-mini-app` | Telegram Mini Apps (TWA) |
| `trigger-dev` | Background jobs & AI workflows |
| `twilio-communications` | SMS, voice, WhatsApp via Twilio |
| `upstash-qstash` | Serverless message queues & scheduled jobs |
| `zapier-make-patterns` | No-code automation (Zapier, Make) |

---

## 11. MARKETING (21) - SEO, CRO, Ads, Growth

| Skill | What it does |
|---|---|
| `ab-test-setup` | A/B test setup with hypothesis & metrics gates |
| `analytics-tracking` | GA4, GTM, conversion tracking, UTM |
| `app-store-optimization` | ASO for App Store & Google Play |
| `content-creator` | SEO-optimized content with brand voice |
| `conversion-optimization` | CRO for pages, forms, popups, onboarding, paywalls |
| `copywriting` | Marketing copywriting |
| `email-sequence` | Drip campaigns, automated email flows |
| `free-tool-strategy` | Free tools for lead generation |
| `geo-fundamentals` | Generative Engine Optimization (AI search) |
| `launch-strategy` | Product launch with ORB framework, 5-phase approach |
| `marketing-ideas` | Marketing ideas & strategies for SaaS |
| `marketing-psychology` | Behavioral science in marketing |
| `paid-ads` | Google Ads, Meta, LinkedIn ad campaigns |
| `programmatic-seo` | SEO pages at scale with templates & data |
| `referral-program` | Referral & affiliate programs |
| `schema-markup` | Structured data & schema.org markup |
| `segment-cdp` | Segment CDP, Analytics.js, tracking plans |
| `seo-audit` | Diagnose & fix SEO issues |
| `seo-fundamentals` | E-E-A-T, Core Web Vitals, algorithms |
| `social-content` | Social media content (LinkedIn, Twitter, etc.) |
| `viral-generator-builder` | Build viral generator tools (quizzes, avatars) |

---

## 12. PLANNING (7) - Strategy, Plans, Workflows

| Skill | What it does |
|---|---|
| `brainstorming` | Turn ideas into designs before coding |
| `executing-plans` | Execute plans in separate session with checkpoints |
| `file-organizer` | Organize files by context, find duplicates |
| `kaizen` | Continuous improvement & error proofing |
| `planning-with-files` | File-based planning (task_plan.md, findings.md) |
| `workflow-automation` | Durable execution for reliable AI agents |
| `writing-plans` | Write implementation plans before touching code |

---

## 13. SECURITY (5 consolidated) - Penetration Testing & Red Team

Each skill is a consolidated reference with sub-topics in `references/`.

| Skill | What it covers |
|---|---|
| `network-security` | Network scanning, Wireshark, SMTP, SSH, Shodan |
| `pentest-methodology` | Ethical hacking methodology, checklists, commands |
| `privilege-escalation` | Linux, Windows, AD, cloud privilege escalation |
| `red-team-ops` | Red team tactics, Metasploit, tools, scanning |
| `web-app-security` | OWASP Top 10, SQLi, XSS, auth bypass, API fuzzing, Burp Suite |

---

## 14. SYSTEM (5) - OS, Shell, Browser Tools

| Skill | What it does |
|---|---|
| `browser-automation` | Playwright/Puppeteer for testing & scraping |
| `browser-extension-builder` | Chrome/Firefox extensions (Manifest V3) |
| `busybox-on-windows` | Unix commands on Windows via BusyBox |
| `linux-shell-scripting` | Bash scripts, Linux automation |
| `powershell-windows` | PowerShell patterns, operators, error handling |

---

## Common Workflows

### Build a Product (Full Lifecycle)
```
@c-suite-orchestrator  → Activates full C-Suite
  ├→ @c-suite-ceo      → Vision, MVP scope, GTM
  ├→ @c-suite-cto      → Stack, architecture
  ├→ @c-suite-cfo      → Pricing, budget, runway
  ├→ @c-suite-chro     → Team, processes
  ├→ @writing-plans    → Implementation plan
  ├→ @subagent-driven-development → Execute with agents
  └→ @launch-strategy  → Ship it
```

### Fix Bugs
```
@systematic-debugging  → Find root cause
@test-fixing          → Fix all failing tests
@test-driven-development → Write regression test
```

### Build a Feature
```
@brainstorming         → Design the feature
@writing-plans         → Plan implementation
@test-driven-development → Build with TDD
@code-review-checklist → Review before merge
@git-pushing           → Commit & push
```

### Launch Marketing
```
@launch-strategy       → Plan the launch
@copywriting           → Write copy
@seo-fundamentals      → SEO setup
@email-sequence        → Drip campaign
@conversion-optimization → Optimize funnel
```

### Research & Evaluate
```
@research-engineer     → Academic-grade research
@competitor-alternatives → Competitor analysis
@product-manager-toolkit → RICE, interviews, PRDs
```

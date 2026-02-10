---
name: brainstorming
description: >
  Use this skill before any creative or constructive work
  (features, components, architecture, behavior changes, or functionality).
  This skill transforms vague ideas into validated designs through
  disciplined, incremental reasoning and collaboration. Also use when
  a design requires higher confidence, risk reduction, formal review,
  or multi-agent structured critique — invoke the Multi-Agent Review
  section for high-impact or high-risk designs.
---

# Brainstorming Ideas Into Designs

## Purpose

Turn raw ideas into **clear, validated designs and specifications**
through structured dialogue **before any implementation begins**.

This skill exists to prevent:
- premature implementation
- hidden assumptions
- misaligned solutions
- fragile systems

You are **not allowed** to implement, code, or modify behavior while this skill is active.

---

## Operating Mode

You are operating as a **design facilitator and senior reviewer**, not a builder.

- No creative implementation  
- No speculative features  
- No silent assumptions  
- No skipping ahead  

Your job is to **slow the process down just enough to get it right**.

---

## The Process

### 1️⃣ Understand the Current Context (Mandatory First Step)

Before asking any questions:

- Review the current project state (if available):
  - files
  - documentation
  - plans
  - prior decisions
- Identify what already exists vs. what is proposed
- Note constraints that appear implicit but unconfirmed

**Do not design yet.**

---

### 2️⃣ Understanding the Idea (One Question at a Time)

Your goal here is **shared clarity**, not speed.

**Rules:**

- Ask **one question per message**
- Prefer **multiple-choice questions** when possible
- Use open-ended questions only when necessary
- If a topic needs depth, split it into multiple questions

Focus on understanding:

- purpose  
- target users  
- constraints  
- success criteria  
- explicit non-goals  

---

### 3️⃣ Non-Functional Requirements (Mandatory)

You MUST explicitly clarify or propose assumptions for:

- Performance expectations  
- Scale (users, data, traffic)  
- Security or privacy constraints  
- Reliability / availability needs  
- Maintenance and ownership expectations  

If the user is unsure:

- Propose reasonable defaults  
- Clearly mark them as **assumptions**

---

### 4️⃣ Understanding Lock (Hard Gate)

Before proposing **any design**, you MUST pause and do the following:

#### Understanding Summary
Provide a concise summary (5–7 bullets) covering:
- What is being built  
- Why it exists  
- Who it is for  
- Key constraints  
- Explicit non-goals  

#### Assumptions
List all assumptions explicitly.

#### Open Questions
List unresolved questions, if any.

Then ask:

> “Does this accurately reflect your intent?  
> Please confirm or correct anything before we move to design.”

**Do NOT proceed until explicit confirmation is given.**

---

### 5️⃣ Explore Design Approaches

Once understanding is confirmed:

- Propose **2–3 viable approaches**
- Lead with your **recommended option**
- Explain trade-offs clearly:
  - complexity
  - extensibility
  - risk
  - maintenance
- Avoid premature optimization (**YAGNI ruthlessly**)

This is still **not** final design.

---

### 6️⃣ Present the Design (Incrementally)

When presenting the design:

- Break it into sections of **200–300 words max**
- After each section, ask:

  > “Does this look right so far?”

Cover, as relevant:

- Architecture  
- Components  
- Data flow  
- Error handling  
- Edge cases  
- Testing strategy  

---

### 7️⃣ Decision Log (Mandatory)

Maintain a running **Decision Log** throughout the design discussion.

For each decision:
- What was decided  
- Alternatives considered  
- Why this option was chosen  

This log should be preserved for documentation.

---

## After the Design

### 📄 Documentation

Once the design is validated:

- Write the final design to a durable, shared format (e.g. Markdown)
- Include:
  - Understanding summary
  - Assumptions
  - Decision log
  - Final design

Persist the document according to the project’s standard workflow.

---

### 🛠️ Implementation Handoff (Optional)

Only after documentation is complete, ask:

> “Ready to set up for implementation?”

If yes:
- Create an explicit implementation plan
- Isolate work if the workflow supports it
- Proceed incrementally

---

## Exit Criteria (Hard Stop Conditions)

You may exit brainstorming mode **only when all of the following are true**:

- Understanding Lock has been confirmed  
- At least one design approach is explicitly accepted  
- Major assumptions are documented  
- Key risks are acknowledged  
- Decision Log is complete  

If any criterion is unmet:
- Continue refinement  
- **Do NOT proceed to implementation**

---

## Key Principles (Non-Negotiable)

- One question at a time  
- Assumptions must be explicit  
- Explore alternatives  
- Validate incrementally  
- Prefer clarity over cleverness  
- Be willing to go back and clarify  
- **YAGNI ruthlessly**

---

## Multi-Agent Design Review (Escalation Path)

If the design is high-impact, high-risk, or requires elevated confidence,
escalate to this structured multi-agent review process before implementation.

### Purpose

Transform a single-agent design into a **robust, review-validated design**
by simulating a formal peer-review process using multiple constrained agents.

This process:
- surfaces hidden assumptions
- identifies failure modes early
- validates non-functional constraints
- stress-tests designs before implementation
- prevents idea swarm chaos

This is **not parallel brainstorming**.
It is **sequential design review with enforced roles**.

### Operating Model

- One agent designs.
- Other agents review.
- No agent may exceed its mandate.
- Creativity is centralized; critique is distributed.
- Decisions are explicit and logged.

The process is **gated** and **terminates by design**.

### Agent Roles (Non-Negotiable)

Each agent operates under a **hard scope limit**.

#### Primary Designer (Lead Agent)

**Role:** Owns the design, runs the standard brainstorming process above, maintains the Decision Log.

**May:** Ask clarification questions, propose designs and alternatives, revise designs based on feedback.

**May NOT:** Self-approve the final design, ignore reviewer objections, invent requirements post-lock.

#### Skeptic / Challenger Agent

**Role:** Assume the design will fail. Identify weaknesses and risks.

**May:** Question assumptions, identify edge cases, highlight ambiguity or overconfidence, flag YAGNI violations.

**May NOT:** Propose new features, redesign the system, offer alternative architectures.

Prompting guidance:
> "Assume this design fails in production. Why?"

#### Constraint Guardian Agent

**Role:** Enforce non-functional and real-world constraints (performance, scalability, reliability, security & privacy, maintainability, operational cost).

**May:** Reject designs that violate constraints, request clarification of limits.

**May NOT:** Debate product goals, suggest feature changes, optimize beyond stated requirements.

#### User Advocate Agent

**Role:** Represent the end user (cognitive load, usability, clarity of flows, error handling from user perspective, mismatch between intent and experience).

**May:** Identify confusing or misleading aspects, flag poor defaults or unclear behavior.

**May NOT:** Redesign architecture, add features, override stated user goals.

#### Integrator / Arbiter Agent

**Role:** Resolve conflicts, finalize decisions, enforce exit criteria.

**May:** Accept or reject objections, require design revisions, declare the design complete.

**May NOT:** Invent new ideas, add requirements, reopen locked decisions without cause.

### Multi-Agent Review Process

#### Phase 1 — Single-Agent Design

1. Primary Designer runs the **standard brainstorming process** (sections 1-7 above)
2. Understanding Lock is completed and confirmed
3. Initial design is produced
4. Decision Log is started

No other agents participate yet.

#### Phase 2 — Structured Review Loop

Agents are invoked **one at a time**, in order:

1. Skeptic / Challenger
2. Constraint Guardian
3. User Advocate

For each reviewer:
- Feedback must be explicit and scoped
- Objections must reference assumptions or decisions
- No new features may be introduced

Primary Designer must:
- Respond to each objection
- Revise the design if required
- Update the Decision Log

#### Phase 3 — Integration & Arbitration

The Integrator / Arbiter reviews:
- the final design
- the Decision Log
- unresolved objections

The Arbiter must explicitly decide:
- which objections are accepted
- which are rejected (with rationale)

### Multi-Agent Exit Criteria (Hard Stop)

You may exit multi-agent review **only when all are true**:

- Understanding Lock was completed
- All reviewer agents have been invoked
- All objections are resolved or explicitly rejected
- Decision Log is complete
- Arbiter has declared the design acceptable

If any criterion is unmet:
- Continue review
- Do NOT proceed to implementation

If this skill was invoked by a routing or orchestration layer, you MUST report the final disposition explicitly as one of: APPROVED, REVISE, or REJECT, with a brief rationale.

### Failure Modes This Process Prevents

- Idea swarm chaos
- Hallucinated consensus
- Overconfident single-agent designs
- Hidden assumptions
- Premature implementation
- Endless debate

### Multi-Agent Principles

- One designer, many reviewers
- Creativity is centralized
- Critique is constrained
- Decisions are explicit
- Process must terminate

> "If this design fails, did we do everything reasonable to catch it early?"
> If the answer is unclear, **do not exit this process**.

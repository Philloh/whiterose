---
title: "Defense in Depth Against OWASP LLM01 Prompt Injection"
date: 2026-05-17 08:45:00 +0300
categories: [AI]
tags: [owasp, prompt-injection, llm01, defense-in-depth]
pin: false
---

## Summary

**LLM01:2025 Prompt Injection** remains the top entry in the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/). Official text: *"A Prompt Injection Vulnerability occurs when user prompts alter the LLM's behavior or output in unintended ways."* ([LLM01 page](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)). No single filter eliminates the class because models consume **instructions and data in one stream**—a point the UK NCSC reiterated in 2025 guidance. This article summarizes **layered controls** aligned with OWASP cheat sheets and Microsoft/Azure security architecture docs—without claiming perfect prevention.

## Layer 1 — Privilege separation

- Run tools with **least-privilege** service accounts.
- Split **read** agents from **write** agents; require step-up auth for destructive actions.
- Map to OWASP **LLM06 Excessive Agency** mitigations.

## Layer 2 — Input and retrieval hygiene

- Treat all retrieved chunks as **untrusted** (see indirect injection, [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)).
- Sanitize structured fields; avoid concatenating user text into system prompts without delimiters.
- Microsoft recommends **spotlighting / marking** trusted vs untrusted sections in Azure OpenAI grounding docs.

## Layer 3 — Output and tool gates

- Schema-validate JSON tool arguments before execution.
- Block outbound URLs not on allow lists when models fetch web content.
- Human-in-the-loop for financial, medical, or mass-email actions.

## Layer 4 — Monitoring and evals

- Maintain **prompt injection regression suites** (open datasets such as [PromptBench](https://github.com/UCSB-NLP-Chang/PromptBench) and vendor red-team sets).
- Log refusal rates, tool denials, and anomaly spikes.

## Layer 5 — Architectural honesty

OWASP and NCSC both stress: **prompt injection is not SQL injection**—you cannot parameterize away semantics while using natural language interfaces. Document **residual risk** for auditors; combine LLM features with deterministic policy engines where feasible.

## References

- [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [NCSC — Prompt injection guidance](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)
- [Microsoft — Azure OpenAI security baseline](https://learn.microsoft.com/en-us/azure/ai-services/openai/security)

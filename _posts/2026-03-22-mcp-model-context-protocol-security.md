---
title: "Model Context Protocol (MCP) and the Expanding Agent Attack Surface"
date: 2026-03-22 15:30:00 +0300
categories: [AI]
tags: [mcp, ai-agents, tool-security, llm]
pin: false
---

## Summary

Anthropic introduced the **Model Context Protocol (MCP)** in November 2024 as an open standard for connecting LLM applications to **tools, data sources, and workflows** ([Anthropic announcement](https://www.anthropic.com/news/model-context-protocol)). Ecosystem adoption grew through 2025 with IDE integrations (Cursor, Zed), server directories, and enterprise connectors. From a security research perspective, MCP shifts risk from **chat output** to **agentic execution**—the same trajectory OWASP **LLM01** and **LLM06:2025 Excessive Agency** describe ([OWASP LLMRisk](https://genai.owasp.org/llmrisk/)).

## What MCP standardizes

MCP defines JSON-RPC message patterns between:

- **Hosts** — LLM applications (Claude Desktop, IDE agents).
- **Clients** — protocol adapters inside the host.
- **Servers** — expose **resources**, **tools**, and **prompts**.

Spec and SDKs live in the open repository [modelcontextprotocol/modelcontextprotocol](https://github.com/modelcontextprotocol/modelcontextprotocol) (formerly `specification` repos consolidated under the org).

## Security-relevant properties

Documented design goals include structured capability negotiation, but researchers and vendors note emergent risks:

| Risk | Why it matters |
| ---- | -------------- |
| **Tool over-permissioning** | MCP servers may wrap shell, filesystem, or cloud APIs |
| **Confused deputy** | Host acts on model-chosen tool calls with user's OS credentials |
| **Indirect injection → tool call** | Untrusted document content steers agent to invoke exfil tools |
| **Supply chain of MCP servers** | Third-party servers in directories are unaudited by default |

Insect.io and Trail of Bits published 2025 analyses of MCP trust boundaries emphasizing **server authenticity**, **transport security (stdio vs SSE)**, and **user consent UX**—teams should read vendor-specific hardening guides rather than assuming protocol = safe.

## Hardening checklist (operations)

1. **Allow-list** MCP servers; treat new servers like installing browser extensions.
2. Run high-risk tools in **sandboxed** environments with network egress controls.
3. Log **tool invocations** with arguments (redact secrets) for IR.
4. Separate **read** vs **write** tools across different server instances with distinct credentials.
5. Apply **prompt injection defenses** at host level—MCP does not replace LLM01 controls.

## References

- [Anthropic — Introducing MCP](https://www.anthropic.com/news/model-context-protocol)
- [Model Context Protocol — specification repo](https://github.com/modelcontextprotocol/modelcontextprotocol)
- [OWASP LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP LLM Top 10 project](https://genai.owasp.org/)

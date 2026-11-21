---
title: Design
description: How parda is built — the goals, the trade-offs, and why each technique was chosen.
---

# parda — design

*Parda* (पर्दा) is Nepali for curtain. parda is a curtain between your machine and every AI service:
the AI sees stand-ins, you see your real data.

## Why it exists

Coding agents, AI chat tools and our own apps send whatever is in front of them to an AI company:
`.env` files, customer emails, staff names, API keys pasted into a terminal. Companies that need
SOC 2, ISO 27001 or GDPR evidence have no cheap, local way to stop that. The products that exist
(2025–26) are enterprise-priced, block instead of mask, or keep the lookup table of real values on
*their* servers. Nobody covers Nepali names.

parda is free, open source (MIT OR Apache-2.0), with **no paid plan**.

## Goals

- **No settings.** Install once; every supported AI tool is protected. Nothing to choose, nothing to flip.
- **Nothing sensitive leaves the machine.** All detection runs locally with rules — no AI model and no
  outside service is ever asked "is this sensitive?".
- **Agents keep working.** The AI sees consistent stand-ins; real values are put back into the answer
  as it streams in, including into the commands and file edits an agent makes.
- **Fails closed.** If parda isn't running, AI requests fail with a clear error. They never go out unfiltered.
- **Lightweight.** Under 5 MB download, under 15 MB memory idle, no runtime to install, no CPU when idle.
- **Evidence for compliance teams.** A local log of what kinds of data were masked and how often —
  never the values.
- **Fully documented** for users, contributors and compliance reviewers.

## Non-goals (for now)

- Browser chat UIs and web forms (planned: a browser extension sharing the same rules).
- Cursor (it builds prompts on its own servers; a local proxy can't see them) and Copilot inline
  completions (need TLS interception).
- Images, PDFs and audio inside requests: passed through unscanned, documented as a limitation.
- AI-based detection (100 MB–1 GB models break the weight goal).
- A paid tier, accounts, telemetry, or any network call parda makes on its own.

## Anti-goals — failure even if it "works"

- Sending any part of a request anywhere to decide what is sensitive.
- Corrupting a user's files because an agent rewrote them with a mask in place of the real value.
- Breaking prompt caching (stand-ins must be identical from one request to the next).
- Claiming "anonymized": stand-in data is still personal data under GDPR. The claim is
  "your data never leaves your machine".

## Approaches considered

| | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | **One small Rust program**, rules-based, local proxy | Rules miss unusual personal data written as prose | **Picked** — light, one engine for every surface, same stack as nodoka |
| B | Python on Presidio + GLiNER | Better recall day one; ~1 GB memory, hard to package, a second engine for the browser | Rejected — breaks "lightweight" |
| C | TypeScript proxy + extension | One language; weakest local detection, needs Node.js everywhere | Rejected |

## How it works

```
 coding agent ──http──▶ parda (127.0.0.1:7390) ──https──▶ AI provider
   real data            mask ▸ vault ▸ restore             sees stand-ins only
```

1. `parda install` points `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` at parda (shell startup files and
   Claude Code's `settings.json`). Whatever those pointed at before (the provider, or another proxy such
   as a compression proxy) becomes parda's upstream, so existing setups keep working.
2. A request arrives. parda parses the JSON body and walks every string value except structural and
   signed fields (`model`, ids, `signature`, `thinking`, encrypted reasoning, base64 media).
3. Each string is scanned by the rules in one pass per rule. Overlapping finds keep the earliest, longest.
4. Each find becomes a stand-in. The JSON is re-serialized (key order preserved) and sent upstream.
5. The response streams back. parda restores stand-ins inside each event, holding back only the few
   characters that could be the start of a split stand-in, and flushes them before the next unrelated event.

### Techniques — chosen per kind of data, automatically

| Data | Technique | AI sees |
|---|---|---|
| API keys, tokens, private keys, passwords, connection-string secrets | Tokenize, restore locally | `[SECRET_3f9a2c1d]` |
| Names (English and Devanagari), phones, IDs, card/bank numbers, IPs | Pseudonymize (same value → same stand-in), restore locally | `[PERSON_8b01e4aa]` |
| Email addresses | Format-preserving stand-in, restore locally | `email_51c0d9e2@parda.invalid` |

**Why secrets are tokenized, not redacted:** agents edit files by echoing their content back. A
redaction marker (`[REDACTED]`) would be written into the user's `.env` or key file, destroying it.
A token is restored on the user's machine before the edit happens, so the file stays intact while the
AI provider still never sees the secret.

**Why the same value always gets the same stand-in:** the stand-in is a keyed BLAKE3 hash of the value
(key: 32 random bytes in `~/.parda/key`, mode 0600, never leaves the machine). It is stable across
requests and restarts, so prompt caching keeps working and the AI can tell "same person" from "two
people". Without the key, nobody can work backwards from a stand-in. 8 hex characters; on a collision
the stand-in grows to 12.

**The vault** (stand-in → real value) lives only in parda's memory, is never written to disk and is
cleared when parda stops. After a restart, the next request re-masks the conversation history the
client resends, which refills it with the same stand-ins. It is capped (100 000 entries, then cleared)
so memory stays bounded.

**Thinking blocks** (Anthropic) and encrypted reasoning (OpenAI) are left exactly as the provider sent
them, in both directions, because they are signed: changing a character breaks the next request.
They may show stand-ins to the user; they never contain real values from us.

### What it detects (v0.1)

- **Secrets:** provider key formats (Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, Google, npm,
  SendGrid, Twilio…), JWTs, PEM private keys, bearer tokens, passwords in connection strings, and
  values of secret-looking settings (`*_KEY=`, `"password": "…"`, `token: …`).
- **Personal data:** emails; phone numbers (international, Nepal mobile); card numbers (Luhn-checked);
  IBANs (checksum); US SSNs; public IPv4 addresses; labelled ID numbers (PAN, citizenship, passport,
  national ID, in English or Nepali).
- **Names:** two or more capitalised words where the first is a known given name or the last a
  distinctive surname; Devanagari names by the same idea with given, middle and surname lists.
  Single-word names are not masked (too many false finds in code).

**When unsure, mask.** A false find costs the AI a little context (and is restored for you anyway);
a miss is a leak.

### Fail closed

- parda down → connection refused → the AI tool shows an error. Nothing is sent.
- Request body that isn't JSON, or is compressed → refused with a clear error (it can't be scanned).
- WebSocket upgrade → refused.
- Upstream unreachable → `502` with a parda error message.

### The log

`~/.parda/log.jsonl`, one line per request: time, API, path, counts per kind masked, count restored.
Never values. Rotated at 10 MB (one old file kept). `parda status` summarises it.

## Commands

| Command | What it does |
|---|---|
| `parda install` | Copies itself to `~/.parda/bin`, starts at login (launchd / systemd user), routes AI tools through it |
| `parda uninstall` | Puts every file it touched back exactly |
| `parda status` | Running? Where each route goes, what was masked today |
| `parda mask` | Masks stdin to stdout — try it, or use it before pasting into a web chat |
| `parda run` | Runs the proxy in the foreground (what the background service runs) |

## Supported tools (v0.1)

Works through a base URL: Claude Code (CLI and IDE extensions), Codex CLI (API-key sign-in), Aider,
anything using the Anthropic or OpenAI SDKs that honours `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`.
Not covered: Cursor, Copilot inline completions, Gemini CLI with Google sign-in, desktop chat apps.

## Weight budget (checked in CI)

| | Budget |
|---|---|
| Release binary | < 5 MB |
| Idle memory | < 15 MB |
| Added delay per request | measured and published, target < 5 ms for typical requests |

## Left to the builder

Exact regexes, name lists, port number (7390), log field names, and module layout.

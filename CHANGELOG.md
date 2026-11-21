# Changelog

## 0.1.0 — unreleased

First release.

- Local proxy for Anthropic and OpenAI APIs on `127.0.0.1:7390`; forwards to whatever the tools used
  before (provider, proxy or gateway).
- Masks secrets (provider keys, JWTs, bearer tokens, PEM keys, URL passwords, secret settings),
  personal data (emails, phones, cards, IBANs, US SSNs, public IPs, labelled IDs in English and
  Nepali) and names (English and Devanagari).
- Keyed, stable stand-ins; in-memory vault; restoring in JSON and streamed answers, including
  stand-ins split across events and inside tool-call arguments.
- Tells the model that stand-ins are placeholders to use as written.
- Fails closed: unreadable or compressed bodies refused; WebSocket answered with 426.
- `install` routes Claude Code, Codex, Aider and SDK apps with no settings; `uninstall` restores
  every file; `status`; `mask`.
- Evidence log with kinds and counts, never values.
- Install never overwrites a file it can't read; uninstall says what it couldn't put back.

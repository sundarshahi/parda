# Changelog

## Unreleased

Fixed (found by fuzzing):

- A long run of numbers (a pasted table, a column of ids) no longer stalls the proxy: the card check
  took time with the cube of the run's length, 1.7 s for 4 KB of digits and eight times that for 8 KB.
- A value found by the name beside it (`DB_PASSWORD=…`) is now masked everywhere else it appears in
  the same request, including bare (`mysql -p…`) and in earlier messages.

Fuzz targets for masking, requests and streamed answers run in CI.

## 0.2.0 — 2026-11-25

- Gemini CLI and apps using Google's Gen AI SDK: `install` sets `GOOGLE_GEMINI_BASE_URL` and
  `CODE_ASSIST_ENDPOINT`; Gemini requests and streamed answers are masked and restored (media,
  signatures and thought summaries handled).
- GitHub Copilot CLI and VS Code chat with your own Anthropic or OpenAI key: documented setup.

Fixed (found by an independent audit):

- A value masked once is now masked wherever it comes back, so a password the model wrote into a
  command can't leave unmasked in the next request.
- Secrets under JSON keys named like secrets (`{"DB_PASSWORD": "…"}`), `.env` text inside JSON strings,
  URL passwords with no user or with a `/`, every address in a list of IPs, and card numbers next to
  other digits are now masked.
- Fewer false finds: `PWD=`, names about secrets (`secret_name`, `password_reset_url`), numbers that
  pass Luhn but belong to no card brand. Big numbers keep every digit.
- A stand-in split around a keep-alive (`ping`, SSE comment) is now restored.
- The local port refuses web pages (`Origin`, `Sec-Fetch-Site`, foreign `Host`); idle connections time
  out; connections, request lines and headers are capped.
- Percent-encoded data in the URL is refused like plain data.
- Text files sent inline are checked.
- The note to the model is added only to requests that ask it for an answer (not embeddings or token
  counts).
- Install: a startup file without a final newline stays valid; Codex config keeps comments, line
  endings and the user's line in place; a startup file that can't be written is reported and skipped.
- Uninstall: Claude Code settings come back byte for byte; startup files parda created are removed.

## 0.1.0 — 2026-11-22

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

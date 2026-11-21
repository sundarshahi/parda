# parda

**Use AI without handing it your secrets.** parda masks API keys, passwords, names, emails and ID
numbers before your AI coding agent sends them, and puts the real values back in the answer.
Local, open source, no settings.

[![ci](https://github.com/sundarshahi/parda/actions/workflows/ci.yml/badge.svg)](https://github.com/sundarshahi/parda/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

*Parda* (पर्दा) is Nepali for curtain: the AI sees stand-ins, you see your data.

**Docs: [sundarshahi.github.io/parda](https://sundarshahi.github.io/parda/)**

```
You ask your agent      Add Sita Sharma (sita@acme.com) to the seed file, DB_PASSWORD=Hunter2Hunter2
The AI company gets     Add [PERSON_3f9a2c1d] (email_51c0d9e2@parda.invalid) to the seed file, DB_PASSWORD=[SECRET_8b01e4aa]
Your file ends up with  name: "Sita Sharma", email: "sita@acme.com"
```

- **Nothing leaves to be checked.** Detection runs on your machine with rules. No AI model, no cloud
  scanner, no telemetry. The table from stand-ins back to real values lives only in memory.
- **No settings.** Install once; Claude Code, Codex, Aider and apps using the Anthropic or OpenAI SDKs
  go through parda. `parda uninstall` puts every file back exactly.
- **Agents keep working.** The same value always gets the same stand-in, prompt caching keeps
  working, and real values come back into commands and file edits — even when a stand-in is split
  across two pieces of a streamed answer.
- **Fails closed.** If parda isn't running, AI requests fail with an error instead of going out
  unfiltered. Bodies it can't read are refused, not forwarded.
- **Light.** A 2 MB program using about 2.5 MB of memory. Masking a 150 KB Claude Code request
  takes 6–8 ms on an Apple M2 Pro.
- **Free forever.** MIT or Apache-2.0. No paid plan, no accounts.

## Install

macOS and Linux (WSL 2 works):

```sh
curl -fsSL https://raw.githubusercontent.com/sundarshahi/parda/main/install.sh | sh
```

or from source with Rust 1.85+:

```sh
cargo install --git https://github.com/sundarshahi/parda && parda install
```

Open a new terminal and restart your AI tools. Then:

```sh
parda status                       # running? where requests go, what was masked today
echo "Ram Thapa, ram@example.com" | parda mask   # see masking without any AI tool
parda uninstall                    # put everything back
```

[What install changes on your machine →](https://sundarshahi.github.io/parda/install.html#what-install-changes)

## What it masks

| | |
|---|---|
| **Secrets** | Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, Google, npm, SendGrid, Twilio keys; JWTs; bearer tokens; PEM private keys; passwords in URLs; values of settings named like `*_PASSWORD`, `*_SECRET`, `api_key`, `clientSecret` |
| **Personal data** | Emails, phone numbers, card numbers (Luhn), IBANs (checksum), US SSNs, public IPs, ID numbers next to a label (PAN, नागरिकता, passport, national ID, tax ID…) |
| **Names** | Two or more words, English or Devanagari, using lists of given names, middle names and surnames — including Nepali |

Known limits, stated plainly: single-word and lower-case names, addresses and dates of birth are
not detected, and images, PDFs and audio pass through unchecked.
[Full list and limits →](https://sundarshahi.github.io/parda/what-it-masks.html)

## Supported tools

| Tool | |
|---|---|
| Claude Code (CLI, VS Code, JetBrains) | ✓ tested |
| Codex CLI | ✓ set up automatically (`~/.codex/config.toml`) |
| Aider | ✓ via `OPENAI_API_BASE` / `ANTHROPIC_API_BASE` |
| Apps using the Anthropic / OpenAI SDKs | ✓ via `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` |
| Gemini CLI, Copilot, browser chats | planned |
| Cursor | can't be covered: it builds prompts on its own servers |

Already using another proxy or a company gateway? parda keeps it and forwards there.
[Details →](https://sundarshahi.github.io/parda/tools.html)

## How it works

```
your AI tool ──http──▶ parda (127.0.0.1:7390) ──https──▶ AI company
  real data             mask ▸ vault ▸ restore             sees stand-ins only
```

Secrets are **tokenized** (replaced and restored only on your machine — never deleted, because an
agent writing `[REDACTED]` back into your `.env` would destroy it). Personal data is
**pseudonymized** with a keyed BLAKE3 hash: same value, same stand-in, and nobody without your key
can reverse it. Signed fields such as thinking blocks are never touched.
[How it works →](https://sundarshahi.github.io/parda/how-it-works.html) ·
[Design and trade-offs →](docs/design.md)

## For compliance teams

Every request adds one line to `~/.parda/log.jsonl` with the kinds and counts of what was masked —
never the values. parda contributes to ISO 27001 A.8.11 (data masking) and A.8.12 (DLP), SOC 2
CC6.7 and CC7.2, and GDPR pseudonymisation, with the re-identification table kept on the exporter's
machine. It doesn't make you compliant on its own.
[For compliance teams →](https://sundarshahi.github.io/parda/compliance.html)

## Contributing

Bug reports, missed or false finds (with made-up examples — never real data), name lists for more
languages and support for more tools are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: please report privately, see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option. Contributions are dual-licensed the same way.

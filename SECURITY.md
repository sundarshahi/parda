# Security policy

## Supported versions

Security fixes go into the latest release.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**. Don't open a public issue. You'll get a reply within a week, and
a fix or a plan within 30 days.

A leak counts: if you find input that should be masked but reaches the AI provider in clear text in
a way the [known limits](https://sundarshahi.github.io/parda/what-it-masks.html#known-limits) don't
describe, please report it privately too. Use made-up data in your report.

## What parda can do on your machine

So you can judge the impact of a report:

- It runs as your own user and never asks for root.
- It listens on `127.0.0.1:7390` only, and forwards the requests your AI tools send to the address
  they used before parda (an AI provider, or a proxy you already had). It makes no other network
  connections and collects no telemetry.
- Real values are kept only in memory and never written to disk. The key that makes stand-ins is in
  `~/.parda/key` (mode 0600). The log `~/.parda/log.jsonl` (mode 0600) records kinds and counts,
  never values.
- It writes `~/.parda`, a marked block in shell startup files (`~/.zshenv`, `~/.zshrc`,
  `~/.bashrc`, `~/.bash_profile`, fish `conf.d`), `env.ANTHROPIC_BASE_URL` in Claude Code's
  `settings.json`, a marked `openai_base_url` in Codex's `config.toml`, and its login service (a
  LaunchAgent or systemd user service). `parda uninstall` removes each one.
- `install.sh` downloads a release from GitHub and checks its SHA-256 checksum before running it.

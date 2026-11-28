# Contributing to parda

Thanks for helping. The most useful contributions, in order:

1. **A miss or a false find.** Something parda should have masked and didn't, or masked when it
   shouldn't have. Usually a rule tweak and a one-line test.
2. **Names for more languages and regions.** The lists in [`data/`](data/) are plain text.
3. **Support for another tool** (Gemini CLI, Copilot Chat with your own key, …).
4. **Bug reports** with `parda status` and the matching lines from `~/.parda/log.jsonl`.

> **Never paste real secrets or personal data** in an issue, a test or a commit — not even "old"
> ones. Use made-up examples like `Ram Bahadur Thapa`, `ram@example.com`, `4111 1111 1111 1111`.

Please read [docs/design.md](docs/design.md) before changing behaviour: most choices there were
measured or tested against a real coding agent.

## Set up

Rust 1.85 or newer, on macOS or Linux.

```sh
git clone https://github.com/sundarshahi/parda
cd parda
cargo test
```

`cargo test` runs the unit tests and two end-to-end suites:

- [`tests/proxy.rs`](tests/proxy.rs) starts the real `parda run` between a client and a fake AI
  provider on random local ports, and checks what each side sees.
- [`tests/install.rs`](tests/install.rs) runs `parda install` and `parda uninstall` in a throwaway home
  folder and checks every file comes back exactly. It never touches your real home folder or
  services.

Try it without any AI tool:

```sh
echo "Sita Sharma, sita@example.com, DB_PASSWORD=Hunter2Hunter2" | cargo run -q -- mask
```

Measure the rules on a big file:

```sh
PARDA_BENCH_FILE=some-large-file.txt cargo test --release bench -- --ignored --nocapture
```

Fuzz the masking and the stream restoring (nightly Rust and `cargo install cargo-fuzz`):

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run request fuzz/corpus/request fuzz/seeds/request -- -dict=fuzz/parda.dict -max_total_time=60
```

The targets in [`fuzz/fuzz_targets`](fuzz/fuzz_targets) check properties, not only crashes: a found
value is gone from what leaves, restoring gives the request back, and a stream restores the same
however it is cut into chunks. CI runs each for a minute on pull requests and ten on Mondays.

## Where things are

| File | What it does |
|---|---|
| `src/detect.rs` | The rules: secrets, emails, phones, cards, IBANs, IDs. Tests for each. |
| `src/names.rs`, `data/*.txt` | Name detection in Latin script and Devanagari, and the word lists. |
| `src/vault.rs` | Stand-ins (keyed BLAKE3), the in-memory vault, restoring. |
| `src/body.rs` | Walking JSON request/response bodies; which fields are skipped; the note to the model. |
| `src/sse.rs` | Restoring stand-ins in streamed answers, including ones split across events. |
| `src/proxy.rs` | The local HTTP server and forwarding upstream. |
| `src/setup.rs` | `install` / `uninstall` / `status`: shell files, Claude Code and Codex settings, login service. |
| `src/log.rs` | The evidence log. |

## Changing a rule

1. Add a test with the text that should (or shouldn't) be found, in `src/detect.rs` or `src/names.rs`.
   Watch it fail.
2. Change the rule. Keep rules ASCII-only (`(?-u)`, `[0-9]`) unless they need other scripts: Unicode
   `\b` and `\d` are around 100× slower on large requests.
3. Run the benchmark above on a large file if you touched a regular expression.
4. Remember the direction of safety: **when unsure, mask.** A false find costs the AI a little
   context and is restored for the user; a miss is a leak. The exception is ordinary code
   (`max_tokens: 4096`, `token = getToken()`), which agents read all day.

## Before you open a pull request

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

- Keep changes small and focused; one pull request per change.
- A bug fix comes with a test that fails without the fix.
- A behaviour change updates `docs/design.md`, the site in `site/` if users see it, and `CHANGELOG.md`.
- Comments explain *why* in a line or two; longer explanations belong in the pull request.

## The website

`site/` is plain HTML and one CSS file; there is no build step. Every colour, size and space comes
from the variables at the top of `site/style.css`. Preview by opening `site/index.html` in a browser.
It is published to GitHub Pages by [`.github/workflows/pages.yml`](.github/workflows/pages.yml) on
every push to `main` that changes `site/`.

## Releasing (maintainers)

1. Update the version in `Cargo.toml` and move `CHANGELOG.md` entries under it.
2. Commit, then tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. The [release workflow](.github/workflows/release.yml) builds macOS and Linux binaries (x86_64 and
   arm64), adds SHA-256 checksums and publishes the GitHub release that `install.sh` downloads.

## Security issues

Please don't open a public issue; see [SECURITY.md](SECURITY.md).

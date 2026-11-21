//! parda: a curtain between your machine and every AI. Secrets and personal data are swapped for
//! stand-ins before a request leaves; real values are put back in the answer. Local, no settings.

mod body;
mod detect;
mod log;
mod names;
mod proxy;
mod setup;
mod sse;
mod vault;

use std::io::Read;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

const HELP: &str =
    "parda — masks secrets and personal data before AI tools send them, and puts them back in the answer.

Usage:
  parda install     Start parda now and at login, and route AI tools through it
  parda status      Is it running, where requests go, what was masked today
  parda mask        Mask text from stdin (try it, or use it before pasting into a web chat)
  parda uninstall   Put everything back the way it was
  parda run         Run the proxy in this terminal (what the background service runs)

Docs: https://sundarshahi.github.io/parda/";

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "install" => match setup::install() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("parda install failed: {e}");
                ExitCode::FAILURE
            }
        },
        "uninstall" => {
            setup::uninstall();
            ExitCode::SUCCESS
        }
        "status" => {
            setup::status();
            ExitCode::SUCCESS
        }
        "mask" => mask(),
        "run" => run(),
        "-V" | "--version" | "version" => {
            println!("parda {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "" | "-h" | "--help" | "help" => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("parda: unknown command `{other}`\n\n{HELP}");
            ExitCode::FAILURE
        }
    }
}

fn vault() -> Result<vault::Vault, String> {
    let key = vault::Vault::load_or_create_key(&setup::dir()).map_err(|e| format!("could not read the key: {e}"))?;
    Ok(vault::Vault::new(key))
}

fn mask() -> ExitCode {
    let mut text = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut text) {
        eprintln!("parda: could not read stdin as text: {e}");
        return ExitCode::FAILURE;
    }
    let v = match vault() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parda: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut counts = vault::Counts::new();
    print!("{}", v.mask(&text, &mut counts).unwrap_or(text));
    let summary: Vec<String> = counts.iter().map(|(k, n)| format!("{n} {k}")).collect();
    eprintln!("parda: masked {}", if summary.is_empty() { "nothing".into() } else { summary.join(", ") });
    ExitCode::SUCCESS
}

fn run() -> ExitCode {
    let dir = setup::dir();
    let v = match vault() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parda: {e}");
            return ExitCode::FAILURE;
        }
    };
    let port = setup::port();
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("parda: could not listen on 127.0.0.1:{port}: {e}");
            if setup::running() {
                eprintln!("parda is already running there.");
            }
            return ExitCode::FAILURE;
        }
    };
    let port = listener.local_addr().map_or(port, |a| a.port());
    eprintln!("parda: listening on http://127.0.0.1:{port}");
    let routes = setup::routes(&dir);
    for r in &routes {
        eprintln!("parda: http://127.0.0.1:{port}{} → {}", r.prefix, r.upstream);
    }
    vault::token_re();
    detect::warm_up(); // build the rules now, not on the first request
    proxy::serve(Arc::new(proxy::State::new(v, routes, dir)), listener);
    ExitCode::SUCCESS
}

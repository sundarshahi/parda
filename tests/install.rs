//! `parda install` then `parda uninstall` in a throwaway home folder: every file parda touches comes
//! back exactly as it was, and whatever the tools used before becomes parda's upstream.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

fn parda(home: &Path, cmd: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_parda"))
        .arg(cmd)
        .env_clear()
        .env("HOME", home)
        .env("SHELL", "/bin/zsh")
        .env("PATH", "/usr/bin:/bin")
        .env("PARDA_NO_SERVICE", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{cmd}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn install_routes_everything_and_uninstall_restores_every_file() {
    let home = std::env::temp_dir().join(format!("parda-home-{}", std::process::id()));
    fs::remove_dir_all(&home).ok();
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    let files = [
        (
            ".zshrc",
            "# >>> other proxy >>>\nexport ANTHROPIC_BASE_URL=http://127.0.0.1:8787\n# <<< other proxy <<<\nalias ll='ls -l'", // no final newline
        ),
        (
            ".claude/settings.json",
            // tabs and a compact object: formatting must survive too
            "{\n\t\"env\": {\"ANTHROPIC_BASE_URL\": \"http://127.0.0.1:8787\"},\n\t\"model\": \"opus\"\n}\n",
        ),
        (
            ".codex/config.toml",
            "model = \"gpt-5\"\nopenai_base_url = \"https://gw.example.com/v1\" # company gateway\n\n[profiles.fast]\nmodel = \"gpt-5-mini\"\n",
        ),
    ];
    for (f, text) in files {
        fs::write(home.join(f), text).unwrap();
    }
    let latin1 = b"export NAME='Jos\xe9'\n"; // not UTF-8: must be left exactly as it is
    fs::write(home.join(".bash_profile"), latin1).unwrap();

    let said = parda(&home, "install");
    assert!(said.contains("Anthropic requests go on to http://127.0.0.1:8787"), "{said}");
    assert!(said.contains("OpenAI requests go on to https://gw.example.com/v1"), "{said}");

    assert!(
        said.contains("Gemini CLI (Google sign-in) requests go on to https://cloudcode-pa.googleapis.com"),
        "{said}"
    );

    let up: Value = serde_json::from_str(&fs::read_to_string(home.join(".parda/upstreams.json")).unwrap()).unwrap();
    assert_eq!(up["anthropic"], "http://127.0.0.1:8787");
    assert_eq!(up["gemini"], "https://generativelanguage.googleapis.com");
    let settings: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap()).unwrap();
    assert_eq!(settings["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:7390/anthropic");
    assert!(
        fs::read_to_string(home.join(".codex/config.toml"))
            .unwrap()
            .contains("openai_base_url = \"http://127.0.0.1:7390/openai\"")
    );
    let zshrc = fs::read_to_string(home.join(".zshrc")).unwrap();
    assert!(zshrc.find("other proxy").unwrap() < zshrc.find(">>> parda >>>").unwrap(), "parda's block runs last");
    let env_sh = fs::read_to_string(home.join(".parda/env.sh")).unwrap();
    for line in [
        "ANTHROPIC_BASE_URL=\"http://127.0.0.1:7390/anthropic\"",
        "GOOGLE_GEMINI_BASE_URL=\"http://127.0.0.1:7390/gemini\"",
        "CODE_ASSIST_ENDPOINT=\"http://127.0.0.1:7390/gemini-code\"",
    ] {
        assert!(env_sh.contains(line), "{line} missing from env.sh:\n{env_sh}");
    }
    for f in [".zshenv", ".zshrc"] {
        let ok = Command::new("zsh").arg("-n").arg(home.join(f)).status().map_or(true, |s| s.success());
        assert!(ok, "{f} must still be valid shell after install");
    }
    let key = fs::metadata(home.join(".parda/key")).unwrap();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&key.permissions()) & 0o777, 0o600);

    parda(&home, "install"); // a second install changes nothing it shouldn't
    parda(&home, "uninstall");
    for (f, text) in files {
        assert_eq!(fs::read_to_string(home.join(f)).unwrap(), text, "{f} not restored exactly");
    }
    assert_eq!(fs::read(home.join(".bash_profile")).unwrap(), latin1, "a file parda can't read is never touched");
    for f in [".zshenv", ".bashrc", ".config/fish/conf.d/parda.fish"] {
        assert!(!home.join(f).exists(), "{f}: a file parda created is gone again");
    }
    fs::remove_dir_all(&home).ok();
}

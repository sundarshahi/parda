//! Finds secrets and personal data in text, using rules only. Nothing here touches the network.
//!
//! When unsure, a rule matches: a false find costs the AI a little context (and is restored for the
//! user anyway); a miss is a leak.

use crate::names;
use regex::Regex;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Secret,
    Person,
    Email,
    Phone,
    Card,
    Iban,
    Ssn,
    Ip,
    Id,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Secret => "SECRET",
            Kind::Person => "PERSON",
            Kind::Email => "EMAIL",
            Kind::Phone => "PHONE",
            Kind::Card => "CARD",
            Kind::Iban => "IBAN",
            Kind::Ssn => "SSN",
            Kind::Ip => "IP",
            Kind::Id => "ID",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Find {
    pub start: usize,
    pub end: usize,
    pub kind: Kind,
}

struct Rule {
    kind: Kind,
    re: Regex,
    /// Capture group holding the value (0 = whole match).
    group: usize,
    /// Extra check on the value; the rule matches only if it returns true.
    check: fn(&str) -> bool,
    /// Capture group holding a setting's name (0 = none); see `secret_setting`.
    name_group: usize,
}

fn any(_: &str) -> bool {
    true
}

fn rule(kind: Kind, re: &str, group: usize, check: fn(&str) -> bool) -> Rule {
    Rule { kind, re: Regex::new(re).unwrap_or_else(|e| panic!("bad rule {re}: {e}")), group, check, name_group: 0 }
}

/// `name = value` / `"name": "value"`: group 1 is the name, group 2 the value.
fn setting(re: &str) -> Rule {
    Rule { name_group: 1, ..rule(Kind::Secret, re, 2, any) }
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        use Kind::*;
        vec![
            // Secrets with a known shape.
            // A private key to its END line, or to the end of the text when cut off (head, a line limit).
            rule(Secret, r"-----BEGIN[A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END[A-Z ]*PRIVATE KEY(?: BLOCK)?-----|[\s\S]*\z)", 0, any),
            rule(Secret, r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 0, any),
            rule(Secret, r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", 0, any),
            rule(Secret, r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b", 0, any),
            rule(Secret, r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})", 0, any),
            rule(Secret, r"\bglpat-[A-Za-z0-9_\-]{20,}", 0, any),
            rule(Secret, r"\bxox[abposr]-[A-Za-z0-9\-]{10,}", 0, any),
            rule(Secret, r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", 0, any),
            rule(Secret, r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|\bwhsec_[A-Za-z0-9]{20,}", 0, any),
            rule(Secret, r"\bAIza[0-9A-Za-z_\-]{35}", 0, any),
            rule(Secret, r"\bnpm_[A-Za-z0-9]{36}", 0, any),
            rule(Secret, r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", 0, any),
            rule(Secret, r"\bSK[0-9a-fA-F]{32}\b", 0, any),
            rule(Secret, r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 0, any),
            rule(Secret, r"\bhf_[A-Za-z0-9]{30,}|\bya29\.[0-9A-Za-z_\-]{20,}|\bpypi-AgE[A-Za-z0-9_\-]{50,}", 0, any),
            rule(Secret, r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)", 1, any),
            rule(Secret, r"(?i)\bbasic\s+([A-Za-z0-9+/]{12,}={0,2})", 1, any),
            // curl -u user:password / --user user:password
            rule(Secret, r"\bcurl\b[^\n]*?\s(?:-u|--user)[ =][\x22']?[^\s:\x22']+:([^\s\x22']{3,})", 1, not_placeholder),
            // Password inside a URL: scheme://user:PASSWORD@host
            rule(Secret, r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]*:([^\s@?#]+)@", 1, url_password),
            // Settings whose name says secret: KEY=value lines (.env, shell, YAML) and quoted values
            // anywhere (JSON, code, config). The name and value are judged in `secret_setting`.
            // (`#` starts a comment only after a space, so it can be part of a value.)
            setting(r#"(?m)(?:^|\\[nr])[ \t]*(?:export[ \t]+)?([A-Za-z][A-Za-z0-9_.\-]*)[ \t]*[=:][ \t]*(?:\\?[\x22'])?((?:[^\s\x22',;\\]|\\[^nrt\x22]){4,})"#),
            // Quoted values may hold spaces: "correct horse battery staple".
            setting(r"\\?[\x22']?([A-Za-z][A-Za-z0-9_.\-]*)\\?[\x22']?\s*(?::|=|=>)\s*\\?\x22((?:[^\x22\n\\]|\\[^\x22nrt]){4,})\\?\x22"),
            setting(r"[\x22']?([A-Za-z][A-Za-z0-9_.\-]*)[\x22']?\s*(?::|=|=>)\s*'([^'\n]{4,})'"),
            // NAME=value mid-line: prose, `PGPASSWORD=… psql`, `curl -u`. Trailing punctuation isn't part of it.
            setting(r"(?:^|[\s;&|(]|\\[nrt])([A-Za-z][A-Za-z0-9_]*)=((?:[^\s\x22'#,;&|)\\]|\\[^nrt\x22]){3,}[^\s\x22'#,;&|).:!?\\])"),
            // Personal data.
            rule(Email, r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b", 0, |v| {
                !v.ends_with("@parda.invalid")
            }),
            rule(Phone, r"(?-u)\+\d[\d \-().]{6,18}\d", 0, |v| (8..=15).contains(&digits(v).len())),
            rule(Phone, r"(?-u)\b9[678]\d{8}\b", 0, any),
            rule(Phone, r"(?-u)\(\d{3}\) ?\d{3}-\d{4}\b|\b\d{3}-\d{3}-\d{4}\b|\b0\d{1,2}-\d{6,7}\b", 0, any),
            rule(Iban, r"(?-u)\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, iban),
            rule(Ssn, r"(?-u)\b(\d{3})-(\d{2})-(\d{4})\b", 0, ssn),
            // ID numbers next to a label, in English or Nepali, with ASCII or Devanagari digits.
            // `(?-u)` / ASCII classes keep the fast engine: Unicode \b and \d are ~100× slower here.
            rule(
                Id,
                r"(?i)(?:(?-u:\b)(?:PAN|VAT|citizenship|nagarikta|passport|national[ _-]?id|NID|aadhaa?r|social security|driving licen[cs]e|licen[cs]e no|tax[ _-]?id|TIN|employee[ _-]?id|staff[ _-]?id)(?-u:\b)|प्यान|पान|नागरिकता|राहदानी|परिचयपत्र)[^\n0-9०-९]{0,20}?([A-Z]{0,2}[0-9०-९][0-9०-९\-/ ]{3,18}[0-9०-९])",
                1,
                any,
            ),
        ]
    })
}

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// A URL password, not a port and path (`https://host:8080/a@b`).
fn url_password(v: &str) -> bool {
    let port = v.bytes().take_while(u8::is_ascii_digit).count();
    not_placeholder(v) && !(port > 0 && (port == v.len() || v.as_bytes()[port] == b'/'))
}

fn not_placeholder(v: &str) -> bool {
    !(v.starts_with("${") || v.starts_with('<') || v.starts_with('{') || v.chars().all(|c| c == '*' || c == 'x'))
}

/// A word in a setting's name containing one of these means "the value is a secret" — any value
/// counts (`PGPASSWORD`, `clientSecret`). Short ones must be the whole word (`pass`, not `bypass`).
const STRONG: [&str; 5] = ["password", "passwd", "secret", "credential", "passphrase"];
const STRONG_WHOLE: [&str; 3] = ["pass", "pwd", "passcode"];
/// Words that usually mean a secret, but also name ordinary things (`primary_key`, `auth: true`): the
/// value must also look random.
const WEAK: [&str; 8] = ["key", "apikey", "token", "auth", "accesskey", "privatekey", "authtoken", "accesstoken"];
/// A name ending in one of these names something about a secret, not the secret itself
/// (`secret_name`, `password_reset_url`, `credentials_file`).
const ABOUT: [&str; 21] = [
    "name", "names", "url", "uri", "path", "file", "dir", "id", "arn", "ref", "length", "len", "min", "max", "policy",
    "type", "field", "label", "hint", "prompt", "pattern",
];

/// Splits `DB_PASSWORD`, `api-key`, `clientSecret`, `Co-Authored-By` into lowercase words.
fn name_words(name: &str) -> Vec<String> {
    let mut words = vec![String::new()];
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            words.push(String::new());
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower {
            words.push(String::new());
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        words.last_mut().expect("never empty").push(c.to_ascii_lowercase());
    }
    words.retain(|w| !w.is_empty());
    words
}

/// Whether `value`, set under `name` (a `KEY=value` line, a JSON key), is a secret.
pub fn secret_setting(name: &str, value: &str) -> bool {
    let words = name_words(name);
    // `PWD` / `OLDPWD` are the shell's working directory.
    if words.last().is_some_and(|w| ABOUT.contains(&w.as_str())) || matches!(name, "PWD" | "OLDPWD") {
        return false;
    }
    let strong = words.iter().any(|w| STRONG.iter().any(|s| w.contains(s)) || STRONG_WHOLE.contains(&w.as_str()));
    let weak = words.iter().any(|w| WEAK.contains(&w.as_str()));
    let plain = not_placeholder(value)
        && !value.starts_with('$')
        && !matches!(value.to_ascii_lowercase().as_str(), "true" | "false" | "null" | "none" | "nil" | "undefined")
        && !value.chars().all(|c| c.is_ascii_digit())
        && !looks_like_code(value);
    let random = (value.chars().any(|c| c.is_ascii_digit()) && value.chars().any(|c| c.is_ascii_alphabetic()))
        || (value.len() >= 16 && !value.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c == '-' || c == '.'));
    plain && (strong || (weak && random && !value.contains(char::is_whitespace)))
}

fn looks_like_code(v: &str) -> bool {
    v.contains('(')
        || v.contains('[')
        || v.starts_with("process.env")
        || v.starts_with("os.environ")
        || v.starts_with("ENV")
        || v.starts_with("env.")
        || v.starts_with("config.")
        || v.starts_with("settings.")
}

fn luhn(d: &str) -> bool {
    let mut sum = 0;
    for (i, c) in d.bytes().rev().enumerate() {
        let mut n = (c - b'0') as u32;
        if i % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
    }
    sum % 10 == 0
}

/// A card number: a known brand prefix with that brand's lengths, and a valid Luhn check.
fn card(d: &str) -> bool {
    let n = d.len();
    if !(13..=19).contains(&n) || !d.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let p = |k: usize| d[..k].parse::<u32>().unwrap_or(0);
    let brand = match d.as_bytes()[0] {
        b'4' => matches!(n, 13 | 16 | 19),
        b'5' => (51..=55).contains(&p(2)) && n == 16,
        b'2' => (2221..=2720).contains(&p(4)) && n == 16,
        b'3' => {
            (matches!(p(2), 34 | 37) && n == 15)
                || (p(2) == 35 && n >= 16)
                || ((matches!(p(2), 36 | 38) || (300..=305).contains(&p(3))) && n >= 14)
        }
        b'6' => (p(4) == 6011 || matches!(p(2), 62 | 65) || (644..=649).contains(&p(3))) && n >= 16,
        _ => false,
    };
    brand && luhn(d)
}

/// Card numbers, also when other digits sit next to them (`4111 1111 1111 1111 123`, a CVV or a
/// quantity): runs of digit groups are tried whole, then as consecutive groups.
fn card_finds(text: &str, out: &mut Vec<Find>) {
    static RUN: OnceLock<Regex> = OnceLock::new();
    let run = RUN.get_or_init(|| Regex::new(r"(?-u)\b\d+(?:[ \-]\d+)*\b").unwrap());
    for m in run.find_iter(text) {
        // (start, end) of each digit group, as byte offsets in `text`
        let mut groups: Vec<(usize, usize)> = Vec::new();
        for (i, c) in m.as_str().bytes().enumerate() {
            let at = m.start() + i;
            match (c.is_ascii_digit(), groups.last_mut()) {
                (true, Some(g)) if g.1 == at => g.1 = at + 1,
                (true, _) => groups.push((at, at + 1)),
                _ => {}
            }
        }
        let mut i = 0;
        while i < groups.len() {
            let mut hit = None;
            // A card has at most 19 digits, so at most 19 groups; looking further cost the cube of the run.
            for j in (i..groups.len().min(i + 19)).rev() {
                let d: String = groups[i..=j].iter().map(|&(a, b)| &text[a..b]).collect();
                if d.len() > 19 {
                    continue;
                }
                if card(&d) {
                    hit = Some(j);
                    break;
                }
            }
            match hit {
                Some(j) => {
                    out.push(Find { start: groups[i].0, end: groups[j].1, kind: Kind::Card });
                    i = j + 1;
                }
                None => i += 1,
            }
        }
    }
}

/// Public IPv4 addresses. Not part of a longer dotted run (`1.2.3.4.5` is a version).
fn ip_finds(text: &str, out: &mut Vec<Find>) {
    static IP: OnceLock<Regex> = OnceLock::new();
    let ip = IP.get_or_init(|| Regex::new(r"(?-u)\d{1,3}(?:\.\d{1,3}){3}").unwrap());
    let b = text.as_bytes();
    for m in ip.find_iter(text) {
        let before = m.start().checked_sub(1).map(|i| b[i]);
        let after = b.get(m.end()).copied();
        let after2 = b.get(m.end() + 1).copied();
        let word = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_');
        let joined = before == Some(b'.') || word(before) || word(after) || (after == Some(b'.') && word(after2));
        if !joined && public_ip(m.as_str()) {
            out.push(Find { start: m.start(), end: m.end(), kind: Kind::Ip });
        }
    }
}

fn iban(v: &str) -> bool {
    let s: String = v.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let rearranged = s[4..].chars().chain(s[..4].chars());
    let mut rem: u64 = 0;
    for c in rearranged {
        let n = match c {
            '0'..='9' => c as u64 - '0' as u64,
            'A'..='Z' => c as u64 - 'A' as u64 + 10,
            _ => return false,
        };
        rem = if n >= 10 { (rem * 100 + n) % 97 } else { (rem * 10 + n) % 97 };
    }
    rem == 1
}

fn ssn(v: &str) -> bool {
    let p: Vec<&str> = v.split('-').collect();
    p[0] != "000" && p[0] != "666" && !p[0].starts_with('9') && p[1] != "00" && p[2] != "0000"
}

fn public_ip(v: &str) -> bool {
    let Ok(ip) = v.parse::<Ipv4Addr>() else { return false };
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1])) // carrier-grade NAT
        || o[0] >= 224)
}

pub fn warm_up() {
    scan("Ram Thapa राम थापा a@b.co 4111111111111111");
}

/// Every find in `text`, sorted, non-overlapping (earliest start wins, then secrets, then the longest).
/// Stand-ins parda already wrote are never found again.
pub fn scan(text: &str) -> Vec<Find> {
    scan_with(text, Vec::new())
}

/// `scan`, plus finds the caller already has (values masked before, wherever they appear now).
pub fn scan_with(text: &str, mut all: Vec<Find>) -> Vec<Find> {
    for r in rules() {
        for c in r.re.captures_iter(text) {
            if let Some(m) = c.get(r.group) {
                let named =
                    r.name_group == 0 || c.get(r.name_group).is_some_and(|n| secret_setting(n.as_str(), m.as_str()));
                if named && (r.check)(m.as_str()) {
                    all.push(Find { start: m.start(), end: m.end(), kind: r.kind });
                }
            }
        }
    }
    card_finds(text, &mut all);
    ip_finds(text, &mut all);
    all.extend(names::scan(text));
    let tokens: Vec<_> = crate::vault::token_re().find_iter(text).map(|m| (m.start(), m.end())).collect();
    all.retain(|f| !tokens.iter().any(|&(s, e)| f.start < e && s < f.end));
    // Same start: a secret beats anything else (the password in `user:pw@host` over an email).
    all.sort_by_key(|f| (f.start, f.kind != Kind::Secret, std::cmp::Reverse(f.end)));
    let mut out: Vec<Find> = Vec::with_capacity(all.len());
    for f in all {
        if out.last().is_none_or(|l| f.start >= l.end) {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<(Kind, &str)> {
        scan(text).into_iter().map(|f| (f.kind, &text[f.start..f.end])).collect()
    }

    fn one(text: &str, kind: Kind, value: &str) {
        let f = found(text);
        assert!(f.contains(&(kind, value)), "expected {kind:?} {value:?} in {text:?}, got {f:?}");
    }

    fn none(text: &str) {
        assert_eq!(found(text), vec![], "expected nothing in {text:?}");
    }

    #[test]
    fn secrets() {
        one(
            "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123",
            Kind::Secret,
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123",
        );
        one("key: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX1234", Kind::Secret, "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX1234");
        one("aws AKIAIOSFODNN7EXAMPLE here", Kind::Secret, "AKIAIOSFODNN7EXAMPLE");
        one("token ghp_abcdefghijklmnopqrstuvwxyz0123456789", Kind::Secret, "ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        one("DATABASE_URL=postgres://app:Sup3rS3cret@db.internal:5432/app", Kind::Secret, "Sup3rS3cret");
        one("DB_PASSWORD=hunter22", Kind::Secret, "hunter22");
        one("run PGPASSWORD=s3cretpw psql -h db", Kind::Secret, "s3cretpw");
        one(r#"DB_PASSWORD="my secret pass 2024""#, Kind::Secret, "my secret pass 2024");
        one(r#"{"password": "correct horse battery staple"}"#, Kind::Secret, "correct horse battery staple");
        one("DB_PASSWORD=abc#defgh", Kind::Secret, "abc#defgh");
        one("DB_PASSWORD=Tr0ub4dor#3xyz", Kind::Secret, "Tr0ub4dor#3xyz");
        one("Authorization: Basic dXNlcjpodW50ZXIycGFzcw==", Kind::Secret, "dXNlcjpodW50ZXIycGFzcw==");
        one("curl -u admin:hunter2pass https://x", Kind::Secret, "hunter2pass");
        // Built at run time so secret scanners don't mistake the fake for a real token.
        let hf = ["hf", "_abcdefghijklmnopqrstuvwxyzABCDEFGH"].concat();
        one(&format!("HF {hf}"), Kind::Secret, &hf);
        let cut = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAA";
        one(&format!("head of the file:\n{cut}"), Kind::Secret, cut);
        one("the line DB_PASSWORD=Hunter2Hunter2. Then", Kind::Secret, "Hunter2Hunter2");
        one("export STRIPE_SECRET=abc123def456", Kind::Secret, "abc123def456");
        one(r#"{"password": "correct-horse-battery"}"#, Kind::Secret, "correct-horse-battery");
        one(r#"{"apiKey": "abcd1234efgh"}"#, Kind::Secret, "abcd1234efgh");
        one("clientSecret: 'plainwords'", Kind::Secret, "plainwords");
        one("Authorization: Bearer abcdefghijklmnopqrstuvwxyz.0123", Kind::Secret, "abcdefghijklmnopqrstuvwxyz.0123");
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----";
        one(&format!("key:\n{pem}\n"), Kind::Secret, pem);
    }

    #[test]
    fn settings_that_are_not_secrets() {
        none("max_tokens: 4096");
        none("primary_key: id");
        none("API_KEY=${API_KEY}");
        none("token = getToken()");
        none("SECRET_KEY_BASE=ENV['X']");
        none(r#""password": "<your password>""#);
        none("auth: true");
        none("Co-Authored-By: Claude Haiku");
        none(r#""tokenizer": "cl100k_base""#);
        none("sort_key: created_at");
        none(r#""author": "Sundar""#);
        none(r#""auth": "Basic login flow for the admin page""#);
        none(r#"# DB_PASSWORD is set in the vault"#);
        none("last=$(date -u +%Y-%m-%dT%H:%M:%SZ)");
    }

    #[test]
    fn personal_data() {
        one("mail ram.thapa@example.com.np now", Kind::Email, "ram.thapa@example.com.np");
        one("call +977 9812345678", Kind::Phone, "+977 9812345678");
        one("mobile 9841234567.", Kind::Phone, "9841234567");
        one("card 4111 1111 1111 1111 exp", Kind::Card, "4111 1111 1111 1111");
        one("iban GB82 WEST 1234 5698 7654 32", Kind::Iban, "GB82 WEST 1234 5698 7654 32");
        one("ssn 123-45-6789", Kind::Ssn, "123-45-6789");
        one("from 8.8.8.8 today", Kind::Ip, "8.8.8.8");
        one("PAN No: 123456789", Kind::Id, "123456789");
        one("नागरिकता नं. २७-०१-७१-०५६७८", Kind::Id, "२७-०१-७१-०५६७८");
    }

    #[test]
    fn lookalikes_are_not_personal_data() {
        none("card 4111 1111 1111 1112"); // fails Luhn
        none("iban GB82 WEST 1234 5698 7654 33"); // bad checksum
        none("listen on 127.0.0.1 and 10.0.0.4 and 192.168.1.20");
        none("ssn 000-12-3456");
        none("version v1.2.3.4 and 1.2.3.4.5");
        none("@types/node and pkg@1.2.3");
    }

    #[test]
    fn audit_misses_now_found() {
        // every address in a list, not every other one
        let ips = found("dns 8.8.8.8 1.1.1.1 9.9.9.9; 52.1.2.3,52.1.2.4");
        assert_eq!(ips.iter().filter(|(k, _)| *k == Kind::Ip).count(), 5, "{ips:?}");
        // a card next to a CVV, an expiry or a quantity
        one("4111 1111 1111 1111 123", Kind::Card, "4111 1111 1111 1111");
        one("card 4111 1111 1111 1111 12/27", Kind::Card, "4111 1111 1111 1111");
        one("qty 2 4111 1111 1111 1111", Kind::Card, "4111 1111 1111 1111");
        one("4111111111111111", Kind::Card, "4111111111111111");
        // URL passwords with no user, or with a slash
        one("redis://:s3cr3tpass99@localhost:6379", Kind::Secret, "s3cr3tpass99");
        one("postgres://app:Xy7/kL9pQ2@db.internal:5432/app", Kind::Secret, "Xy7/kL9pQ2");
        // a .env or JSON written inside a JSON string (literal \n and \")
        one(r"DB_HOST=db\nDB_PASSWORD=hunter33xyz\nDB_PORT=5432", Kind::Secret, "hunter33xyz");
        one(r#"{\"password\":\"hunter44xyz\"}"#, Kind::Secret, "hunter44xyz");
        one(r"echo x\nexport API_TOKEN=abc123def456ghi", Kind::Secret, "abc123def456ghi");
    }

    #[test]
    fn audit_false_finds_gone() {
        none("PWD=/home/ram/project");
        none(r#"secret_name: "prod-db-credentials""#);
        none(r#"password_reset_url: "/accounts/reset""#);
        none("https://example.com:8080/users/@me");
        none("order 1234567812345670 shipped"); // Luhn-valid, but no card brand starts with 1
        none("id 9012345678901234");
        none("build 1.2.3.4.5 from 10.0.0.1");
    }

    #[test]
    fn a_long_table_of_numbers_is_scanned_quickly() {
        // 8 KB of single digits took over ten seconds before the card check was bounded; 40 KB, half an hour.
        let table = (0..4_000).map(|i| (i % 10).to_string()).collect::<Vec<_>>().join(" ");
        let t = std::time::Instant::now();
        scan(&table);
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "took {:?}", t.elapsed());
        // a card at the end of a long run is still found
        one(&format!("{} 4111 1111 1111 1111", &table[..2000]), Kind::Card, "4111 1111 1111 1111");
    }

    #[test]
    fn stand_ins_are_never_found_again() {
        none("hi [PERSON_1a2b3c4d], mail email_1a2b3c4d@parda.invalid");
    }
}

#[cfg(test)]
mod bench {
    /// `PARDA_BENCH_FILE=… cargo test --release bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn per_rule_timing() {
        let text = std::fs::read_to_string(std::env::var("PARDA_BENCH_FILE").unwrap()).unwrap();
        let t = std::time::Instant::now();
        super::rules();
        crate::names::scan("warm up Ram Thapa राम थापा");
        println!("compile {:?}", t.elapsed());
        for (i, r) in super::rules().iter().enumerate() {
            let t = std::time::Instant::now();
            let n = r.re.captures_iter(&text).count();
            println!("rule {i:2} {:>10?} {n} {}", t.elapsed(), &r.re.as_str()[..r.re.as_str().len().min(50)]);
        }
        let t = std::time::Instant::now();
        crate::names::scan(&text);
        println!("names {:?}", t.elapsed());
        let t = std::time::Instant::now();
        super::scan(&text);
        println!("scan total {:?}", t.elapsed());
    }
}

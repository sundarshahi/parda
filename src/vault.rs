//! Stand-ins and the vault that maps them back to real values.
//!
//! A stand-in is a keyed BLAKE3 hash of the value, so the same value always gets the same stand-in
//! (prompt caching keeps working; the AI can tell one person from two) and nobody without the key can
//! work backwards. The vault lives only in memory and is gone when parda stops.

use crate::detect::{self, Kind};
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

pub type Counts = BTreeMap<&'static str, u64>;

/// Above this many entries the vault is cleared; the next request refills what it needs.
const MAX_ENTRIES: usize = 100_000;
const EMAIL_DOMAIN: &str = "@parda.invalid";

pub fn token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"\[(?:SECRET|PERSON|PHONE|CARD|IBAN|SSN|IP|ID)_[0-9a-f]{8,16}\]|email_[0-9a-f]{8,16}@parda\.invalid",
        )
        .unwrap()
    })
}

pub struct Vault {
    key: [u8; 32],
    map: Mutex<HashMap<String, String>>,
}

impl Vault {
    pub fn new(key: [u8; 32]) -> Self {
        Vault { key, map: Mutex::new(HashMap::new()) }
    }

    /// The key lives in `dir/key` (mode 0600). Created from the OS random source on first use.
    pub fn load_or_create_key(dir: &Path) -> std::io::Result<[u8; 32]> {
        let path = dir.join("key");
        let mut key = [0u8; 32];
        if let Ok(b) = fs::read(&path) {
            if b.len() == 32 {
                key.copy_from_slice(&b);
                return Ok(key);
            }
        }
        fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
        fs::create_dir_all(dir)?;
        let tmp = dir.join("key.new");
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?
        };
        f.write_all(&key)?;
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(key)
    }

    fn stand_in(&self, kind: Kind, value: &str) -> String {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(kind.label().as_bytes());
        h.update(&[0]);
        h.update(value.as_bytes());
        let hex = h.finalize().to_hex();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_ENTRIES {
            map.clear();
        }
        for len in [8, 12, 16] {
            let t = match kind {
                Kind::Email => format!("email_{}{EMAIL_DOMAIN}", &hex[..len]),
                _ => format!("[{}_{}]", kind.label(), &hex[..len]),
            };
            match map.get(&t) {
                Some(v) if v != value => continue, // collision: try a longer stand-in
                Some(_) => return t,
                None => {
                    map.insert(t.clone(), value.to_string());
                    return t;
                }
            }
        }
        unreachable!("three BLAKE3 prefixes collided")
    }

    /// Replaces every find with its stand-in. `None` when there was nothing to mask.
    pub fn mask(&self, text: &str, counts: &mut Counts) -> Option<String> {
        let finds = detect::scan(text);
        if finds.is_empty() {
            return None;
        }
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for f in finds {
            out.push_str(&text[at..f.start]);
            out.push_str(&self.stand_in(f.kind, &text[f.start..f.end]));
            *counts.entry(f.kind.label()).or_default() += 1;
            at = f.end;
        }
        out.push_str(&text[at..]);
        Some(out)
    }

    /// Puts real values back. `json_escape` for text that is itself JSON source (tool-call arguments).
    /// Stand-ins parda didn't make are left as they are. `None` when nothing changed.
    pub fn restore(&self, text: &str, json_escape: bool, restored: &mut u64) -> Option<String> {
        if !text.contains('[') && !text.contains(EMAIL_DOMAIN) {
            return None;
        }
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let mut n = 0;
        let out = token_re().replace_all(text, |c: &regex::Captures| match map.get(&c[0]) {
            Some(v) => {
                n += 1;
                if json_escape {
                    let q = serde_json::to_string(v).unwrap_or_default();
                    q[1..q.len() - 1].to_string()
                } else {
                    v.clone()
                }
            }
            None => c[0].to_string(),
        });
        *restored += n;
        (n > 0).then(|| out.into_owned())
    }
}

/// How many bytes at the end of `text` could be the start of a stand-in that the next chunk completes.
pub fn pending_suffix(text: &str) -> usize {
    let from = text.len().saturating_sub(40);
    (from..text.len())
        .filter(|&i| text.is_char_boundary(i))
        .find(|&i| is_token_prefix(&text[i..]))
        .map_or(0, |i| text.len() - i)
}

fn is_token_prefix(s: &str) -> bool {
    fn hex_then(r: &str) -> (bool, &str) {
        let h = r.bytes().take_while(u8::is_ascii_hexdigit).count();
        (h <= 16, &r[h..])
    }
    if let Some(r) = s.strip_prefix('[') {
        let letters = r.bytes().take_while(u8::is_ascii_uppercase).count();
        let r = &r[letters..];
        if letters > 6 {
            return false;
        }
        let Some(r) = r.strip_prefix('_') else { return r.is_empty() };
        let (ok, rest) = hex_then(r);
        return ok && rest.is_empty() && !r.bytes().any(|b| b.is_ascii_uppercase());
    }
    if s.len() <= 6 {
        return "email_".starts_with(s);
    }
    let Some(r) = s.strip_prefix("email_") else { return false };
    let (ok, rest) = hex_then(r);
    ok && rest.len() < EMAIL_DOMAIN.len() && EMAIL_DOMAIN.starts_with(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_same_stand_in_and_round_trip() {
        let (a, b) = (Vault::new([7; 32]), Vault::new([7; 32]));
        let text = "Email ram@example.com, key sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let mut c = Counts::new();
        let ma = a.mask(text, &mut c).unwrap();
        assert_eq!(ma, b.mask(text, &mut Counts::new()).unwrap());
        assert!(!ma.contains("ram@example.com") && !ma.contains("sk-ant"));
        assert_eq!(c.get("EMAIL"), Some(&1));
        assert_eq!(c.get("SECRET"), Some(&1));
        let mut n = 0;
        assert_eq!(a.restore(&ma, false, &mut n).unwrap(), text);
        assert_eq!(n, 2);
        let other = Vault::new([8; 32]).mask(text, &mut Counts::new()).unwrap();
        assert_ne!(ma, other, "a different key gives different stand-ins");
    }

    #[test]
    fn unknown_stand_ins_are_left_alone() {
        let v = Vault::new([1; 32]);
        assert_eq!(v.restore("hi [PERSON_00000000]", false, &mut 0), None);
    }

    #[test]
    fn json_escaped_restore() {
        let v = Vault::new([1; 32]);
        let t = v.stand_in(Kind::Secret, r#"pa"ss\word1"#);
        assert_eq!(v.restore(&t, true, &mut 0).unwrap(), r#"pa\"ss\\word1"#);
    }

    #[test]
    fn collision_gets_a_longer_stand_in() {
        let v = Vault::new([2; 32]);
        let t = v.stand_in(Kind::Person, "Ram Thapa");
        v.map.lock().unwrap().insert(t.clone(), "someone else".into());
        let longer = v.stand_in(Kind::Person, "Ram Thapa");
        assert_eq!(longer.len(), t.len() + 4);
    }

    #[test]
    fn pending() {
        assert_eq!(pending_suffix("abc [PERS"), 5);
        assert_eq!(pending_suffix("abc [PERSON_1a2b"), 12);
        assert_eq!(pending_suffix("x email_12"), 8);
        assert_eq!(pending_suffix("x email_1a2b3c4d@parda.inv"), 24);
        assert_eq!(pending_suffix("done."), 0);
        assert_eq!(pending_suffix("[PERSON_1a2b3c4d]"), 0);
        assert_eq!(pending_suffix("arr[0]"), 0);
    }
}

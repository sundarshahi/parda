//! Walking JSON request and response bodies.
//!
//! Only string values are touched, never keys. Structural and signed fields are skipped in both
//! directions: changing a thinking block or its signature breaks the next request.

use crate::vault::{Counts, Vault};
use serde_json::Value;

/// Structural fields: never masked or restored, nor anything inside them — except inside a tool's
/// own input, where any key can hold user data.
const SKIP: [&str; 14] = [
    "model",
    "id",
    "type",
    "role",
    "encrypted_content",
    "tool_use_id",
    "tool_call_id",
    "call_id",
    "media_type",
    "stop_reason",
    "finish_reason",
    "object",
    "system_fingerprint",
    "item_id",
];

/// Fields that carry streamed text, where a stand-in can be split across two events.
pub const TEXT_KEYS: [&str; 6] = ["text", "partial_json", "arguments", "content", "delta", "refusal"];

/// Fields that tell streamed pieces of different blocks or calls apart; they become part of the path.
const POSITION_KEYS: [&str; 4] = ["index", "output_index", "content_index", "item_id"];

pub struct Leaf<'a> {
    /// Where the string sits, e.g. `@index=0/delta/text`.
    pub path: &'a str,
    pub key: &'a str,
    /// The string is itself JSON source (tool-call arguments): restored values must be escaped.
    pub json_source: bool,
}

pub fn visit(v: &mut Value, f: &mut dyn FnMut(&mut String, &Leaf)) {
    walk(v, &mut String::new(), "", "", false, f);
}

fn skipped(key: &str, parent_type: &str, in_tool_input: bool) -> bool {
    if in_tool_input {
        return false;
    }
    match key {
        // signed by the provider: changing a character breaks the next request
        "thinking" | "signature" => true,
        // base64 media and redacted thinking; a plain-text document's `data` is scanned
        "data" | "file_data" => matches!(parent_type, "base64" | "redacted_thinking") || key == "file_data",
        _ => SKIP.contains(&key),
    }
}

fn walk(
    v: &mut Value,
    path: &mut String,
    key: &str,
    parent_type: &str,
    in_tool_input: bool,
    f: &mut dyn FnMut(&mut String, &Leaf),
) {
    match v {
        Value::String(s) => {
            let json_source =
                key == "partial_json" || key == "arguments" || (key == "delta" && parent_type.contains("arguments"));
            f(s, &Leaf { path, key, json_source });
        }
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                let len = path.len();
                path.push_str(&format!("/{i}"));
                walk(x, path, key, parent_type, in_tool_input, f);
                path.truncate(len);
            }
        }
        Value::Object(m) => {
            let ty = m.get("type").and_then(Value::as_str).unwrap_or("").to_string();
            let len = path.len();
            if !in_tool_input {
                for p in POSITION_KEYS {
                    match m.get(p) {
                        Some(Value::Number(n)) => path.push_str(&format!("@{p}={n}")),
                        Some(Value::String(s)) => path.push_str(&format!("@{p}={s}")),
                        _ => {}
                    }
                }
            }
            for (k, x) in m.iter_mut() {
                if skipped(k, &ty, in_tool_input) {
                    continue;
                }
                let tool_input = in_tool_input || (k == "input" && ty.ends_with("tool_use"));
                let l = path.len();
                path.push('/');
                path.push_str(k);
                walk(x, path, k, &ty, tool_input, f);
                path.truncate(l);
            }
            path.truncate(len);
        }
        _ => {}
    }
}

/// An inline file or image (`data:image/png;base64,…`): not text, never scanned.
fn is_data_url(s: &str) -> bool {
    s.strip_prefix("data:").and_then(|r| r.split_once(";base64,")).is_some_and(|(mime, b64)| {
        mime.contains('/')
            && mime.bytes().all(|c| c.is_ascii_alphanumeric() || b"/.+-".contains(&c))
            && !b64.bytes().any(|c| c.is_ascii_whitespace())
    })
}

/// Told to the model whenever a request carries stand-ins. Without it, models treat stand-ins as
/// redactions and refuse to repeat them, which breaks agents.
pub const NOTE: &str = "Note from parda, a privacy tool on the user's device: some values in this conversation were \
replaced before leaving the device by placeholders such as [PERSON_…], [SECRET_…] or \
email_…@parda.invalid. Each stands for a real value the user already has, and the device puts the real value \
back into your reply. Treat them as the real values: use them exactly as written in replies, code, commands and tool \
calls. They are not redactions, and nothing needs protecting from the user.";

/// Adds `NOTE` where each API reads instructions: Anthropic `system`; OpenAI `instructions`
/// (Responses API) or a system message after the leading ones (Chat Completions).
fn add_note(v: &mut Value, anthropic: bool) {
    let Some(m) = v.as_object_mut() else { return };
    let append = |s: &mut String| {
        s.push_str("\n\n");
        s.push_str(NOTE);
    };
    if anthropic {
        match m.get_mut("system") {
            Some(Value::String(sys)) => append(sys),
            Some(Value::Array(blocks)) => blocks.push(serde_json::json!({"type": "text", "text": NOTE})),
            _ => {
                m.insert("system".into(), NOTE.into());
            }
        }
    } else if let Some(Value::String(i)) = m.get_mut("instructions") {
        append(i);
    } else if let Some(Value::Array(msgs)) = m.get_mut("messages") {
        let at = msgs.iter().take_while(|x| matches!(x["role"].as_str(), Some("system" | "developer"))).count();
        msgs.insert(at, serde_json::json!({"role": "system", "content": NOTE}));
    } else if m.contains_key("input") {
        m.insert("instructions".into(), NOTE.into());
    }
}

/// Masks every string in a JSON request body. Err when the body isn't JSON (it can't be scanned,
/// so it must not be sent).
pub fn mask_request(vault: &Vault, body: &[u8], counts: &mut Counts, anthropic: bool) -> Result<Vec<u8>, String> {
    let mut v: Value = serde_json::from_slice(body).map_err(|e| format!("the request body isn't JSON ({e})"))?;
    let mut changed = false;
    visit(&mut v, &mut |s, _| {
        if is_data_url(s) {
            return;
        }
        if let Some(m) = vault.mask(s, counts) {
            *s = m;
            changed = true;
        }
    });
    if changed {
        add_note(&mut v, anthropic);
    }
    // Always the re-written body, never the original bytes: a duplicate key that parsing dropped
    // must not ride along unscanned.
    serde_json::to_vec(&v).map_err(|e| e.to_string())
}

/// Restores every stand-in in a parsed response.
pub fn restore_value(vault: &Vault, v: &mut Value, restored: &mut u64) {
    visit(v, &mut |s, leaf| {
        if let Some(r) = vault.restore(s, leaf.json_source, restored) {
            *s = r;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vault() -> Vault {
        Vault::new([3; 32])
    }

    #[test]
    fn masks_text_but_not_structure_and_keeps_key_order() {
        let v = vault();
        let body = json!({"model": "m", "messages": [{"role": "user", "content": [
            {"type": "text", "text": "mail ram@example.com"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AKIAIOSFODNN7EXAMPLE"}}
        ]}], "max_tokens": 5});
        let out = mask_request(&v, &serde_json::to_vec(&body).unwrap(), &mut Counts::new(), true).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("ram@example.com"));
        assert!(s.contains("AKIAIOSFODNN7EXAMPLE"), "image data untouched");
        assert!(s.find("\"model\"").unwrap() < s.find("\"messages\"").unwrap());
        assert!(s.find("\"messages\"").unwrap() < s.find("\"max_tokens\"").unwrap());
    }

    #[test]
    fn thinking_and_signature_untouched() {
        let v = vault();
        let block =
            json!({"type": "thinking", "thinking": "Ram Thapa ram@example.com", "signature": "sig ram@example.com"});
        let body = json!({"messages": [{"role": "assistant", "content": [block.clone()]}]});
        let out = mask_request(&v, &serde_json::to_vec(&body).unwrap(), &mut Counts::new(), true).unwrap();
        let back: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(back["messages"][0]["content"][0], block);
    }

    #[test]
    fn tool_input_and_text_documents_are_scanned_whatever_their_keys() {
        let v = vault();
        let body = json!({"messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "write", "input": {"data": "AKIAIOSFODNN7EXAMPLE", "id": "ram@example.com", "type": "ram@example.com"}},
            {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "mail ram@example.com"}},
            {"type": "text", "text": "data: AKIAIOSFODNN7EXAMPLE"},
            {"type": "image", "source": {"type": "url", "url": "data:image/png;base64,QUtJQUlPU0ZPRE5ON0VYQU1QTEU="}}
        ]}]});
        let out =
            String::from_utf8(mask_request(&v, &serde_json::to_vec(&body).unwrap(), &mut Counts::new(), true).unwrap())
                .unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE") && !out.contains("ram@example.com"), "{out}");
        assert!(out.contains("\"toolu_1\"") && out.contains("QUtJQUlPU0ZPRE5ON0VYQU1QTEU="), "ids and base64 stay");
    }

    #[test]
    fn duplicate_keys_never_go_out_unscanned() {
        let out =
            mask_request(&vault(), br#"{"system":"AKIAIOSFODNN7EXAMPLE","system":"hi"}"#, &mut Counts::new(), true)
                .unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("AKIA"));
    }

    #[test]
    fn not_json_is_refused() {
        assert!(mask_request(&vault(), b"name=Ram Thapa", &mut Counts::new(), true).is_err());
    }

    #[test]
    fn the_model_is_told_about_stand_ins_only_when_there_are_some() {
        let v = vault();
        let mask = |b: Value, anthropic| {
            let out = mask_request(&v, &serde_json::to_vec(&b).unwrap(), &mut Counts::new(), anthropic).unwrap();
            serde_json::from_slice::<Value>(&out).unwrap()
        };
        let pii = "I am ram@example.com";
        let a = mask(
            json!({"system": [{"type": "text", "text": "You are X"}], "messages": [{"role": "user", "content": pii}]}),
            true,
        );
        assert_eq!(a["system"][1]["text"], NOTE);
        let a = mask(json!({"messages": [{"role": "user", "content": pii}]}), true);
        assert_eq!(a["system"], NOTE);
        let o =
            mask(json!({"messages": [{"role": "system", "content": "S"}, {"role": "user", "content": pii}]}), false);
        assert_eq!(o["messages"][1]["content"], NOTE);
        assert_eq!(o["messages"][2]["role"], "user");
        let r = mask(json!({"instructions": "Be brief", "input": pii}), false);
        assert_eq!(r["instructions"], format!("Be brief\n\n{NOTE}"));
        let clean = mask(json!({"system": "S", "messages": [{"role": "user", "content": "hello"}]}), true);
        assert_eq!(clean["system"], "S", "no stand-ins, no note");
    }

    #[test]
    fn restore_escapes_in_json_source_fields() {
        let v = vault();
        let m = v.mask(r"DB_PASSWORD=back\slash12", &mut Counts::new()).unwrap();
        let token = m.strip_prefix("DB_PASSWORD=").unwrap().to_string();
        let mut ev = json!({"type": "content_block_delta", "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": format!("{{\"cmd\": \"echo {token}\"}}")}});
        let mut n = 0;
        restore_value(&v, &mut ev, &mut n);
        let args: Value = serde_json::from_str(ev["delta"]["partial_json"].as_str().unwrap()).unwrap();
        assert_eq!(args["cmd"], r"echo back\slash12");
        assert_eq!(n, 1);
    }
}

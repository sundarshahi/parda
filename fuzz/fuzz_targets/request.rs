//! Any request body: valid JSON is never refused, the masked body is JSON of the same shape, and
//! restoring it gives the original back.
#![no_main]

use libfuzzer_sys::fuzz_target;
use parda_fuzz::body::{self, Api};
use parda_fuzz::detect;
use parda_fuzz::vault::{self, Counts, Vault};
use serde_json::Value;

/// Same shape and values. An inline text file (`data:text/…;base64,`) is masked inside its base64,
/// which a response never carries back, so it is only checked for staying a string.
fn same(original: &Value, back: &Value) -> bool {
    match (original, back) {
        (Value::String(a), Value::String(b)) => a == b || a.starts_with("data:"),
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y)),
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|((ka, x), (kb, y))| ka == kb && same(x, y))
        }
        _ => original == back,
    }
}

/// A value found in one message is gone from every message, also the ones scanned before it.
fn no_survivors(original: &mut Value, masked: &mut Value) {
    let unscanned = |s: &str, key: &str| s.starts_with("data:") || key == "file_data";
    let mut values: Vec<String> = Vec::new();
    body::visit(original, &mut |s, leaf| {
        if unscanned(s, leaf.key) {
            return;
        }
        if detect::secret_setting(leaf.key, s) && !vault::token_re().is_match(s) {
            values.push(s.clone());
        }
        values.extend(detect::scan(s).iter().map(|f| s[f.start..f.end].to_string()));
    });
    values.retain(|v| v.len() >= 4); // shorter values are not searched for on their own
    body::visit(masked, &mut |s, leaf| {
        if unscanned(s, leaf.key) {
            return;
        }
        let rest = vault::token_re().replace_all(s, "\u{0}");
        for v in &values {
            assert!(!rest.contains(v.as_str()), "{v:?} was found, and is still in {s:?}");
        }
    });
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, body)) = data.split_first() else { return };
    let api = [Api::Anthropic, Api::OpenAi, Api::Gemini][(flags % 3) as usize];
    let note = flags & 0x80 != 0;
    let v = Vault::new([5; 32]);
    let Ok(out) = body::mask_request(&v, body, &mut Counts::new(), api, note) else {
        assert!(serde_json::from_slice::<Value>(body).is_err(), "valid JSON was refused");
        return;
    };
    let mut back: Value = serde_json::from_slice(&out).expect("the masked body is not JSON");
    if note {
        return; // the note to the model adds a field on purpose
    }
    let mut original: Value = serde_json::from_slice(body).expect("accepted, so it parses");
    no_survivors(&mut original, &mut back.clone());
    body::restore_value(&v, &mut back, &mut 0);
    assert!(same(&original, &back), "restore did not give the request back:\n{original}\n{back}");
});

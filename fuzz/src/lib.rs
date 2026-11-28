//! Shared by the fuzz targets.
//!
//! ponytail: parda is a binary crate, so its modules are compiled here straight from `../src`
//! instead of splitting parda into a library. Split it if anything else ever needs to link it.
#![allow(dead_code)]

#[path = "../../src/body.rs"]
pub mod body;
#[path = "../../src/detect.rs"]
pub mod detect;
#[path = "../../src/names.rs"]
pub mod names;
#[path = "../../src/sse.rs"]
pub mod sse;
#[path = "../../src/vault.rs"]
pub mod vault;

use vault::{Counts, Vault};

/// A vault that already holds three values, and their stand-ins.
///
/// A stand-in is a keyed hash, which no fuzzer can guess. So the targets write the bytes 1, 2, 3 in
/// their input and `expand` swaps them for real stand-ins: one mutation puts a restorable value
/// anywhere, and chunking then splits it at every possible place.
pub fn seeded_vault() -> (Vault, [String; 3]) {
    let v = Vault::new([5; 32]);
    let mut c = Counts::new();
    let token = |text: &str, c: &mut Counts| v.mask(text, c).expect("the seed value is found");
    let person = token("Ram Bahadur Thapa", &mut c);
    let email = token("ram@example.com", &mut c);
    // A quote and a backslash: restoring into JSON source must escape them.
    let secret = v.mask_as(detect::Kind::Secret, r#"pa"ss\word1"#, &mut c);
    (v, [person, email, secret])
}

pub fn expand(text: &str, tokens: &[String; 3]) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{1}' => out.push_str(&tokens[0]),
            '\u{2}' => out.push_str(&tokens[1]),
            '\u{3}' => out.push_str(&tokens[2]),
            _ => out.push(ch),
        }
    }
    out
}

/// Chunk sizes for cutting a stream the way a network would: small, uneven, repeatable.
pub fn chunks(bytes: &[u8], seed: u8) -> Vec<&[u8]> {
    let mut state = seed as u32 | 1;
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let n = 1 + (state >> 16) as usize % 24;
        let end = (at + n).min(bytes.len());
        out.push(&bytes[at..end]);
        at = end;
    }
    out
}

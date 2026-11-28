//! Any byte stream: the answer is the same however the network cuts it up.
#![no_main]

use libfuzzer_sys::fuzz_target;
use parda_fuzz::sse::SseRestorer;
use parda_fuzz::{chunks, expand, seeded_vault};

fuzz_target!(|data: &[u8]| {
    let Some((&seed, rest)) = data.split_first() else { return };
    let (v, tokens) = seeded_vault();
    let stream = expand(&String::from_utf8_lossy(rest), &tokens).into_bytes();

    let run = |pieces: Vec<&[u8]>| {
        let mut r = SseRestorer::new(&v);
        let mut out = Vec::new();
        for p in pieces {
            out.extend(r.feed(p));
        }
        out.extend(r.finish());
        (out, r.restored)
    };
    let whole = run(vec![&stream]);
    let bytes = run(stream.chunks(1).collect());
    let uneven = run(chunks(&stream, seed));
    assert!(whole == bytes, "one byte at a time gave a different answer");
    assert!(whole == uneven, "uneven chunks gave a different answer");
});

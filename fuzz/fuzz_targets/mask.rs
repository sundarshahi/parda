//! Any text: finds are well-formed, and masking then restoring gives the text back.
#![no_main]

use libfuzzer_sys::fuzz_target;
use parda_fuzz::detect;
use parda_fuzz::vault::{Counts, Vault};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let finds = detect::scan(&text);
    let mut at = 0;
    for f in &finds {
        assert!(f.start >= at && f.start < f.end && f.end <= text.len(), "finds overlap or are empty: {finds:?}");
        assert!(text.is_char_boundary(f.start) && text.is_char_boundary(f.end), "a find splits a character");
        at = f.end;
    }
    let v = Vault::new([5; 32]);
    let Some(masked) = v.mask(&text, &mut Counts::new()) else {
        assert!(finds.is_empty(), "finds but nothing masked");
        return;
    };
    let back = v.restore(&masked, false, &mut 0);
    assert_eq!(back.as_deref(), Some(&*text), "mask then restore changed the text");
});

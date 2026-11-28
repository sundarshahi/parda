//! A value parda found is gone from the masked text everywhere, not only where it was found:
//! `DB_PASSWORD=x` and, lines later, `mysql -px`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use parda_fuzz::detect;
use parda_fuzz::vault::{self, Counts, Vault};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let v = Vault::new([5; 32]);
    let Some(masked) = v.mask(&text, &mut Counts::new()) else { return };
    // Stand-ins out of the way first: a short value can sit inside one's hex by chance.
    let rest = vault::token_re().replace_all(&masked, "\u{0}");
    for f in detect::scan(&text) {
        let value = &text[f.start..f.end];
        // Under four bytes a value is not searched for on its own (`MIN_KNOWN`).
        assert!(value.len() < 4 || !rest.contains(value), "{value:?} was found, and is still in {masked:?}");
    }
});

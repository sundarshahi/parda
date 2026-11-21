//! Person names in English (Latin script) and Nepali (Devanagari), from word lists in `data/`.
//!
//! Latin: a run of two or more Capitalised words is a name when it holds a known given name followed
//! by another word, or ends in a distinctive surname. Devanagari has no capitals, so a name is a known
//! surname with the word(s) before it, or a known given name followed by middle names / a surname.
//! Single words are never masked: too many false finds in code.

use crate::detect::{Find, Kind};
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

struct Lists {
    given: HashSet<&'static str>,
    surname: HashSet<&'static str>,
    given_ne: HashSet<&'static str>,
    surname_ne: HashSet<&'static str>,
    middle_ne: HashSet<&'static str>,
    stop: HashSet<&'static str>,
    latin_run: Regex,
    dev_word: Regex,
}

fn words(text: &'static str) -> HashSet<&'static str> {
    text.lines().filter(|l| !l.starts_with('#')).flat_map(str::split_whitespace).collect()
}

fn lists() -> &'static Lists {
    static L: OnceLock<Lists> = OnceLock::new();
    L.get_or_init(|| Lists {
        given: words(include_str!("../data/given.txt")),
        surname: words(include_str!("../data/surnames.txt")),
        given_ne: words(include_str!("../data/given_ne.txt")),
        surname_ne: words(include_str!("../data/surnames_ne.txt")),
        middle_ne: words(include_str!("../data/middle_ne.txt")),
        stop: words(include_str!("../data/stop.txt")),
        // No \b: a Unicode word boundary is ~100× slower; edges are checked in `scan` instead.
        latin_run: Regex::new(r"\p{Lu}\p{Ll}+(?: \p{Lu}\p{Ll}+)+").unwrap(),
        dev_word: Regex::new(r"[\p{Devanagari}\x{200C}\x{200D}]+").unwrap(),
    })
}

/// Nepali postpositions often written joined to the name: थापाले, शर्माको.
const SUFFIXES: [&str; 10] = ["ले", "लाई", "को", "का", "की", "बाट", "सँग", "मा", "ज्यू", "जी"];

fn is_surname_ne(l: &Lists, w: &str) -> bool {
    l.surname_ne.contains(w)
        || SUFFIXES.iter().any(|s| w.strip_suffix(s).is_some_and(|b| !b.is_empty() && l.surname_ne.contains(b)))
}

pub fn scan(text: &str) -> Vec<Find> {
    let l = lists();
    let mut out = Vec::new();
    let person = |start, end| Find { start, end, kind: Kind::Person };

    for run in l.latin_run.find_iter(text) {
        let word_char = |c: char| c.is_alphanumeric() || c == '_';
        if text[..run.start()].chars().next_back().is_some_and(word_char)
            || text[run.end()..].chars().next().is_some_and(word_char)
        {
            continue; // part of a longer word: McDonald, JohnDoe
        }
        let mut w = Vec::new();
        let mut at = run.start();
        for word in run.as_str().split(' ') {
            w.push((at, at + word.len(), word));
            at += word.len() + 1;
        }
        let n = w.len();
        let first_given = (0..n - 1).find(|&i| l.given.contains(w[i].2));
        let last_surname = (1..n).rev().find(|&k| l.surname.contains(w[k].2));
        let span = match (first_given, last_surname) {
            (Some(i), Some(k)) if i < k => Some((i.max(k.saturating_sub(3)), k)),
            (_, Some(k)) if !l.stop.contains(w[k - 1].2) => Some((k - 1, k)),
            (Some(i), _) => Some((i, (i + 3).min(n - 1))),
            _ => None,
        };
        if let Some((a, b)) = span {
            out.push(person(w[a].0, w[b].1));
        }
    }

    let w: Vec<_> = l.dev_word.find_iter(text).map(|m| (m.start(), m.end(), m.as_str())).collect();
    let joined = |a: usize, b: usize| text[w[a].1..w[b].0].chars().all(|c| c == ' ' || c == '\t');
    for k in 0..w.len() {
        if is_surname_ne(l, w[k].2) {
            let mut j = k;
            while j > 0 && joined(j - 1, j) && l.middle_ne.contains(w[j - 1].2) {
                j -= 1;
            }
            if j > 0 && joined(j - 1, j) && !l.stop.contains(w[j - 1].2) && !is_surname_ne(l, w[j - 1].2) {
                j -= 1;
            }
            if j < k {
                out.push(person(w[j].0, w[k].1));
            }
        }
        if l.given_ne.contains(w[k].2) {
            let mut e = k;
            while e + 1 < w.len() && joined(e, e + 1) && l.middle_ne.contains(w[e + 1].2) {
                e += 1;
            }
            if e + 1 < w.len() && joined(e, e + 1) && is_surname_ne(l, w[e + 1].2) {
                e += 1;
            }
            if e > k {
                out.push(person(w[k].0, w[e].1));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::detect::{Kind, scan};

    fn people(text: &str) -> Vec<&str> {
        scan(text).into_iter().filter(|f| f.kind == Kind::Person).map(|f| &text[f.start..f.end]).collect()
    }

    #[test]
    fn english_and_romanised_nepali_names() {
        assert_eq!(people("Contact Ram Bahadur Thapa today"), ["Ram Bahadur Thapa"]);
        assert_eq!(people("Dear John Doe,"), ["John Doe"]);
        assert_eq!(people("signed by Sundar Shahi"), ["Sundar Shahi"]);
        assert_eq!(people("Dr Nirvik Shrestha called"), ["Nirvik Shrestha"]);
        assert_eq!(people("Install Priya Patel's laptop"), ["Priya Patel"]);
    }

    #[test]
    fn devanagari_names() {
        assert_eq!(people("कर्मचारी राम बहादुर थापा आज आएनन्"), ["राम बहादुर थापा"]);
        assert_eq!(people("मेरो नाम सीता शर्मा हो"), ["सीता शर्मा"]);
        assert_eq!(people("हरि प्रसाद आए"), ["हरि प्रसाद"]);
        assert_eq!(people("निर्मला अधिकारीले भनिन्"), ["निर्मला अधिकारीले"]);
        assert_eq!(people("श्री थापा"), Vec::<&str>::new());
    }

    #[test]
    fn no_false_names_in_code_and_products() {
        for text in [
            "Claude Code reads CLAUDE.md",
            "Ruby on Rails and React Native",
            "const [state, setState] = useState()",
            "Visual Studio Code, Google Chrome, Amazon Web Services",
            "Pull Request Review Checklist",
            "Dev Server Started On Port",
            "Grace Hopper", // left out: Grace is also a word
            "Thapa",        // a single word is never a name
        ] {
            assert_eq!(people(text), Vec::<&str>::new(), "{text}");
        }
    }
}

//! Path-protection guard — ported from digger's `is_path_whitelisted` (lib/core/app_protection.sh).
//! The single most safety-critical primitive in the cleaner: given a path about to be deleted and
//! the user's whitelist, decide whether it (or a protected relative) must be spared.
//!
//! A path is protected when, after normalizing (collapse `//`, drop trailing `/`) both sides, it:
//!   - matches a pattern exactly, or matches a glob pattern, OR
//!   - is an ANCESTOR of a whitelisted path (deleting it would take a protected child with it), OR
//!   - is a DESCENDANT of a non-glob whitelisted directory.
//!
//! Glob support is bash's own: `*`, `?`, `[…]` bracket expressions (ranges, `!`/`^` negation, a
//! leading `]` as a literal, `\` escapes inside the brackets, and the `[[:class:]]` /`[[.coll.]]` /
//! `[[=equiv=]]` forms) plus `\` escapes outside them. It USED to be `*`/`?` only, with a comment
//! calling bracket expressions "effectively never used in path whitelists" — true of whitelists, but
//! this matcher is also what [`super::protect::should_protect_path`] matches the oracle's own
//! hardcoded patterns with, and several of THOSE are bracket expressions (`*[Ss]ystem[Ss]ettings*`,
//! `com.fabfilter.*.[0-9].plist`). Bash uses one pattern matcher everywhere, so this is one matcher
//! everywhere — and "everywhere" now includes a user's `~/.config/mole/whitelist`, so "no pattern in
//! the oracle's own tables uses that form" stopped being a reason to leave a form out. Every form
//! bash 3.2 accepts is implemented, and pinned against the real bash's verdicts by
//! `whitelist_match.golden.json`.
//!
//! Character classes are resolved in the **C locale**, because the shipping program forces it:
//! `bin/clean.sh:8-9` is `export LC_ALL=C` / `export LANG=C`. So `[[:alpha:]]` is ASCII letters and
//! does not match `é`, matching the bash this engine replaces rather than matching Unicode.
//!
//! ## Deliberate divergence: `?` and bracket members count CHARACTERS, where bash counts BYTES
//!
//! `LC_ALL=C` also makes bash 3.2 single-BYTE, so `é` is two units to it: `[[ é == ? ]]` is FALSE
//! and `[[ é == ?? ]]` is TRUE, and `[[ é == [é] ]]` is false because the bracket holds two bytes and
//! matches one. This matcher works on `char`, so it answers the opposite on all three. Making it
//! byte-oriented would mean re-typing every caller's `&str` as `&[u8]`, and the divergence is
//! reachable only through `?` or a bracket — `*` and literals are identical either way — so it is
//! left as a FAIL-SAFE rather than fixed, and the direction is checked rather than assumed:
//!
//!   * this matcher can only match MORE than bash on a non-ASCII path, never less;
//!   * at [`is_path_whitelisted`], [`super::protect`] and [`super::validate`], matching more means
//!     protecting more, which is the safe direction;
//!   * at [`super::plan::expand_pattern`] matching more would mean DELETING more, which is not — so
//!     the guard is that no clean target may contain a `?` or a `[` at all (none of the 247 does),
//!     pinned by `no_clean_target_uses_a_glob_where_chars_and_bytes_disagree` over there rather than
//!     left as a comment. A target that needed one would have to come with the byte rewrite.
//!
//! ## Behaviour change: a literal `[` in a whitelist entry no longer protects by prefix
//!
//! [`has_glob`] now reports `true` for a pattern containing `[`, as the oracle's own `case` does.
//! It previously did not, and that gap changed what a whitelist entry PROTECTS, not merely what it
//! matches: `is_path_whitelisted` suppresses its descendant rule for glob patterns, so an entry like
//! `~/Library/Caches/foo[1]` used to protect every path UNDER it and now protects only the entry
//! itself and its ancestors. That is what bash has always done; the old behaviour was the divergence.
//! A user with a bracketed literal path in their whitelist who wants the subtree spared should
//! whitelist the subtree without the brackets (or escape them: `foo\[1\]` still contains `[`, so it
//! is still a glob to bash — there is no way to write a bracketed path that keeps the descendant
//! rule, in this engine or in the oracle). See `has_glob` and [`parse_whitelist_config`].

/// Normalize exactly as the oracle does, in the oracle's order: strip ONE trailing `/`
/// (`${target_path%/}`), THEN collapse `//` to `/` until none remain. Order is observable and the
/// obvious "collapse then trim" is wrong twice:
///   * `/` normalizes to the EMPTY string, not to `/` — and the ancestor rule then fires for any
///     absolute pattern, so bash reports `/` as whitelisted. An engine that special-cased the empty
///     result back to `"/"` answered "not protected" for the root of the filesystem, which is the
///     single worst input to be wrong on.
///   * `/a//` normalizes to `/a/` — one trailing slash survives, because the strip happened before
///     the collapse produced a new one. Collapsing first yields `/a`, which then matches (and is an
///     ancestor of) things bash's `/a/` does not.
fn normalize(path: &str) -> String {
    let mut s = path.strip_suffix('/').unwrap_or(path).to_string();
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    s
}

/// Does this pattern contain any glob metacharacter? Mirrors the oracle's own test verbatim —
/// `case "$check_pattern" in *\** | *\?* | *\[*)` — which is a PRESENCE check, not a
/// "is this a well-formed bracket expression" check. A lone `[` counts as a glob to bash even
/// though it then matches as a literal, and that asymmetry is load-bearing: `is_path_whitelisted`
/// suppresses its descendant rule for glob patterns, so mis-answering here silently changes what a
/// whitelist entry protects. Counting `[` is a fidelity FIX with a user-visible consequence — see
/// the module header's "a literal `[` in a whitelist entry no longer protects by prefix".
pub(crate) fn has_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

/// Match `text` against a bash `[[ text == pattern ]]` glob: `*` (spans `/`, unlike a shell
/// pathname expansion), `?`, `[…]` bracket expressions, `\` escapes. `pub(crate)`: also used by
/// [`super::plan::expand_pattern`] to expand a single path COMPONENT against real directory entries,
/// and by [`super::protect`] for the oracle's `case`-arm and bundle-ID patterns — one matcher for
/// all three, because bash has one matcher for all three.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    glob_rec(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
    )
}

/// The C-locale character classes, i.e. the ones `bin/clean.sh:8-9`'s `LC_ALL=C` selects. ASCII only
/// and deliberately so: bash under `LC_ALL=C` says `[[:alpha:]]` does not match `é`, and this engine
/// exists to agree with that bash, not to be more Unicode-aware than it. The name list is bash's
/// own, which is POSIX's twelve plus the two extensions bash also accepts, `ascii` and `word`
/// (`[[ _ == [[:word:]] ]]` is true against the real thing; `[[ _ == [[:alnum:]] ]]` is not).
///
/// `None` is "bash does not know this name", which is NOT "a class that matches nothing": bash
/// stops treating the construct as a class at all and re-reads it as ordinary members — see
/// [`brackmatch`]'s `[:name:]` arm.
fn class_matches(name: &str, c: char) -> Option<bool> {
    Some(match name {
        "alnum" => c.is_ascii_alphanumeric(),
        "alpha" => c.is_ascii_alphabetic(),
        "ascii" => c.is_ascii(),
        "blank" => matches!(c, ' ' | '\t'),
        "cntrl" => c.is_ascii_control(),
        "digit" => c.is_ascii_digit(),
        "graph" => c.is_ascii_graphic(),
        "lower" => c.is_ascii_lowercase(),
        "print" => c.is_ascii() && !c.is_ascii_control(),
        "punct" => c.is_ascii_punctuation(),
        "space" => matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c'),
        "upper" => c.is_ascii_uppercase(),
        "word" => c.is_ascii_alphanumeric() || c == '_',
        "xdigit" => c.is_ascii_hexdigit(),
        _ => return None,
    })
}

/// bash's scan for the `:]` / `.]` that closes a `[:class:]` or `[.symbol.]`: the first `delim`
/// immediately followed by `]`, at or after `from` (which is the first character of the NAME, so
/// `[[::]]` finds its closer at once and yields the empty name). `None` when the pattern runs out
/// first — and the two callers do different things with that, see [`brackmatch`].
fn find_closer(p: &[char], from: usize, delim: char) -> Option<usize> {
    (from..p.len()).find(|&k| p[k] == delim && p.get(k + 1) == Some(&']'))
}

/// bash's `matched:` label: a member matched, so skip the REST of the bracket expression and report
/// the pattern index the caller resumes at.
///
/// `brcnt` counts `[:` / `[.` / `[=` openers, so a `[:class:]` sitting AFTER the member that matched
/// is skipped whole rather than ending the bracket at its `:]`. It also means an UNCLOSED one runs
/// the scan off the end of the pattern and loses a match that was already found — which is not a
/// transcription slip but bash's own observable behaviour: `[[ x == [x[:y] ]]` is FALSE even though
/// `x` is plainly the first member, because the `[:` with no `:]` leaves `brcnt` at 1 forever.
fn skip_rest(p: &[char], mut i: usize, negated: bool, test: char) -> Option<usize> {
    let mut brcnt = 1usize;
    while brcnt > 0 {
        let Some(c) = p.get(i).copied() else {
            return unterminated(test);
        };
        i += 1;
        if c == '[' && matches!(p.get(i), Some(':') | Some('.') | Some('=')) {
            brcnt += 1;
        } else if c == ']' {
            brcnt -= 1;
        } else if c == '\\' {
            if i >= p.len() {
                return None; // a plain no-match, NOT the `[`-literal fallback below
            }
            i += 1;
        }
    }
    if negated {
        None
    } else {
        Some(i)
    }
}

/// bash's answer to a bracket expression that ran off the end of the pattern:
/// `return ((test == '[') ? savep : (CHAR *)0)`. "Unterminated" does not mean "no match" — it means
/// the `[` is matched as an ORDINARY CHARACTER and the pattern resumes just after it (`savep`, which
/// is index 1 relative to the `[`). It can therefore only fire when the text character IS `[`, and
/// that asymmetry is the whole reason [`brackmatch`] cannot be a parse-then-test design: the same
/// pattern consumes a different amount of ITSELF depending on the character it is matched against.
fn unterminated(test: char) -> Option<usize> {
    if test == '[' {
        Some(1)
    } else {
        None
    }
}

/// bash 3.2's `BRACKMATCH` (`lib/glob/sm_loop.c`), ported as the state machine it is rather than as
/// an idealised bracket parser, because the two disagree and bash is the oracle. `p` starts AT the
/// `[`. `Some(i)` means "consume one character of TEXT and resume the pattern at `p[i]`"; `None` is
/// no match.
///
/// The three sub-expression forms each fail differently, and every one of these was read off
/// /bin/bash 3.2.57 rather than assumed:
///
///   * `[=x=]` is recognised only in that exact five-character shape, so `[[=ab=]]` and `[[=a]` are
///     not equivalence classes at all — their `[`, `=` and name characters are ordinary members, and
///     `[[ 'a]' == [[=ab=]] ]]` is TRUE.
///   * `[:name:]` needs both a `:]` and a name bash knows; without either it drops the `[` and
///     carries on from the `:`, so `[[:alpha]` is the member set `{:,a,l,p,h}` and does NOT match
///     `[`, and `[[:foo:]` matches `:` (the members run on through the `:]` to the real `]`).
///   * `[.sym.]` with no `.]` is unterminated instead, so `[[.a]` matches `[a` and `[.` — the `[` as
///     a literal, then the rest re-read as a plain bracket. A `[.sym.]` whose symbol is not exactly
///     one character is neither of those: it is a member that matches nothing, so `[[..]x]` still
///     matches `x`.
///
/// And the one that made this port necessary: after a NON-matching `[=x=]`, bash reads the next
/// character without testing it for the closing `]`. For `[[=a=]]` that eats the bracket's own
/// terminator, the scan runs off the end, and the unterminated path above turns the leading `[` into
/// a literal — so `[[ '[a]' == [[=a=]] ]]` is TRUE, and so is `[=]`, while the same pattern also
/// matches plain `a` by the ordinary route. Three matches from one one-character-looking bracket.
fn brackmatch(p: &[char], test: char) -> Option<usize> {
    let mut i = 1; // just past the `[` — bash's `savep`
    let negated = matches!(p.get(i), Some('!') | Some('^'));
    if negated {
        i += 1;
    }
    // bash reads the first member BEFORE entering its loop, which is exactly why a `]` in first
    // position is a literal member rather than the terminator: the terminator test lives at the
    // bottom of the loop, where the NEXT member is read.
    let mut c = p.get(i).copied();
    i += 1;

    loop {
        let Some(cc) = c else {
            return unterminated(test);
        };
        let (mut lo, mut hi) = (cc, cc);

        // `[=x=]` — a single-character equivalence class, which in the C locale is that character.
        if cc == '['
            && p.get(i) == Some(&'=')
            && p.get(i + 2) == Some(&'=')
            && p.get(i + 3) == Some(&']')
        {
            let equiv = p[i + 1];
            i += 4;
            if equiv == test {
                return skip_rest(p, i, negated, test);
            }
            c = p.get(i).copied();
            i += 1;
            if c.is_none() {
                return unterminated(test);
            }
            // No `]` test here, unlike every other advance in this function. That is bash 3.2's
            // asymmetry, not an omission — see this function's doc comment.
            continue;
        }

        // `[:name:]` — a character class. Acting on one needs BOTH a `:]` closer and a name bash
        // knows; failing either, it stops treating this as a class, DROPS the `[` and re-reads from
        // the `:` as an ordinary member. So `[[:alpha]` is the member set `{:,a,l,p,h}` — note the
        // `[` itself is gone, `[[ '[' == [[:alpha] ]]` is false — and `[[:foo:]` matches `:`,
        // because the run-on members carry through the `:]` to the real `]`.
        if cc == '[' && p.get(i) == Some(&':') {
            let class = find_closer(p, i + 1, ':').and_then(|close| {
                let name: String = p[i + 1..close].iter().collect();
                class_matches(&name, test).map(|hit| (hit, close))
            });
            let Some((hit, close)) = class else {
                c = p.get(i).copied();
                i += 1;
                continue;
            };
            i = close + 2;
            if hit {
                return skip_rest(p, i, negated, test);
            }
            c = p.get(i).copied();
            i += 1;
            match c {
                None => return unterminated(test),
                Some(']') => break,
                _ => continue,
            }
        }

        // `[.sym.]` — a collating symbol. In the C locale only a one-character symbol is defined; a
        // longer or empty one is a member that matches nothing (NOT an error), so `[[..]x]` still
        // matches `x`.
        if cc == '[' && p.get(i) == Some(&'.') {
            let Some(close) = find_closer(p, i + 1, '.') else {
                return unterminated(test);
            };
            let symbol = &p[i + 1..close];
            i = close + 2;
            if symbol == [test] {
                return skip_rest(p, i, negated, test);
            }
            c = p.get(i).copied();
            i += 1;
            match c {
                None => return unterminated(test),
                Some(']') => break,
                _ => continue,
            }
        }

        // `\` escapes the next character (`[\]]` is a literal `]`, `[\-]` a literal `-`). A `\` with
        // nothing after it is a plain no-match, not the `[`-literal fallback.
        if cc == '\\' {
            let escaped = p.get(i).copied()?;
            lo = escaped;
            hi = escaped;
            i += 1;
        }

        // `a-z` is a range; a `-` immediately before the `]` is an ordinary member, and a range whose
        // upper end runs off the pattern (`[a-`) kills the expression. The endpoint can itself be
        // escaped, so `[a-\c]` is the range `a`..`c`.
        if p.get(i) == Some(&'-') && p.get(i + 1) != Some(&']') {
            let mut end = p.get(i + 1).copied()?;
            i += 2;
            if end == '\\' {
                end = p.get(i).copied()?;
                i += 1;
            }
            hi = end;
        }

        if lo <= test && test <= hi {
            return skip_rest(p, i, negated, test);
        }

        c = p.get(i).copied();
        i += 1;
        if c == Some(']') {
            break;
        }
    }

    // Ran into the closing `]` with nothing matched. `i` is already past it, which is where a
    // NEGATED expression resumes.
    if negated {
        Some(i)
    } else {
        None
    }
}

fn glob_rec(p: &[char], t: &[char]) -> bool {
    match p.split_first() {
        None => t.is_empty(),
        Some(('*', rest)) => glob_rec(rest, t) || (!t.is_empty() && glob_rec(p, &t[1..])),
        Some(('?', rest)) => !t.is_empty() && glob_rec(rest, &t[1..]),
        Some(('[', _)) => {
            !t.is_empty()
                && match brackmatch(p, t[0]) {
                    // One character of text is consumed either way — including on the "the `[` was
                    // a literal after all" path, where `next` is 1 and the rest of the bracket is
                    // re-read from scratch as ordinary pattern.
                    Some(next) => glob_rec(&p[next..], &t[1..]),
                    None => false,
                }
        }
        Some(('\\', rest)) => match rest.split_first() {
            Some((c, after)) => !t.is_empty() && t[0] == *c && glob_rec(after, &t[1..]),
            // A trailing lone backslash matches NOTHING in bash — not even a literal backslash:
            // `[[ 'a\' == 'a'\ ]]` and `[[ 'a' == 'a'\ ]]` are both false, as is `[[ 'x\' == *\ ]]`.
            // (An earlier comment here claimed the opposite and the code implemented the claim.)
            None => false,
        },
        Some((c, rest)) => !t.is_empty() && t[0] == *c && glob_rec(rest, &t[1..]),
    }
}

/// True when `target` is protected by the whitelist and must not be cleaned. Empty target or empty
/// whitelist ⇒ not protected (nothing to match).
pub fn is_path_whitelisted(target: &str, patterns: &[&str]) -> bool {
    if target.is_empty() || patterns.is_empty() {
        return false;
    }
    let target = normalize(target);
    for pattern in patterns {
        let pattern = normalize(pattern);
        let globbed = has_glob(&pattern);

        // Exact, or glob match. The glob arm is NOT gated on `globbed`, because the oracle's is not
        // (`app_protection.sh:459-462` is `[[ … == "$check_pattern" ]] || [[ … == $check_pattern ]]`,
        // the second unquoted and unconditional) — and gating it lost protection. `has_glob` is a
        // presence test for `*`, `?` and `[` only, so a pattern whose ONLY metacharacter is a
        // backslash reports false and yet still matches as a glob: bash spares `…/Caches/mydir` for
        // a whitelist entry of `…/Caches/my\dir`, and an engine that skipped the glob arm here
        // deleted it. `globbed` still gates the DESCENDANT rule below, which is where the oracle
        // really does branch on it.
        if target == pattern || glob_match(&pattern, &target) {
            return true;
        }
        // Target is an ancestor of a whitelisted path (the pattern lives under target) — deleting
        // target would remove the protected descendant, so protect target too.
        if pattern.starts_with(&format!("{target}/")) {
            return true;
        }
        // Target is a descendant of a non-glob whitelisted directory.
        if !globbed && target.starts_with(&format!("{pattern}/")) {
            return true;
        }
    }
    false
}

/// The line filters `bin/clean.sh:60-113` applies to each whitelist line AFTER `~`/`$HOME`
/// expansion, in the oracle's order. Returns the reason bash would have pushed onto
/// `WHITELIST_WARNINGS`, or `None` when bash would keep the line.
///
/// The `case` list is transcribed verbatim from `bin/clean.sh:96-100` and matched with the same
/// matcher bash's `case` uses ([`glob_match`]), so `/System/*` really is "a glob whose `*` spans
/// `/`" rather than a hand-rolled prefix test that would disagree about `/System/a/b`.
const SYSTEM_PATH_ARMS: &[&str] = &[
    "/",
    "/System",
    "/System/*",
    "/bin",
    "/bin/*",
    "/sbin",
    "/sbin/*",
    "/usr/bin",
    "/usr/bin/*",
    "/usr/sbin",
    "/usr/sbin/*",
    "/etc",
    "/etc/*",
    "/var/db",
    "/var/db/*",
];

fn whitelist_line_rejection(line: &str) -> Option<&'static str> {
    if line.contains("..") {
        return Some("path traversal not allowed");
    }
    if line != FINDER_METADATA_SENTINEL {
        // bash's test is `=~ [[:cntrl:]]`, under `LC_ALL=C` — ASCII controls, not Unicode C1.
        if line.chars().any(|c| c.is_ascii_control()) {
            return Some("invalid path format (control character)");
        }
        if !line.starts_with('/') {
            return Some("must be an absolute path");
        }
    }
    if line.contains("//") {
        return Some("consecutive slashes");
    }
    if SYSTEM_PATH_ARMS.iter().any(|arm| glob_match(arm, line)) {
        return Some("protected system path");
    }
    None
}

/// Parse the user's clean-whitelist config the way `bin/clean.sh:60-113` does: one pattern per line,
/// leading/trailing whitespace trimmed, `#` comments and blank lines skipped, a leading `~` (and a
/// literal `$HOME`/`${HOME}`, as digger's own writer sometimes emits) expanded to `home`, then the
/// oracle's own line filters applied and exact duplicates dropped. Patterns that survive are handed
/// back as-is for [`is_path_whitelisted`] to match (exact/glob/ancestor/descendant) — this function
/// decides which lines EXIST, not what a surviving pattern protects.
///
/// An earlier revision skipped the filters, arguing that a line bash rejects "becomes, here, a
/// pattern that simply never matches: inert, not dangerous". That was wrong, and wrong in the
/// direction that silently disables the cleaner. A pattern does not have to MATCH anything to have
/// an effect — `is_path_whitelisted`'s ancestor rule protects any directory a whitelisted path lives
/// under. So `~/Library/Caches/../../..` matches nothing at all and still protects `~/Library/Caches`,
/// `~/Library` and `~` outright, while bash rejects the line with "Path traversal not allowed" and
/// cleans normally. A bare `/System` line is the same shape: bash rejects it, an unfiltered port
/// keeps it and then spares every path under `/System` via the descendant rule. Both are divergences
/// large enough to make the two programs delete different things, so the filters are ported.
///
/// Still NOT ported: surfacing the rejections. bash collects them into `WHITELIST_WARNINGS` and
/// prints them; this engine has no channel for that and inventing one is a separate change. The
/// rejected line is dropped either way, which is the part that decides what gets deleted.
///
/// Note for anyone chasing "my whitelist entry stopped working": an entry containing `[` is a GLOB
/// to bash even when it is a literal directory name, so it protects itself and its ancestors but no
/// longer its descendants — see the module header.
pub fn parse_whitelist_config(text: &str, home: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let expanded = match line.strip_prefix('~') {
            Some(rest) => format!("{home}{rest}"),
            None => line.to_string(),
        };
        let expanded = expanded.replace("$HOME", home).replace("${HOME}", home);
        if whitelist_line_rejection(&expanded).is_some() {
            continue;
        }
        if !out.contains(&expanded) {
            out.push(expanded);
        }
    }
    out
}

/// The sentinel digger's whitelist format uses to mean "don't touch Finder metadata" — the one entry
/// in [`DEFAULT_WHITELIST_PATTERNS`] that is not a path (`lib/core/base.sh:103`). Kept in the list
/// because dropping it would make this a doctored copy of the oracle's array rather than the array;
/// as a MATCH pattern it is inert (it is relative, so it can never match, be an ancestor of, or be a
/// descendant of any absolute candidate path). Its real effect in bash is to flip
/// `PROTECT_FINDER_METADATA`, which gates `clean_finder_metadata`'s `.DS_Store` tree sweep — and this
/// engine does not port that sweep at all (an unbounded home-wide recursive walk, a distinct
/// feature), so there is nothing here for the flag to gate.
pub const FINDER_METADATA_SENTINEL: &str = "FINDER_METADATA";

/// digger's built-in whitelist, `lib/core/base.sh:104-127`, with `$HOME` left as `~` for
/// [`resolve_whitelist`] to expand (bash expands it at array-definition time; same result).
///
/// `bin/clean.sh:60-113` loads these when `~/.config/mole/whitelist` does NOT exist — the state of
/// every fresh install. Three of them name paths this engine's target table sweeps outright:
/// `~/.m2/repository/*` (a Java developer's entire local Maven repository, routinely 5-20 GB, and
/// artifacts resolved from a private Nexus may not be re-resolvable at all), `~/.gradle/caches/*`,
/// and `ms-playwright`. Two more (`pypoetry/virtualenvs`, `JetBrains`) are reached through the
/// coarse `~/Library/Caches/*` sweep, where a "cache" directory is really a set of virtualenvs with
/// installed packages in it.
pub const DEFAULT_WHITELIST_PATTERNS: &[&str] = &[
    "~/Library/Caches/ms-playwright*",
    "~/.cache/huggingface*",
    "~/.m2/repository/*",
    "~/.gradle/caches/*",
    "~/.gradle/daemon/*",
    "~/.ollama/models/*",
    "~/Library/Caches/com.nssurge.surge-mac/*",
    "~/Library/Application Support/com.nssurge.surge-mac/*",
    "~/Library/Caches/org.R-project.R/R/renv/*",
    "~/Library/Caches/pypoetry/virtualenvs*",
    "~/Library/Caches/JetBrains*",
    "~/Library/Caches/com.jetbrains.toolbox*",
    "~/Library/Caches/tealdeer/tldr-pages",
    "~/Library/Application Support/JetBrains*",
    "~/Library/Caches/com.apple.finder",
    "~/Library/Mobile Documents*",
    // System-critical caches that affect macOS functionality and stability. The oracle's own
    // comment: "CRITICAL: Removing these will cause system search and UI issues".
    "~/Library/Caches/com.apple.FontRegistry*",
    "~/Library/Caches/com.apple.spotlight*",
    "~/Library/Caches/com.apple.Spotlight*",
    "~/Library/Caches/CloudKit*",
    FINDER_METADATA_SENTINEL,
];

/// Resolve the user's active clean-whitelist: parsed from `~/.config/mole/whitelist` — the file the
/// GUI's Review screen writes the user's UNTICKED paths into before a real clean run (a "whitelist
/// session", fenced and restored afterward) — when that file exists and is readable.
/// Env-overridable via `CLEAN_WHITELIST_CONFIG`, mirroring
/// [`crate::purge::resolve_search_paths`]'s `PURGE_PATHS_CONFIG` so tests don't need a real `$HOME`.
///
/// A MISSING or UNREADABLE file falls back to [`DEFAULT_WHITELIST_PATTERNS`], exactly as
/// `bin/clean.sh:60-113` does. That structure is an if/ELSE, so a file that EXISTS **replaces** the
/// defaults rather than merging with them — a user who writes a whitelist loses the built-ins, and
/// this matches that rather than being "helpfully" safer, because diverging in the safe direction is
/// still diverging. (Read the bash before changing this: the else-branch is a plain array
/// assignment, `WHITELIST_PATTERNS=("${DEFAULT_WHITELIST_PATTERNS[@]}")`, not an append.)
///
/// An earlier revision of this function returned an empty `Vec` for the missing-file case, with a
/// long comment arguing that porting the defaults would be unsafe: `is_path_whitelisted`'s ancestor
/// rule protects a directory that CONTAINS a whitelisted path, so a default like
/// `~/Library/Caches/ms-playwright*` would protect the whole `~/Library/Caches` target and neuter
/// the highest-value sweep `clean` has. That reasoning was correct about the mechanism and wrong
/// about the premise, and the premise moved: the target is now `~/Library/Caches/*`, expanded per
/// CHILD, so the ancestor rule is asked about `~/Library/Caches/com.apple.Safari`, never about
/// `~/Library/Caches` itself — which is exactly how the oracle has always asked it
/// (`lib/clean/user.sh:56` is `safe_clean ~/Library/Caches/* "User app cache"`, the shell expanding
/// the glob before `safe_clean` sees anything). Meanwhile the cost of the omission was real:
/// `~/.m2/repository/*` and `~/.gradle/caches/build-cache-*/*` are targets in this engine's table,
/// so a fresh install was queued to delete a developer's entire local Maven repository.
///
/// Env-overridable via `CLEAN_WHITELIST_CONFIG`, mirroring [`crate::purge::resolve_search_paths`]'s
/// `PURGE_PATHS_CONFIG` so tests don't need a real `$HOME`.
pub fn resolve_whitelist(home: &str) -> Vec<String> {
    let config = std::env::var("CLEAN_WHITELIST_CONFIG")
        .unwrap_or_else(|_| format!("{home}/.config/mole/whitelist"));
    resolve_whitelist_from(&config, home)
}

/// [`resolve_whitelist`] with the config path passed in rather than read out of process-global env.
///
/// This split exists for the tests, and it is a correctness fix rather than tidying. `set_var` /
/// `remove_var` on `CLEAN_WHITELIST_CONFIG` mutate state shared by every test THREAD in the process,
/// and `cargo test` runs them concurrently in one process. Three tests here set the var and three
/// depend on its value; the resulting interleavings made
/// `resolve_whitelist_falls_back_to_the_builtin_defaults_when_the_file_is_missing` fail about one run
/// in three, and — far worse — opened a window in which
/// `the_builtin_defaults_match_the_oracle_on_every_captured_path` read the DEVELOPER'S REAL
/// `~/.config/mole/whitelist`, because it passes the capture machine's `$HOME` and would find the
/// var freshly unset. A test must never read real user config, and a flaky safety gate is worse than
/// no gate because people rerun it until it is green. Every test below therefore names its config
/// path explicitly through this function; exactly one (`resolve_whitelist_reads_the_env_override`)
/// touches the env var at all, so there is no longer a pair of tests that can race.
pub(crate) fn resolve_whitelist_from(config: &str, home: &str) -> Vec<String> {
    match std::fs::read_to_string(config) {
        Ok(text) => parse_whitelist_config(&text, home),
        Err(_) => DEFAULT_WHITELIST_PATTERNS
            .iter()
            .map(|p| match p.strip_prefix('~') {
                Some(rest) => format!("{home}{rest}"),
                None => (*p).to_string(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_target_or_whitelist_is_not_protected() {
        assert!(!is_path_whitelisted("", &["/x"]));
        assert!(!is_path_whitelisted("/x", &[]));
    }

    #[test]
    fn exact_match_protects() {
        let wl = &["/Users/me/Documents", "/Users/me/keep.txt"];
        assert!(is_path_whitelisted("/Users/me/Documents", wl));
        assert!(is_path_whitelisted("/Users/me/keep.txt", wl));
        assert!(!is_path_whitelisted("/Users/me/Caches", wl));
    }

    #[test]
    fn normalization_makes_slashes_irrelevant() {
        // Trailing + doubled slashes on either side still match (the #724 case).
        assert!(is_path_whitelisted(
            "/Users/me/Documents/",
            &["/Users/me/Documents"]
        ));
        assert!(is_path_whitelisted(
            "/Users/me//Documents",
            &["/Users/me/Documents/"]
        ));
    }

    #[test]
    fn ancestor_of_a_protected_path_is_protected() {
        // Whitelisting a child protects the parent from being wiped wholesale.
        let wl = &["/Users/me/Library/Application Support/MyApp/keep"];
        assert!(is_path_whitelisted(
            "/Users/me/Library/Application Support/MyApp",
            wl
        ));
        assert!(is_path_whitelisted("/Users/me/Library", wl));
    }

    #[test]
    fn descendant_of_a_nonglob_dir_is_protected() {
        let wl = &["/Users/me/Projects"];
        assert!(is_path_whitelisted(
            "/Users/me/Projects/app/node_modules",
            wl
        ));
        assert!(!is_path_whitelisted("/Users/me/ProjectsOther", wl)); // prefix but not a child
    }

    #[test]
    fn glob_patterns_match() {
        let wl = &["/Users/me/Downloads/*", "/Users/me/*.key", "/tmp/build-?"];
        assert!(is_path_whitelisted("/Users/me/Downloads/keep.zip", wl));
        assert!(is_path_whitelisted("/Users/me/secret.key", wl));
        assert!(is_path_whitelisted("/tmp/build-3", wl));
        assert!(!is_path_whitelisted("/tmp/build-33", wl)); // ? is exactly one char
        assert!(!is_path_whitelisted("/Users/me/other.txt", wl));
    }

    #[test]
    fn glob_star_spans_slashes_like_bash_case() {
        // In bash `[[ x == pat ]]`, `*` matches across `/` too.
        assert!(is_path_whitelisted("/a/b/c/d", &["/a/*"]));
    }

    // -- parse_whitelist_config / resolve_whitelist (defect 1: the engine used to never load this
    // file at all, so the GUI's "unticked paths" protection session was silently disconnected).

    #[test]
    fn parse_skips_comments_and_blanks_and_expands_tilde_and_home() {
        let text = "\
# Mole Whitelist - Protected paths won't be deleted

  ~/keep-me/subdir
/abs/already/there
# another comment
$HOME/dollar-style
${HOME}/braced-style
";
        let got = parse_whitelist_config(text, "/Users/me");
        assert_eq!(
            got,
            vec![
                "/Users/me/keep-me/subdir",
                "/abs/already/there",
                "/Users/me/dollar-style",
                "/Users/me/braced-style",
            ]
        );
    }

    #[test]
    fn parse_globs_pass_through_untouched_for_is_path_whitelisted_to_match() {
        // This function's job is text -> pattern strings; matching (including globs) belongs to
        // is_path_whitelisted, which is already tested above. Just confirm the glob survives intact.
        let got = parse_whitelist_config("~/Library/Caches/ms-playwright*\n", "/Users/me");
        assert_eq!(got, vec!["/Users/me/Library/Caches/ms-playwright*"]);
        assert!(is_path_whitelisted(
            "/Users/me/Library/Caches/ms-playwright-chromium",
            &[got[0].as_str()]
        ));
    }

    #[test]
    fn parse_empty_text_is_an_empty_list_not_an_error() {
        assert!(parse_whitelist_config("", "/Users/me").is_empty());
        assert!(parse_whitelist_config("# only a comment\n\n", "/Users/me").is_empty());
    }

    /// A scratch directory unique to this TEST, not merely to this process. `std::process::id()`
    /// alone is shared by every test in the binary, so two tests that both used it were writing to
    /// sibling paths only because their hardcoded prefixes happened to differ.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow_wl_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolve_whitelist_reads_the_configured_file() {
        let dir = scratch("cfg");
        let cfg = dir.join("whitelist");
        std::fs::write(&cfg, "# comment\n\n~/keep-me\n/abs/path\n").unwrap();
        let got = resolve_whitelist_from(cfg.to_str().unwrap(), "/home/me");
        assert_eq!(got, vec!["/home/me/keep-me", "/abs/path"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ONLY test in this module that touches `CLEAN_WHITELIST_CONFIG`. Everything else names its
    /// config path through [`resolve_whitelist_from`], so this one has no peer to race with — which
    /// is the point: `set_var` is process-global and `cargo test` runs these as threads in ONE
    /// process, so any second test reading or writing this var reintroduces the flake.
    #[test]
    fn resolve_whitelist_reads_the_env_override() {
        let dir = scratch("env");
        let cfg = dir.join("whitelist");
        std::fs::write(&cfg, "/abs/from/env\n").unwrap();
        std::env::set_var("CLEAN_WHITELIST_CONFIG", &cfg);
        let got = resolve_whitelist("/home/me");
        std::env::remove_var("CLEAN_WHITELIST_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, vec!["/abs/from/env"]);
    }

    #[test]
    fn resolve_whitelist_falls_back_to_the_builtin_defaults_when_the_file_is_missing() {
        // The config path is passed in, not inherited from a shared env var, so this cannot observe
        // another test's mutation and cannot fall through to a real developer's own whitelist.
        let home = "/nonexistent-home-for-tests";
        let got = resolve_whitelist_from("/nonexistent/whitelist", home);
        assert_eq!(
            got.len(),
            DEFAULT_WHITELIST_PATTERNS.len(),
            "a missing config file means digger's built-in defaults, not an empty list"
        );
        assert!(
            got.iter().all(|p| !p.starts_with('~')),
            "~ must be expanded: {got:?}"
        );
        assert!(got.contains(&format!("{home}/.m2/repository/*")));
        // The sentinel is not a path and must survive verbatim rather than being home-prefixed.
        assert!(got.contains(&FINDER_METADATA_SENTINEL.to_string()));
    }

    #[test]
    fn a_whitelist_file_replaces_the_defaults_rather_than_merging_with_them() {
        // `bin/clean.sh:60` is an if/ELSE, not an append: a user who writes a whitelist file loses
        // the built-ins. Diverging in the SAFE direction (merging) would still be diverging, and the
        // oracle's `is_path_whitelisted` has no way to express "and also the defaults".
        let dir = scratch("replace");
        let cfg = dir.join("whitelist");
        std::fs::write(&cfg, "/only/this/one\n").unwrap();
        let got = resolve_whitelist_from(cfg.to_str().unwrap(), "/home/me");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, vec!["/only/this/one"]);
    }

    // -- the built-in defaults, against the oracle's own answers.
    //
    // This REPLACES a test called `default_pattern_would_protect_the_whole_caches_target`, which
    // asserted that `is_path_whitelisted("…/Library/Caches", ["…/Library/Caches/ms-playwright*"])`
    // is true and concluded from it that the defaults could not be ported. The assertion was true
    // and is still true (see `the_ancestor_rule_still_fires_on_the_parent…` below, which keeps it,
    // sourced from the oracle instead of hand-typed) — but the conclusion depended on the planner
    // emitting `~/Library/Caches` as a target, and it does not: the target is `~/Library/Caches/*`,
    // expanded per CHILD, which is exactly how the oracle has always asked the question
    // (`lib/clean/user.sh:56`). So the old test was green while testing a hypothesis about a path
    // this engine can no longer produce. It is deleted rather than patched, because the thing worth
    // pinning is not "what would happen to a target we don't emit" but "does the engine agree with
    // the oracle about every path we DO emit" — which is what these two do.

    const ORACLE_VERDICTS: &str = include_str!("protection.golden.json");

    /// `(path, default_whitelisted)` for every captured path, plus the `$HOME` the oracle's
    /// `$HOME`-anchored default patterns were captured under.
    fn oracle_whitelist_rows() -> (String, Vec<(String, bool)>) {
        let doc = crate::json::Json::parse(ORACLE_VERDICTS).expect("fixture parses");
        let home = doc
            .get("home")
            .and_then(|v| v.as_str())
            .expect("fixture records the capture home")
            .to_string();
        let rows = doc
            .get("paths")
            .and_then(|p| p.as_array())
            .expect("fixture has a paths array")
            .iter()
            .map(|row| {
                (
                    row.get("path")
                        .and_then(|v| v.as_str())
                        .unwrap()
                        .to_string(),
                    row.get("default_whitelisted")
                        .and_then(|v| v.as_bool())
                        .expect("row has a default-whitelist verdict"),
                )
            })
            .collect();
        (home, rows)
    }

    #[test]
    fn the_builtin_defaults_match_the_oracle_on_every_captured_path() {
        let (home, rows) = oracle_whitelist_rows();
        // Resolve through the real code path (missing file ⇒ defaults), against the captured home.
        // The missing path is passed explicitly: this test uses the CAPTURE machine's real `$HOME`,
        // so an env-var race that left `CLEAN_WHITELIST_CONFIG` unset here would have made it read
        // the developer's own `~/.config/mole/whitelist` and silently grade against that.
        let patterns = resolve_whitelist_from("/nonexistent/whitelist", &home);
        let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();

        let hits = rows.iter().filter(|(_, w)| *w).count();
        assert!(
            hits > 50,
            "the fixture must actually exercise the defaults, or this proves nothing ({hits} hits)"
        );
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(path, expected)| is_path_whitelisted(path, &refs) != *expected)
            .map(|(path, expected)| {
                format!("  {path}\n    oracle: {expected}, engine: {}", !expected)
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "{} of {} captured paths disagree with the oracle's DEFAULT_WHITELIST_PATTERNS:\n{}",
            wrong.len(),
            rows.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn the_ancestor_rule_still_fires_on_the_parent_but_not_on_the_children_we_actually_emit() {
        // The claim the deleted test got half-right, settled by the oracle rather than by argument:
        // `~/Library/Caches` IS protected by the defaults (the ancestor rule, because
        // `ms-playwright*` lives under it) — but every path the planner actually emits is a CHILD,
        // and an unrelated child is not protected.
        //
        // An earlier version of this test only LOOKED THE TWO VERDICTS UP IN THE FIXTURE, which
        // asserts what the oracle said and nothing about this engine — it passed unchanged against a
        // build with the ancestor rule deleted. The fixture lookup is kept, as the precondition it
        // actually is (these two paths must be in the corpus, and the oracle must say what the
        // comment claims), and the assertion that matters now runs `is_path_whitelisted` itself.
        let (home, rows) = oracle_whitelist_rows();
        let find = |p: &str| rows.iter().find(|(path, _)| path == p).map(|(_, v)| *v);
        let parent = format!("{home}/Library/Caches");
        let child = format!("{home}/Library/Caches/com.apple.Safari");
        assert_eq!(find(&parent), Some(true), "fixture coverage for {parent}");
        assert_eq!(find(&child), Some(false), "fixture coverage for {child}");

        let patterns = resolve_whitelist_from("/nonexistent/whitelist", &home);
        let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        assert!(
            is_path_whitelisted(&parent, &refs),
            "the ancestor rule must protect {parent}: a default lives under it"
        );
        assert!(
            !is_path_whitelisted(&child, &refs),
            "{child} is an unrelated child and no default protects it"
        );
    }

    // -- parse_whitelist_config's line filters, against `bin/clean.sh:60-113`.

    #[test]
    fn a_traversal_line_is_rejected_because_it_would_protect_every_ancestor() {
        // Not "inert": `~/Library/Caches/../../..` matches nothing, and the ANCESTOR rule would
        // still protect `~/Library/Caches`, `~/Library` and `~` outright — the whole user sweep.
        // bash rejects the line ("Path traversal not allowed"), so this must too.
        let got = parse_whitelist_config("~/Library/Caches/../../..\n/keep/me\n", "/Users/me");
        assert_eq!(got, vec!["/keep/me"]);
        assert!(!is_path_whitelisted(
            "/Users/me/Library/Caches",
            &["/keep/me"]
        ));
    }

    #[test]
    fn system_path_lines_are_rejected_with_the_oracles_own_case_arms() {
        // `bin/clean.sh:96-100`. Each of these would otherwise be a non-glob pattern whose
        // DESCENDANT rule spares everything beneath it.
        for line in [
            "/",
            "/System",
            "/System/Library/Caches",
            "/bin",
            "/bin/ls",
            "/etc",
            "/etc/hosts",
            "/usr/bin",
            "/usr/sbin/x",
            "/var/db",
            "/var/db/x",
            "/sbin",
        ] {
            assert!(
                parse_whitelist_config(&format!("{line}\n"), "/Users/me").is_empty(),
                "bash rejects {line:?} as a protected system path"
            );
        }
        // Neighbours that merely LOOK like the arms are kept — `/System/*` is a glob, not a prefix
        // test, and `/etc/*` does not cover `/etcetera`.
        assert_eq!(
            parse_whitelist_config("/Systemic\n/etcetera\n/usr/local/bin\n", "/Users/me"),
            vec!["/Systemic", "/etcetera", "/usr/local/bin"]
        );
    }

    #[test]
    fn relative_control_char_double_slash_and_duplicate_lines_are_dropped() {
        assert!(parse_whitelist_config("relative/path\n", "/Users/me").is_empty());
        assert!(parse_whitelist_config("/has\u{7}bell\n", "/Users/me").is_empty());
        assert!(parse_whitelist_config("/double//slash\n", "/Users/me").is_empty());
        // The sentinel is exempt from the absolute-path and control-char checks (and only those).
        assert_eq!(
            parse_whitelist_config("FINDER_METADATA\n", "/Users/me"),
            vec![FINDER_METADATA_SENTINEL]
        );
        // bash keeps the first occurrence only.
        assert_eq!(
            parse_whitelist_config("/a\n/b\n/a\n", "/Users/me"),
            vec!["/a", "/b"]
        );
    }

    // -- the matcher itself, against the real bash's verdicts.
    //
    // `protection.golden.json` above covers the paths this machine plans plus one instantiation of
    // every oracle pattern — which is the right corpus for the protection RAILS and the wrong one
    // for the MATCHER: not one of those paths reaches a bracket expression, so the entire
    // bracket/class/escape arm could be deleted and every test above would still pass. (Verified by
    // deleting it.) This fixture is the matcher's own: `(pattern, text)` pairs run through
    // `[[ text == pattern ]]` under /bin/bash, and `(pattern, target)` pairs run through the real
    // `is_path_whitelisted` with that single pattern as the whole whitelist.

    const ORACLE_MATCHES: &str = include_str!("whitelist_match.golden.json");

    fn oracle_match_doc() -> crate::json::Json {
        crate::json::Json::parse(ORACLE_MATCHES).expect("matcher fixture parses")
    }

    fn oracle_match_rows(key: &str, verdict: &str) -> Vec<(String, String, bool)> {
        let doc = oracle_match_doc();
        doc.get(key)
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("matcher fixture has a {key} array"))
            .iter()
            .map(|row| {
                let s = |k: &str| row.get(k).and_then(|v| v.as_str()).unwrap().to_string();
                (
                    s("pattern"),
                    s(if key == "globs" { "text" } else { "target" }),
                    row.get(verdict)
                        .and_then(|v| v.as_bool())
                        .expect("row carries the oracle's verdict"),
                )
            })
            .collect()
    }

    #[test]
    fn glob_match_agrees_with_bash_on_every_captured_pattern_and_text() {
        let rows = oracle_match_rows("globs", "match");
        assert!(
            rows.len() > 2000,
            "the matcher fixture is too small to prove anything ({} rows)",
            rows.len()
        );
        // Both verdicts must be well represented, or "agrees" could mean "always says false".
        let hits = rows.iter().filter(|(_, _, m)| *m).count();
        assert!(
            hits > 500 && rows.len() - hits > 500,
            "fixture is one-sided: {hits} matches, {} non-matches",
            rows.len() - hits
        );
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(p, t, m)| glob_match(p, t) != *m)
            .map(|(p, t, m)| format!("  pattern {p:?} text {t:?}: bash {m}, engine {}", !m))
            .collect();
        assert!(
            wrong.is_empty(),
            "{} of {} captured (pattern, text) pairs disagree with /bin/bash:\n{}",
            wrong.len(),
            rows.len(),
            wrong
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn bracket_expressions_and_classes_are_actually_exercised_by_the_fixture() {
        // The fixture is only worth anything if it reaches the arms the shipping corpus never does.
        // Without this, a re-capture that quietly dropped the exotic probes would leave the test
        // above green over nothing but `*`/`?`.
        let rows = oracle_match_rows("globs", "match");
        let with = |pred: fn(&str) -> bool| rows.iter().filter(|(p, _, _)| pred(p)).count();
        assert!(with(|p| p.contains('[')) > 200, "bracket coverage");
        assert!(with(|p| p.contains("[[:")) > 20, "POSIX class coverage");
        assert!(
            with(|p| p.contains("[[.") || p.contains("[[=")) > 4,
            "collating coverage"
        );
        assert!(with(|p| p.contains('\\')) > 20, "escape coverage");
        assert!(
            with(|p| p.contains('!') || p.contains('^')) > 10,
            "negation coverage"
        );
    }

    #[test]
    fn is_path_whitelisted_agrees_with_bash_on_every_captured_pattern_and_target() {
        // The end-to-end rail: normalization order, has_glob's `[`, and the ancestor/descendant
        // rules all ride on this, and none of them are visible through `glob_match` alone.
        let rows = oracle_match_rows("whitelist", "whitelisted");
        assert!(rows.len() > 400, "too few rows ({})", rows.len());
        let hits = rows.iter().filter(|(_, _, w)| *w).count();
        assert!(
            hits > 100 && rows.len() - hits > 100,
            "fixture is one-sided: {hits} protected, {} not",
            rows.len() - hits
        );
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(p, t, w)| is_path_whitelisted(t, &[p.as_str()]) != *w)
            .map(|(p, t, w)| format!("  pattern {p:?} target {t:?}: bash {w}, engine {}", !w))
            .collect();
        assert!(
            wrong.is_empty(),
            "{} of {} captured (pattern, target) pairs disagree with /bin/bash:\n{}",
            wrong.len(),
            rows.len(),
            wrong
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The oracle's verdict for one `(pattern, text)` pair of the `globs` half, or a panic saying the
    /// fixture does not cover it — so a re-capture that dropped a probe fails loudly here instead of
    /// leaving a test that asserts nothing.
    fn bash_glob(pattern: &str, text: &str) -> bool {
        oracle_match_rows("globs", "match")
            .into_iter()
            .find(|(p, t, _)| p == pattern && t == text)
            .map(|(_, _, m)| m)
            .unwrap_or_else(|| panic!("fixture must cover glob ({pattern:?}, {text:?})"))
    }

    /// The same for the `whitelist` half.
    fn bash_whitelisted(pattern: &str, target: &str) -> bool {
        oracle_match_rows("whitelist", "whitelisted")
            .into_iter()
            .find(|(p, t, _)| p == pattern && t == target)
            .map(|(_, _, w)| w)
            .unwrap_or_else(|| panic!("fixture must cover whitelist ({pattern:?}, {target:?})"))
    }

    #[test]
    fn an_equivalence_class_matches_three_texts_because_bash_drops_the_brackets_own_terminator() {
        // The last divergence in the corpus, and the reason `brackmatch` is a port of bash's state
        // machine rather than a bracket parser. `[[=a=]]` LOOKS like "the single character a". It is
        // that, plus two more: a non-matching `[=x=]` reads the next character without testing it for
        // the closing `]`, so for this pattern the terminator is eaten, the scan runs off the end,
        // and bash's unterminated-bracket rule turns the leading `[` into a literal — after which
        // `[=a=]` is re-read as an ordinary member set `{=,a}` followed by a literal `]`.
        //
        // Direction matters: the engine used to answer FALSE where bash answers true, i.e. it would
        // delete a path a user's whitelist spared.
        for (text, expect) in [
            ("a", true),
            ("[a]", true),
            ("[=]", true),
            ("[]", false),
            ("=", false),
            ("]", false),
            ("[", false),
        ] {
            assert_eq!(
                bash_glob("[[=a=]]", text),
                expect,
                "fixture drift for {text:?}"
            );
            assert_eq!(
                glob_match("[[=a=]]", text),
                expect,
                "glob_match(\"[[=a=]]\", {text:?})"
            );
        }
        // The neighbouring shapes, which fail three DIFFERENT ways — the reason one blanket
        // "equivalence class = one character" rule cannot be right for all of them.
        for (pattern, text) in [
            ("[[=a=]b]", "[a]"),    // a member after the class restores the `]` test
            ("[[=ab=]]", "a]"),     // not the `[=X=]` shape at all: ordinary members
            ("[[.a.]]", "[a]"),     // collating symbols DO test for the `]`
            ("[[:alpha:]]", "[a]"), // and so do classes
            ("[[:foo:]", ":"),      // an unknown class name drops the `[` and reads on
            ("[[.a]", "[a"),        // a collating symbol with no `.]` is unterminated instead
            ("[x[:y]", "x"),        // an unclosed `[:` strands brcnt and loses a found match
            ("[[:word:]]", "_"),    // bash's non-POSIX class names are real
        ] {
            assert_eq!(
                glob_match(pattern, text),
                bash_glob(pattern, text),
                "glob_match({pattern:?}, {text:?})"
            );
        }
    }

    #[test]
    fn a_backslash_only_whitelist_entry_glob_matches_even_though_has_glob_reports_false() {
        // `has_glob` is a presence test for `*`, `?` and `[` — the oracle's own `case` — so a pattern
        // whose only metacharacter is a backslash reports FALSE. The oracle's glob arm runs anyway
        // (`app_protection.sh:459-462`: an exact compare OR an UNQUOTED one, unconditionally), and an
        // engine that gated that arm on `has_glob` deleted a file bash spares. `globbed` still gates
        // the DESCENDANT rule, which is where the oracle really does branch on it.
        let pat = "/Users/me/Library/Caches/my\\dir";
        assert!(!has_glob(pat), "the premise: no `*`, `?` or `[` in {pat:?}");
        for target in [
            "/Users/me/Library/Caches/mydir",
            "/Users/me/Library/Caches/my\\dir",
            "/Users/me/Library/Caches",
            "/Users/me/Library/Caches/foo",
        ] {
            assert_eq!(
                is_path_whitelisted(target, &[pat]),
                bash_whitelisted(pat, target),
                "is_path_whitelisted({target:?}, [{pat:?}])"
            );
        }
        // Spelled out, because it is the one that was wrong: the escape makes the two spellings match.
        assert!(is_path_whitelisted(
            "/Users/me/Library/Caches/mydir",
            &[pat]
        ));
    }

    #[test]
    fn the_root_directory_is_whitelisted_by_any_absolute_pattern_as_bash_says() {
        // Reachable only through a caller that hands `/` in, and it is the safety primitive giving
        // the wrong answer at the worst possible input. bash normalizes `/` to the EMPTY string
        // (`${p%/}` strips the one and only slash) and the ancestor rule then fires for every
        // absolute pattern. The verdict is read from the fixture rather than argued for.
        let rows = oracle_match_rows("whitelist", "whitelisted");
        let bash = |pat: &str, target: &str| {
            rows.iter()
                .find(|(p, t, _)| p == pat && t == target)
                .map(|(_, _, w)| *w)
                .unwrap_or_else(|| panic!("fixture must cover ({pat:?}, {target:?})"))
        };
        for (pat, target) in [("/a/b", "/"), ("/", "/"), ("/a/b", "//"), ("relative", "/")] {
            assert_eq!(
                is_path_whitelisted(target, &[pat]),
                bash(pat, target),
                "is_path_whitelisted({target:?}, [{pat:?}])"
            );
        }
        // Spelled out, because it is the one that used to be wrong.
        assert!(is_path_whitelisted("/", &["/Users/me/keep"]));
    }

    #[test]
    fn a_bracketed_literal_whitelist_entry_no_longer_protects_its_descendants() {
        // The migration hazard of making `has_glob` count `[`, pinned to the oracle's own answers so
        // it cannot be argued away. `foo[1]` is a GLOB to bash, so the descendant rule is suppressed:
        // the entry protects itself and its ancestors, and NOT the subtree under it. The engine used
        // to protect the subtree, so a user with such an entry loses protection they had.
        let rows = oracle_match_rows("whitelist", "whitelisted");
        let bash = |pat: &str, target: &str| {
            rows.iter()
                .find(|(p, t, _)| p == pat && t == target)
                .map(|(_, _, w)| *w)
                .unwrap_or_else(|| panic!("fixture must cover ({pat:?}, {target:?})"))
        };
        let pat = "/Users/me/Library/Caches/foo[1]";
        for target in [
            "/Users/me/Library/Caches/foo[1]",
            "/Users/me/Library/Caches/foo[1]/inner",
            "/Users/me/Library/Caches",
            "/Users/me/Library/Caches/foo1",
        ] {
            assert_eq!(
                is_path_whitelisted(target, &[pat]),
                bash(pat, target),
                "is_path_whitelisted({target:?}, [{pat:?}])"
            );
        }
        // The behaviour change itself, stated: the entry, yes; its ancestor, yes; its child, no.
        assert!(is_path_whitelisted(
            "/Users/me/Library/Caches/foo[1]",
            &[pat]
        ));
        assert!(is_path_whitelisted("/Users/me/Library/Caches", &[pat]));
        assert!(!is_path_whitelisted(
            "/Users/me/Library/Caches/foo[1]/inner",
            &[pat]
        ));
        assert!(
            has_glob(pat),
            "a literal `[` makes this a glob, as bash's `case` says"
        );
    }
}

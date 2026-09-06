//! The stable Burrow envelope — the ONE JSON contract every Burrow surface speaks.
//!
//! Every conductor command emits a versioned envelope so agents and GUIs get a consistent
//! shape regardless of which engine served the request. Success embeds the engine's
//! already-valid JSON verbatim as `data`; non-JSON output is wrapped as `{"text": "..."}`;
//! failures carry `ok:false` + a classified `error {kind, message, platform}`. Zero-dep.
//! Ported verbatim from burrow-cli's `output.rs` — the first logic to live in the engine.

/// Wrap engine output in the Burrow envelope, auto-detecting JSON vs plain text.
pub fn wrap(cli_version: &str, command: &str, engine: &str, engine_out: &str) -> String {
    let t = engine_out.trim();
    if t.starts_with('{') || t.starts_with('[') {
        envelope(cli_version, command, engine, t)
    } else {
        envelope_text(cli_version, command, engine, t)
    }
}

/// Wrap already-valid engine JSON in the Burrow envelope (`data` = the JSON, verbatim).
/// `engine` names what actually served the request (burrow-engine | fclones | czkawka |
/// bcu | native) — the field was previously hardcoded to burrow-engine. Error envelopes
/// stay conductor-level (no engine attribution — failures often precede engine dispatch).
///
/// PRECONDITION, and it is not checked: `engine_json` must already BE valid JSON, because it is
/// spliced in verbatim. Hand it anything else and this emits a document that does not parse —
/// `dupes --apply` did exactly that, passing fclones's empty stdout and shipping `{…,"data":}`.
/// So: call this only with JSON THIS CRATE SERIALIZED. Anything originating outside the
/// process — a sidecar's stdout, a file's contents — goes through [`wrap`], which routes a
/// non-JSON payload to [`envelope_text`] instead.
///
/// The check deliberately lives at the call site rather than in here. Validating `engine_json`
/// would mean parsing every payload on the way out, and [`crate::json::Json::parse`] both
/// collects the input into a `Vec<char>` (4 bytes per byte of payload, on top of the value tree
/// it builds) and recurses without a depth limit — so `analyze` over a large or deep tree would
/// pay for a second full parse and could overflow the stack on output it had just built
/// successfully. Turning a working command into a crash is a poor trade for a precondition that
/// exactly one of this crate's call sites can violate.
pub fn envelope(cli_version: &str, command: &str, engine: &str, engine_json: &str) -> String {
    format!(
        "{{\"ok\":true,\"burrow_cli\":\"{}\",\"engine\":{},\"command\":\"{}\",\"data\":{}}}",
        cli_version,
        json_string(engine),
        command,
        engine_json.trim()
    )
}

/// Wrap arbitrary engine text (e.g. a bash dry-run report) as `data.text`.
pub fn envelope_text(cli_version: &str, command: &str, engine: &str, text: &str) -> String {
    format!(
        "{{\"ok\":true,\"burrow_cli\":\"{}\",\"engine\":{},\"command\":\"{}\",\"data\":{{\"text\":{}}}}}",
        cli_version,
        json_string(engine),
        command,
        json_string(text)
    )
}

/// Classify an error message into a coarse machine-readable `kind` so a GUI can
/// react (prompt for permissions vs show "unavailable here" vs a generic error).
/// Wording-based; folded in from Ltcc0's #5. A kind set at the error source would
/// be sturdier, but this covers the conductor's current error strings.
fn error_kind(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("os error 5")
        || lower.contains("elevation")
        || lower.contains("uac")
    {
        "permission_denied"
    } else if lower.contains("invalid czkawka output") || lower.contains("invalid engine output") {
        "invalid_output"
    } else if lower.contains("unsupported")
        || lower.contains("macos only")
        || lower.contains("windows only")
        || lower.contains("not available")
        || lower.contains("unavailable")
    {
        "unsupported"
    } else if lower.contains("not found")
        || lower.contains("could not locate")
        || lower.contains("does not exist")
        || lower.contains("is not a directory")
    {
        "not_found"
    } else if lower.contains("exited") {
        "process_failed"
    } else {
        "error"
    }
}

/// The structured error payload shared by the error/unsupported envelopes:
/// `{ "kind": …, "message": …, "platform": … }`.
fn error_object(kind: &str, message: &str, details: Option<&str>) -> String {
    match details {
        Some(details) => format!(
            "{{\"kind\":{},\"message\":{},\"platform\":\"{}\",\"details\":{}}}",
            json_string(kind),
            json_string(message),
            std::env::consts::OS,
            details
        ),
        None => format!(
            "{{\"kind\":{},\"message\":{},\"platform\":\"{}\"}}",
            json_string(kind),
            json_string(message),
            std::env::consts::OS
        ),
    }
}

/// Wrap a failure — top-level `ok:false` plus a structured `error {kind, message,
/// platform}` — so a GUI/agent parses ONE shape, branches on `ok`, and gets a
/// classified reason. (Combines #4's ok-branching with #5's error classification.)
pub fn error_envelope(cli_version: &str, command: &str, message: &str) -> String {
    format!(
        "{{\"ok\":false,\"burrow_cli\":\"{}\",\"engine\":\"burrow-engine\",\"command\":\"{}\",\"error\":{}}}",
        cli_version,
        command,
        error_object(error_kind(message), message, None)
    )
}

/// Wrap a failure and attach narrowly-scoped machine-readable process details. The details
/// live under `error` so all callers retain the same top-level success/failure contract.
pub fn error_envelope_with_details(
    cli_version: &str,
    command: &str,
    message: &str,
    details_json: &str,
) -> String {
    format!(
        "{{\"ok\":false,\"burrow_cli\":\"{}\",\"engine\":\"burrow-engine\",\"command\":\"{}\",\"error\":{}}}",
        cli_version,
        command,
        error_object(error_kind(message), message, Some(details_json))
    )
}

/// A platform-unsupported failure — a failure envelope whose error `kind` is
/// `unsupported`, plus the `feature` that's unavailable on this platform.
pub fn unsupported_envelope(
    cli_version: &str,
    command: &str,
    feature: &str,
    detail: &str,
) -> String {
    format!(
        "{{\"ok\":false,\"burrow_cli\":\"{}\",\"engine\":\"burrow-engine\",\"command\":\"{}\",\"error\":{},\"feature\":{}}}",
        cli_version,
        command,
        error_object("unsupported", detail, None),
        json_string(feature)
    )
}

use crate::json::escape as json_string;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;
    use std::collections::BTreeSet;

    /// The SUCCESS envelope, vendored verbatim from `envelope.golden.json` — the real shipping
    /// oracle's wrapper capture (see `envelope.golden.provenance.txt`). `data` is deliberately
    /// elided there ("<command-specific; judged separately per command>"): every command's
    /// payload is judged by that command's own golden, so what these two tests anchor is the
    /// WRAPPER key set `{ok, burrow_cli, engine, command, data}` — never `burrow_cli`/`engine`'s
    /// exact values, which the provenance says vary legitimately (oracle reports
    /// burrow_cli=0.0.1 where this engine reports 0.1.0; `engine` differs per command) and must
    /// not be pinned.
    const GOLDEN_SUCCESS: &str = include_str!("envelope.golden.json");

    /// The FAILURE envelope, vendored verbatim from `envelope-error.golden.json` — same
    /// provenance as `GOLDEN_SUCCESS` above. `{ok:false, burrow_cli, engine, command,
    /// error:{kind, message, platform}}`, with NO `data` key at all; that absence is part of the
    /// contract, per the provenance file.
    const GOLDEN_ERROR: &str = include_str!("envelope-error.golden.json");

    #[test]
    fn envelope_wraps_object() {
        let golden = Json::parse(GOLDEN_SUCCESS).expect("vendored golden must parse");
        let Json::Object(golden_map) = &golden else {
            panic!("golden root must be a JSON object");
        };
        let golden_keys: BTreeSet<&str> = golden_map.keys().map(String::as_str).collect();

        let e = envelope("0.0.0", "status", "burrow-engine", "{\"a\":1}");
        let parsed = Json::parse(&e).expect("envelope() must emit valid JSON");
        let Json::Object(parsed_map) = &parsed else {
            panic!("envelope() root must be a JSON object");
        };
        let parsed_keys: BTreeSet<&str> = parsed_map.keys().map(String::as_str).collect();
        assert_eq!(
            parsed_keys, golden_keys,
            "envelope()'s top-level keys must match the golden's exactly: {e}"
        );

        assert_eq!(
            parsed.get("ok"),
            golden.get("ok"),
            "success must carry ok:true, matching the golden: {e}"
        );
        assert_eq!(
            parsed.get("command").and_then(Json::as_str),
            Some("status"),
            "{e}"
        );
        // `data` embeds the engine's JSON verbatim — compared structurally (both sides parsed),
        // never as a hand-typed substring, so key order/whitespace can't produce a false failure.
        let expected_data = Json::parse("{\"a\":1}").unwrap();
        assert_eq!(
            parsed.get("data"),
            Some(&expected_data),
            "data must wrap the engine's JSON verbatim: {e}"
        );
    }

    #[test]
    fn wrap_detects_array() {
        assert!(wrap("0.0.0", "status", "burrow-engine", " [1,2] ").contains("\"data\":[1,2]"));
    }

    #[test]
    fn wrap_text_is_escaped_json() {
        let golden = Json::parse(GOLDEN_SUCCESS).expect("vendored golden must parse");
        let Json::Object(golden_map) = &golden else {
            panic!("golden root must be a JSON object");
        };
        let golden_keys: BTreeSet<&str> = golden_map.keys().map(String::as_str).collect();

        let original = "Would remove:\n\t\"~/Library/Caches\"";
        let e = wrap("0.0.0", "clean", "burrow-engine", original);
        let parsed = Json::parse(&e).expect("wrap() must emit valid JSON");
        let Json::Object(parsed_map) = &parsed else {
            panic!("wrap() root must be a JSON object");
        };
        let parsed_keys: BTreeSet<&str> = parsed_map.keys().map(String::as_str).collect();
        assert_eq!(
            parsed_keys, golden_keys,
            "the text-wrapping branch must still produce the golden's wrapper key set: {e}"
        );

        // The non-JSON branch's data shape is an object holding just the raw text (this module's
        // own contract, documented at the top of the file). Checked structurally, then
        // round-tripped through the engine's own JSON reader so control characters (newline,
        // tab, quote) are PROVEN correctly escaped by recovering the exact original string back
        // out, rather than grepping for a few escaped substrings the way a hand-typed shape
        // would.
        let data = parsed.get("data").expect("data must be present");
        let Json::Object(data_map) = data else {
            panic!("data must be an object");
        };
        assert_eq!(
            data_map.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["text"])
        );
        assert_eq!(
            data.get("text").and_then(Json::as_str),
            Some(original),
            "escaping must round-trip to the exact original text: {e}"
        );
    }

    #[test]
    fn json_string_escapes_control_chars() {
        assert_eq!(json_string("a\u{0001}b"), "\"a\\u0001b\"");
    }

    #[test]
    fn envelope_carries_ok_true_for_success() {
        // A GUI/agent branches on a single top-level `ok` for EVERY response; success must carry
        // ok:true (mirroring the failure envelope's ok:false) so the consumer parses one shape,
        // not two — checked against the golden's own `ok` rather than a hand-typed `true`.
        let golden = Json::parse(GOLDEN_SUCCESS).expect("vendored golden must parse");
        let e = envelope("0.0.0", "status", "burrow-engine", "{\"a\":1}");
        let parsed = Json::parse(&e).expect("envelope() must emit valid JSON");
        assert_eq!(
            parsed.get("ok"),
            golden.get("ok"),
            "success envelope must carry ok:true, matching the golden: {e}"
        );
    }

    #[test]
    fn error_envelope_is_a_classified_failure() {
        // Failure = top-level ok:false + a structured error {kind, message, platform}.
        let e = error_envelope("0.0.0", "clean", "engine \"mole\" not found");
        assert!(e.contains("\"ok\":false"), "got: {e}");
        assert!(e.contains("\"command\":\"clean\""), "got: {e}");
        assert!(e.contains("\"kind\":\"not_found\""), "classified: {e}");
        // the message is a valid, escaped JSON string nested under `error`.
        assert!(
            e.contains("\"message\":\"engine \\\"mole\\\" not found\""),
            "got: {e}"
        );
        assert!(e.contains("\"platform\":"), "got: {e}");
    }

    #[test]
    fn error_envelope_classifies_permission_denied() {
        let e = error_envelope("0.0.0", "status", "Access is denied. (os error 5)");
        assert!(e.contains("\"kind\":\"permission_denied\""), "got: {e}");
    }

    #[test]
    fn error_envelope_classifies_elevation_and_invalid_output() {
        let elevation =
            error_envelope("0.0.0", "win-uninstall", "The operation requires elevation");
        assert!(
            elevation.contains("\"kind\":\"permission_denied\""),
            "got: {elevation}"
        );
        let invalid = error_envelope(
            "0.0.0",
            "win-dupes",
            "invalid czkawka output: malformed JSON",
        );
        assert!(
            invalid.contains("\"kind\":\"invalid_output\""),
            "got: {invalid}"
        );
    }

    #[test]
    fn failure_details_are_nested_under_error() {
        // error_envelope_with_details's base shape (ok:false, error:{kind,message,platform}) is
        // the same as any other error envelope, anchored below to envelope-error.golden.json.
        // `details` itself has no oracle to anchor to: it's an ADDITIONAL key this path adds on
        // top of the golden's captured shape (RULEBOOK §4 RULE 1 — an extra key is never a
        // defect to fix by deletion), used only for specific commands like win-uninstall's BCU
        // exit-code reporting, which the captured installer-failure golden doesn't exercise. So
        // `details` is checked structurally instead: proving the caller's JSON round-trips
        // verbatim under `error.details`, not by hand-typing a fragment of the merged object.
        let golden = Json::parse(GOLDEN_ERROR).expect("vendored golden must parse");
        let golden_error = golden
            .get("error")
            .expect("golden must carry an error object");
        let Json::Object(golden_error_map) = golden_error else {
            panic!("golden.error must be an object");
        };

        let details_json =
            r#"{"program":"BCU-console.exe","args":["uninstall","Foo"],"exit_code":5}"#;
        let e = error_envelope_with_details(
            "0.0.0",
            "win-uninstall",
            "BCU exited 5: Access is denied",
            details_json,
        );
        let parsed = Json::parse(&e).expect("error_envelope_with_details must emit valid JSON");
        assert_eq!(parsed.get("ok"), golden.get("ok"), "{e}");

        let error = parsed.get("error").expect("error must be present");
        let Json::Object(error_map) = error else {
            panic!("error must be an object");
        };
        // Iterate the golden's OWN error keys rather than typing "kind"/"message"/"platform" by
        // hand — proves the base shape survived even though this path adds `details` on top.
        for key in golden_error_map.keys() {
            assert!(
                error_map.contains_key(key),
                "error must still carry the golden's {key}: {e}"
            );
        }
        assert_eq!(
            error.get("kind").and_then(Json::as_str),
            Some("permission_denied"),
            "{e}"
        );

        let expected_details = Json::parse(details_json).unwrap();
        assert_eq!(
            error.get("details"),
            Some(&expected_details),
            "details must nest under error, verbatim: {e}"
        );
    }

    #[test]
    fn unsupported_envelope_is_a_failure_not_success() {
        // Regression: a platform-unsupported response must be top-level ok:false
        // (a GUI branches on `ok`), with error kind `unsupported` + the feature.
        let e = unsupported_envelope("0.0.0", "dupes", "dupes apply", "not on Windows");
        assert!(e.contains("\"ok\":false"), "must be a failure: {e}");
        assert!(e.contains("\"kind\":\"unsupported\""), "got: {e}");
        assert!(e.contains("\"feature\":\"dupes apply\""), "got: {e}");
        assert!(e.contains("\"command\":\"dupes\""), "got: {e}");
        assert!(e.contains("\"message\":\"not on Windows\""), "got: {e}");
    }
}

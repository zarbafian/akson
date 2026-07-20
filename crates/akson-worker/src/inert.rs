//! Inert-source checks for rendered artifacts (design §20.4, §19 Phase-1 gate).
//!
//! An artifact a worker returns may be *rendered* by the requester — an SVG opened
//! in a browser, Markdown/HTML shown in a viewer, a Mermaid/Graphviz diagram drawn
//! client-side. Those formats can carry active content (scripts, event handlers,
//! external fetches) that would execute or phone home on view. Such an artifact is
//! rejected before it is delivered; formats that are pure data (JSON, plain text)
//! are inert by construction and pass.
//!
//! This is a conservative denylist over the raw bytes: it errs toward rejecting a
//! borderline artifact rather than delivering something that might execute.

/// Why an artifact's source is not inert.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("artifact of type {media_type:?} is not inert: {reason}")]
pub struct NotInert {
    pub media_type: String,
    pub reason: &'static str,
}

/// Whether `media_type` names a format that is rendered as markup/diagram (and so
/// must be checked for active content). Anything else is treated as inert data.
fn is_renderable(media_type: &str) -> bool {
    // Case-insensitively: `Image/SVG+XML` renders exactly like `image/svg+xml`, so a
    // case-variant type must not slip past as "inert data".
    let m = media_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        m.as_str(),
        "image/svg+xml"
            | "text/html"
            | "application/xhtml+xml"
            | "text/markdown"
            | "text/x-markdown"
            | "text/vnd.mermaid"
            | "text/vnd.graphviz"
            | "text/vnd.graphviz+dot"
    )
}

/// Checks that an artifact is inert for its media type (design §20.4). Renderable
/// formats are scanned for active content; data formats pass unconditionally.
pub fn check_inert(media_type: &str, bytes: &[u8]) -> Result<(), NotInert> {
    if !is_renderable(media_type) {
        return Ok(());
    }
    let reject = |reason| {
        Err(NotInert {
            media_type: media_type.to_owned(),
            reason,
        })
    };

    // A renderable text artifact is valid UTF-8 with no NUL bytes. Reject anything
    // else: a UTF-16/UTF-32 (or NUL-padded) payload hides `<script`/`javascript:`
    // behind NUL bytes here, yet a browser decodes and executes it. Failing closed
    // is safe — legitimate SVG/HTML/Markdown/Graphviz is clean UTF-8.
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return reject("is not clean UTF-8 text (may hide active content)");
    }

    // Work on a lowercased copy so matches are case-insensitive (bytes are valid
    // UTF-8 per the guard above), with numeric HTML character references decoded
    // first: a browser decodes `java&#x73;cript:` to `javascript:` and `&#x3c;script`
    // to `<script`, so scanning only the raw bytes misses the very payloads this
    // check exists to catch (codex review). Decode `&#dd;`/`&#xhh;` before scanning.
    let text = decode_numeric_entities(&String::from_utf8_lossy(bytes)).to_ascii_lowercase();

    // Active markup / embedding.
    for token in [
        "<script",
        "<iframe",
        "<object",
        "<embed",
        "<foreignobject",
        "<applet",
        "<meta http-equiv",
        "<!entity",
        "<!doctype",
        "<?xml-stylesheet",
    ] {
        if text.contains(token) {
            return reject("contains active or embedding markup");
        }
    }

    // Script URIs (in links, animations, xlink:href, CSS url()).
    for token in ["javascript:", "data:text/html", "vbscript:"] {
        if text.contains(token) {
            return reject("contains a script or html data URI");
        }
    }

    // Inline event handlers: an `on<letters>=` attribute. Scanned generically so an
    // obscure handler (onanimationstart, onbegin, …) is caught, not just a fixed
    // list.
    if has_event_handler(&text) {
        return reject("contains an inline event handler");
    }

    // External references — an SVG/HTML/Graphviz artifact that fetches over the
    // network on render: `href`/`src`, CSS `url(...)`, or a Graphviz `URL="..."`
    // attribute — pointing at an absolute or protocol-relative URL.
    if references_external_url(&text) {
        return reject("references an external URL");
    }

    Ok(())
}

/// Decodes numeric HTML character references — `&#123;` (decimal) and `&#x1f;`
/// (hex) — to their characters, leaving everything else (named entities, stray
/// text) untouched. Enough to defeat the common obfuscation of a dangerous token
/// like `javascript:` or `<script` behind numeric references; a browser decodes
/// these before acting on the markup, so the inert scan must too. A malformed or
/// out-of-range reference is left literal (still harmless to the scan).
fn decode_numeric_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' && i + 2 < bytes.len() && bytes[i + 1] == b'#' {
            let (radix, start) = if matches!(bytes[i + 2], b'x' | b'X') {
                (16, i + 3)
            } else {
                (10, i + 2)
            };
            let mut j = start;
            while j < bytes.len() && bytes[j] != b';' {
                j += 1;
            }
            if j < bytes.len() && j > start {
                if let Some(ch) = u32::from_str_radix(&text[start..j], radix)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(ch);
                    i = j + 1; // skip past the ';'
                    continue;
                }
            }
        }
        // Not a decodable reference — copy this byte's char through.
        let ch = text[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Whether `text` (already lowercased) carries an `href`/`src`/`url` reference whose
/// target is an absolute (`http://`, `https://`) or protocol-relative (`//`) URL.
///
/// `href`/`src` are attribute names; `url` is matched only as a CSS function (`url(`)
/// or an attribute assignment (`url=`, as Graphviz emits for `URL="http://…"`), and
/// only at a token boundary — so a plain mention of a URL in prose ("see url
/// https://… for details") is not mistaken for a fetched reference.
fn references_external_url(text: &str) -> bool {
    let b = text.as_bytes();
    // `srcset` before `src`: an `<img srcset="https://…">` fetches on render just as
    // `src` does, and the plain `src` scan would otherwise stop at the "set" and
    // miss the URL (codex review).
    for anchor in ["href", "srcset", "src", "url"] {
        let mut from = 0;
        while let Some(pos) = text[from..].find(anchor) {
            let at = from + pos;
            let after = at + anchor.len();
            from = at + 1;
            if anchor == "url" {
                // Require a boundary before, and `=` or `(` (after optional space)
                // after; otherwise it is a bare word, not a reference.
                let boundary = at == 0 || !b[at - 1].is_ascii_alphanumeric();
                let mut k = after;
                while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | b'\x0c') {
                    k += 1;
                }
                if !boundary || k >= b.len() || !matches!(b[k], b'=' | b'(') {
                    continue;
                }
            }
            // Skip the `=`/`(`, any quote, and whitespace, then look at the target.
            let target = text[after..].trim_start_matches(['=', '"', '\'', '(', ' ', '\t']);
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("//")
            {
                return true;
            }
        }
    }
    false
}

/// Whether `text` (already lowercased) contains an inline event handler: a run
/// `on<letters>` immediately followed by optional whitespace and `=`, where the
/// `on` starts an attribute (preceded by whitespace, `<`, `/`, or a quote).
fn has_event_handler(text: &str) -> bool {
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find("on") {
        let at = i + pos;
        let boundary = at == 0
            || matches!(
                b[at - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'<' | b'/' | b'"' | b'\''
            );
        if boundary {
            let mut j = at + 2;
            while j < b.len() && b[j].is_ascii_lowercase() {
                j += 1;
            }
            if j > at + 2 {
                // Skip whitespace, then require '='.
                let mut k = j;
                while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | b'\x0c') {
                    k += 1;
                }
                if k < b.len() && b[k] == b'=' {
                    return true;
                }
            }
        }
        i = at + 2;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_formats_are_inert() {
        assert!(check_inert("application/sarif+json", b"{\"runs\":[]}").is_ok());
        assert!(check_inert("text/plain", b"onclick= not really markup").is_ok());
        assert!(check_inert("application/json", b"{\"onload\":\"x\"}").is_ok());
    }

    #[test]
    fn a_clean_svg_passes() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10" fill="red"/><text>ok</text></svg>"#;
        // The xmlns is a namespace URI, not a fetched reference (it is an attribute
        // value with no href/src/url anchor) — still inert.
        assert!(check_inert("image/svg+xml", svg).is_ok());
    }

    #[test]
    fn svg_with_a_script_is_rejected() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        assert!(check_inert("image/svg+xml", svg).is_err());
    }

    #[test]
    fn svg_with_an_event_handler_is_rejected() {
        let svg = br#"<svg><rect onload="steal()" /></svg>"#;
        assert!(check_inert("image/svg+xml", svg).is_err());
        // Uppercase too.
        assert!(check_inert("image/svg+xml", b"<svg><rect ONCLICK=\"x\"/></svg>").is_err());
    }

    #[test]
    fn svg_with_an_external_image_is_rejected() {
        let svg = br#"<svg><image href="https://evil.example/track.png"/></svg>"#;
        assert!(check_inert("image/svg+xml", svg).is_err());
        // Protocol-relative too.
        assert!(check_inert("image/svg+xml", b"<svg><image href=\"//evil/x\"/></svg>").is_err());
    }

    #[test]
    fn markdown_with_a_javascript_link_or_script_is_rejected() {
        assert!(check_inert("text/markdown", b"[click](javascript:alert(1))").is_err());
        assert!(check_inert("text/markdown", b"# ok\n<script>x</script>\n").is_err());
    }

    #[test]
    fn clean_markdown_passes() {
        let md = b"# Findings\n\n- line 1 looks correct\n- see [docs](/local/path)\n";
        assert!(check_inert("text/markdown", md).is_ok());
    }

    #[test]
    fn a_doctype_or_entity_in_svg_is_rejected() {
        let xxe = br#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "y">]><svg/>"#;
        assert!(check_inert("image/svg+xml", xxe).is_err());
    }

    #[test]
    fn a_word_containing_on_is_not_a_false_positive() {
        // "one", "only", "front" contain "on" but are not handlers.
        let md = b"# Notes\nonly one concern on the frontend; done.\n";
        assert!(check_inert("text/markdown", md).is_ok());
    }

    #[test]
    fn a_graphviz_url_attribute_to_an_external_link_is_rejected() {
        // Graphviz renders a node's URL="…" as a clickable external link; a remote
        // target would phone home on click. Both quote styles and a space around `=`.
        let dot = br#"digraph { a [label="x" URL="https://evil.example/track"]; }"#;
        assert!(check_inert("text/vnd.graphviz", dot).is_err());
        assert!(check_inert(
            "text/vnd.graphviz+dot",
            b"digraph{ n[url = \"http://evil/x\"] }"
        )
        .is_err());
    }

    #[test]
    fn a_css_url_function_to_an_external_resource_is_rejected() {
        let svg = br#"<svg><rect style="fill:url(https://evil.example/p.png)"/></svg>"#;
        assert!(check_inert("image/svg+xml", svg).is_err());
    }

    #[test]
    fn a_clean_graphviz_passes() {
        // A local anchor and a URL merely named in a label are not external fetches.
        let dot =
            br##"digraph { a -> b; a [URL="#section" label="see https://docs.local later"]; }"##;
        assert!(check_inert("text/vnd.graphviz", dot).is_ok());
    }

    #[test]
    fn a_case_variant_media_type_is_still_checked() {
        // `Image/SVG+XML` renders as SVG; a script in it must not pass as inert data.
        assert!(check_inert("Image/SVG+XML", b"<svg><script>x</script></svg>").is_err());
        assert!(check_inert("TEXT/HTML", b"<body onload=\"x\"></body>").is_err());
    }

    #[test]
    fn an_event_handler_with_newline_whitespace_is_rejected() {
        // LF/CR/form-feed are HTML whitespace, so `onload\n=` is a live handler.
        assert!(check_inert("text/html", b"<body onload\n=alert(1)>").is_err());
        assert!(check_inert("text/html", b"<rect onclick\r\n = 'x'/>").is_err());
    }

    #[test]
    fn utf16_or_nul_padded_content_is_rejected() {
        // UTF-16-encoded "<script" hides the token behind NUL bytes but executes.
        let utf16: Vec<u8> = "<script>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(check_inert("image/svg+xml", &utf16).is_err());
        assert!(check_inert("text/html", b"ok\0<script>").is_err());
        // But clean UTF-8 markdown still passes.
        assert!(check_inert("text/markdown", "# ok\nrésumé\n".as_bytes()).is_ok());
    }

    #[test]
    fn a_bare_url_word_in_prose_is_not_a_reference() {
        // "url" mentioned in prose (not as an attribute/function) is not a fetch, even
        // when an absolute URL follows it; "curl" must not anchor either.
        let md = b"# Notes\nthe url https://api.example was called; run curl https://x to repro.\n";
        assert!(check_inert("text/markdown", md).is_ok());
    }

    #[test]
    fn a_script_uri_hidden_behind_numeric_char_references_is_rejected() {
        // A browser decodes `java&#x73;cript:` to `javascript:` before acting; so
        // must the scan (codex review). Both hex and decimal forms.
        let hex = br#"<a href="java&#x73;cript:alert(1)">x</a>"#;
        assert!(check_inert("text/html", hex).is_err());
        let dec = br#"<a href="java&#115;cript:alert(1)">x</a>"#;
        assert!(check_inert("text/html", dec).is_err());
        // And a tag opener hidden the same way (`&#x3c;script`).
        let tag = "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;".as_bytes();
        assert!(check_inert("text/html", tag).is_err());
        // A legitimate numeric reference to a harmless character still passes.
        assert!(check_inert("text/html", "<p>ok &#8212; done</p>".as_bytes()).is_ok());
    }

    #[test]
    fn an_external_srcset_fetch_is_rejected() {
        // `srcset` fetches on render just like `src`; the plain `src` scan missed it.
        let html = br#"<img srcset="https://attacker.example/pixel 1x">"#;
        assert!(check_inert("text/html", html).is_err());
    }
}

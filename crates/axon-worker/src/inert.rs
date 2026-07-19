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
    let m = media_type.split(';').next().unwrap_or("").trim();
    matches!(
        m,
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

    // Work on a lowercased copy so matches are case-insensitive; non-UTF-8 bytes are
    // replaced (they cannot form the ASCII tokens below, but keep the scan total).
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();

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

    // External references — an SVG/HTML that fetches over the network on render.
    // `href`/`src`/`url(` pointing at an absolute or protocol-relative URL.
    let b = text.as_bytes();
    for anchor in ["href", "src", "url("] {
        let mut from = 0;
        while let Some(pos) = text[from..].find(anchor) {
            let start = from + pos + anchor.len();
            // Skip an `=` and any quote/paren/whitespace, then look at the target.
            let target = text[start..].trim_start_matches(['=', '"', '\'', '(', ' ', '\t']);
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("//")
            {
                return reject("references an external URL");
            }
            from = start.max(from + pos + 1);
            if from >= b.len() {
                break;
            }
        }
    }

    Ok(())
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
            || matches!(b[at - 1], b' ' | b'\t' | b'\n' | b'\r' | b'<' | b'/' | b'"' | b'\'');
        if boundary {
            let mut j = at + 2;
            while j < b.len() && b[j].is_ascii_lowercase() {
                j += 1;
            }
            if j > at + 2 {
                // Skip whitespace, then require '='.
                let mut k = j;
                while k < b.len() && matches!(b[k], b' ' | b'\t') {
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
}

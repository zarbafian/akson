//! The Google Gemini (generateContent API) adapter's pure logic (design §16.3):
//! build a generateContent request and extract the reply from the broker's response.
//! Kept separate from `main` so it is unit-testable without a sandbox or a live model.
//!
//! Gemini's shape differs from the OpenAI and Anthropic ones the other adapters use,
//! which is exactly why it exercises the broker's flexibility:
//! - the model is named in the request **path** (`/v1beta/models/<model>:generateContent`),
//!   not the body — so it is fixed on the processor, not passed per call;
//! - auth is an `x-goog-api-key` header (`processor add … --auth x-goog-api-key`);
//! - the prompt rides as a single user `content` part, and the reply is read from
//!   `candidates[0].content.parts[0].text`.

/// Builds a Gemini generateContent request body for `content`, capping the reply at
/// `max_output_tokens`. The model is bound by the processor's path, not the body.
pub fn generate_content_request(content: &str, max_output_tokens: u32) -> String {
    serde_json::json!({
        "contents": [{ "role": "user", "parts": [{ "text": content }] }],
        "generationConfig": { "maxOutputTokens": max_output_tokens },
    })
    .to_string()
}

/// Extracts the model's text from the broker's reply. Gemini returns
/// `{candidates:[{content:{parts:[{text:"…"}], role:"model"}}], …}` as the body.
pub fn extract_content(reply: &serde_json::Value) -> Result<String, String> {
    if let Some(err) = reply.get("error") {
        return Err(format!("the broker refused or could not complete the call: {err}"));
    }
    if let Some(code) = reply.get("status").and_then(serde_json::Value::as_u64) {
        if !(200..300).contains(&code) {
            return Err(format!("the model endpoint returned HTTP {code}"));
        }
    }
    let body = reply
        .get("response")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the broker reply carried no response body".to_owned())?;
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("the model reply was not JSON: {e}"))?;
    parsed["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "the model reply had no candidates[0].content.parts[0].text".to_owned())
}

/// Validates that `bytes` is a well-formed SARIF report (design §14.2) and returns
/// how many findings it carries. A worker's SARIF is untrusted, so it is parsed
/// under the standard limits before it is emitted as evidence — a model that returns
/// malformed or oversized SARIF fails closed rather than shipping garbage.
pub fn validate_sarif(bytes: &[u8]) -> Result<usize, String> {
    let report = axon_evidence::parse_sarif(bytes, &axon_evidence::SarifLimits::default())
        .map_err(|e| format!("the model did not return valid SARIF: {e}"))?;
    Ok(report.findings.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_content_request_is_well_formed() {
        let body: serde_json::Value =
            serde_json::from_str(&generate_content_request("review this", 256)).unwrap();
        assert_eq!(body["contents"][0]["role"], "user");
        assert_eq!(body["contents"][0]["parts"][0]["text"], "review this");
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 256);
        // The model is NOT in the body (it is bound by the processor path).
        assert!(body.get("model").is_none());
    }

    #[test]
    fn extract_content_pulls_the_first_candidate_text() {
        let reply = serde_json::json!({
            "state": "completed",
            "status": 200,
            "response": r#"{"candidates":[{"content":{"parts":[{"text":"LGTM"}],"role":"model"}}]}"#,
        });
        assert_eq!(extract_content(&reply).unwrap(), "LGTM");
    }

    #[test]
    fn a_broker_error_and_a_non_2xx_status_are_errors() {
        assert!(extract_content(&serde_json::json!({ "error": { "status": 403 } })).is_err());
        assert!(extract_content(&serde_json::json!({
            "status": 429, "response": "rate limited"
        }))
        .is_err());
    }

    #[test]
    fn a_reply_without_candidates_is_an_error() {
        let reply = serde_json::json!({
            "status": 200,
            "response": r#"{"candidates":[]}"#,
        });
        assert!(extract_content(&reply).is_err());
    }

    #[test]
    fn validate_sarif_accepts_a_report_and_counts_findings() {
        let sarif = br#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"reviewer"}},"results":[
            {"message":{"text":"nit on line 1"}}
        ]}]}"#;
        assert_eq!(validate_sarif(sarif).unwrap(), 1);
        assert!(validate_sarif(b"not sarif at all").is_err());
    }
}

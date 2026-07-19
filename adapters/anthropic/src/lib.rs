//! The Anthropic (Claude) adapter's pure logic (design §16.3): build a Messages-API
//! request and extract the reply from the broker's response. Kept separate from
//! `main` so it is unit-testable without a sandbox or a live model.
//!
//! The Messages API differs from OpenAI's chat-completions in three ways the adapter
//! and processor config handle: the path is `/v1/messages`, `max_tokens` is
//! required in the body, and auth is an `x-api-key` header plus a static
//! `anthropic-version` header — the latter two configured on the processor
//! (`--auth x-api-key --header anthropic-version:2023-06-01`).

/// Builds a Messages-API request body for `model` with `content` as the single
/// user message and a `max_tokens` cap (Anthropic requires it).
pub fn messages_request(model: &str, content: &str, max_tokens: u32) -> String {
    serde_json::json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{ "role": "user", "content": content }],
    })
    .to_string()
}

/// Extracts the assistant's text from the broker's reply. Anthropic returns
/// `{content:[{type:"text", text:"…"}], …}` as the response body.
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
    parsed["content"]
        .as_array()
        .and_then(|blocks| {
            blocks
                .iter()
                .find(|b| b["type"] == "text")
                .and_then(|b| b["text"].as_str())
        })
        .map(str::to_owned)
        .ok_or_else(|| "the model reply had no text content block".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn messages_request_is_well_formed_with_max_tokens() {
        let body: serde_json::Value =
            serde_json::from_str(&messages_request("claude-3-5-sonnet", "hi", 512)).unwrap();
        assert_eq!(body["model"], "claude-3-5-sonnet");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["messages"][0]["content"], "hi");
    }

    #[test]
    fn extract_content_pulls_the_first_text_block() {
        let reply = serde_json::json!({
            "state": "completed",
            "status": 200,
            "response": r#"{"content":[{"type":"text","text":"LGTM"}],"role":"assistant"}"#,
        });
        assert_eq!(extract_content(&reply).unwrap(), "LGTM");
    }

    #[test]
    fn a_broker_error_and_a_non_2xx_status_are_errors() {
        assert!(extract_content(&serde_json::json!({ "error": { "status": 403 } })).is_err());
        assert!(extract_content(&serde_json::json!({
            "status": 401, "response": "unauthorized"
        }))
        .is_err());
    }

    #[test]
    fn a_reply_without_a_text_block_is_an_error() {
        let reply = serde_json::json!({
            "status": 200,
            "response": r#"{"content":[{"type":"tool_use"}]}"#,
        });
        assert!(extract_content(&reply).is_err());
    }
}

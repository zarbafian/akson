//! The OpenAI-compatible adapter's pure logic (design §16.3): build a
//! chat-completions request, and extract the model's reply from the broker's
//! response. Kept separate from `main` so it is unit-testable without a sandbox or
//! a live model.
//!
//! It targets the OpenAI chat-completions shape, which the OpenAI API and every
//! local server (Ollama, llama.cpp, vLLM, LM Studio) speak — so the same adapter
//! works against any of them; which one is a matter of the processor's config.

/// Builds an OpenAI chat-completions request body for `model` with `content` as the
/// single user message.
pub fn chat_request(model: &str, content: &str) -> String {
    serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": content }],
    })
    .to_string()
}

/// Extracts the assistant's text from the broker's reply. The broker returns
/// `{state, status, response}` on success (`response` is the model's HTTP body) or
/// `{error: …}` on failure; the body is the OpenAI chat-completions JSON.
pub fn extract_content(reply: &serde_json::Value) -> Result<String, String> {
    if let Some(err) = reply.get("error") {
        return Err(format!("the broker refused or could not complete the call: {err}"));
    }
    let status = reply.get("status").and_then(serde_json::Value::as_u64);
    if let Some(code) = status {
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
    parsed["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "the model reply had no choices[0].message.content".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_is_well_formed() {
        let body: serde_json::Value = serde_json::from_str(&chat_request("gpt-4o", "hello")).unwrap();
        assert_eq!(body["model"], "gpt-4o");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "hello");
    }

    #[test]
    fn extract_content_pulls_the_assistant_text() {
        let reply = serde_json::json!({
            "state": "completed",
            "status": 200,
            "response": r#"{"choices":[{"message":{"role":"assistant","content":"LGTM"}}]}"#,
        });
        assert_eq!(extract_content(&reply).unwrap(), "LGTM");
    }

    #[test]
    fn a_broker_error_is_surfaced() {
        let reply = serde_json::json!({ "error": { "status": 403, "title": "output-denied" } });
        assert!(extract_content(&reply).is_err());
    }

    #[test]
    fn a_non_2xx_model_status_is_an_error() {
        let reply = serde_json::json!({
            "state": "completed",
            "status": 401,
            "response": "unauthorized",
        });
        assert!(extract_content(&reply).is_err());
    }

    #[test]
    fn a_reply_without_choices_is_an_error() {
        let reply = serde_json::json!({
            "state": "completed",
            "status": 200,
            "response": r#"{"id":"x","choices":[]}"#,
        });
        assert!(extract_content(&reply).is_err());
    }
}

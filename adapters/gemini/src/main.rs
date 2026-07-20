//! The Google Gemini worker adapter (design §16.3). Run inside the sandbox as the
//! performer's worker; the operator configures a processor at the Gemini endpoint —
//! the model is named in the path — and points the worker command at this adapter:
//!
//! ```text
//! akson processor add gemini google generativelanguage.googleapis.com 443 ca \
//!     --path /v1beta/models/gemini-2.0-flash:generateContent --auth x-goog-api-key
//! AKSON_WORKER_EXEC='akson-adapter-gemini --processor gemini'
//! ```
//!
//! It reads the approved input, asks the granted model (through the broker — never
//! the network directly) to review it, and writes the reply as the response. There
//! is no `--model` flag: Gemini binds the model in the processor's path.

use std::process::ExitCode;

use akson_adapter_gemini::{extract_content, generate_content_request, validate_sarif};
use akson_adapter_sdk::Task;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("akson-adapter-gemini: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let mut task = Task::load().map_err(|e| e.to_string())?;

    let input = task.read(&args.input).map_err(|e| e.to_string())?;
    let content = String::from_utf8_lossy(&input);
    let prompt = if args.sarif {
        format!(
            "Review the following {} and report findings as a SARIF 2.1.0 report. \
             Return ONLY the SARIF JSON, no prose:\n\n{content}",
            args.input
        )
    } else {
        format!(
            "Review the following {} and report your findings concisely:\n\n{content}",
            args.input
        )
    };

    let request = generate_content_request(&prompt, args.max_tokens);
    let reply = task
        .call_model(&args.processor, &request)
        .map_err(|e| e.to_string())?;
    let text = extract_content(&reply)?;

    if args.sarif {
        // Validate the model's SARIF (untrusted) before emitting it as evidence, and
        // summarize it in the text response.
        let count = validate_sarif(text.as_bytes())?;
        task.write_artifact("findings", "application/sarif+json", text.as_bytes())
            .map_err(|e| e.to_string())?;
        task.respond(
            format!("Review complete: {count} finding(s); see the SARIF artifact.").as_bytes(),
        )
        .map_err(|e| e.to_string())
    } else {
        task.respond(text.as_bytes()).map_err(|e| e.to_string())
    }
}

/// The adapter's arguments, from the worker command line.
struct Args {
    /// The processor to call (must match the granted `processor_use` scope). Its path
    /// binds the Gemini model, e.g. `/v1beta/models/gemini-2.0-flash:generateContent`.
    processor: String,
    /// The input id used as the prompt content (default `diff`).
    input: String,
    /// The reply cap (`generationConfig.maxOutputTokens`).
    max_tokens: u32,
    /// Emit findings as a validated `application/sarif+json` artifact (needs
    /// `artifact_export` granted) instead of a plain text response.
    sarif: bool,
}

impl Args {
    fn parse(mut it: impl Iterator<Item = String>) -> Result<Self, String> {
        let (mut processor, mut input, mut max_tokens, mut sarif) = (None, None, 1024u32, false);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--processor" => processor = it.next(),
                "--input" => input = it.next(),
                "--sarif" => sarif = true,
                "--max-tokens" => {
                    max_tokens = it
                        .next()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| "--max-tokens needs a number".to_owned())?;
                }
                other => return Err(format!("unexpected argument {other:?}")),
            }
        }
        Ok(Args {
            processor: processor.ok_or_else(|| "missing --processor <id>".to_owned())?,
            input: input.unwrap_or_else(|| "diff".to_owned()),
            max_tokens,
            sarif,
        })
    }
}

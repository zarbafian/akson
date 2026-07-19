//! The Anthropic (Claude) worker adapter (design §16.3). Run inside the sandbox as
//! the performer's worker; the operator configures it as the worker command and
//! points a processor at the Messages API:
//!
//! ```text
//! axon processor add claude anthropic api.anthropic.com 443 ca \
//!     --path /v1/messages --auth x-api-key --header anthropic-version:2023-06-01
//! AXON_WORKER_CMD='axon-adapter-anthropic --processor claude --model claude-3-5-sonnet-latest'
//! ```
//!
//! It reads the approved input, asks the granted model (through the broker — never
//! the network directly) to review it, and writes the reply as the response.

use std::process::ExitCode;

use axon_adapter_anthropic::{extract_content, messages_request};
use axon_adapter_sdk::Task;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("axon-adapter-anthropic: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let mut task = Task::load().map_err(|e| e.to_string())?;

    let input = task.read(&args.input).map_err(|e| e.to_string())?;
    let content = String::from_utf8_lossy(&input);
    let prompt = format!(
        "Review the following {} and report your findings concisely:\n\n{content}",
        args.input
    );

    let request = messages_request(&args.model, &prompt, args.max_tokens);
    let reply = task
        .call_model(&args.processor, &request)
        .map_err(|e| e.to_string())?;
    let text = extract_content(&reply)?;

    task.respond(text.as_bytes()).map_err(|e| e.to_string())
}

/// The adapter's arguments, from the worker command line.
struct Args {
    processor: String,
    model: String,
    input: String,
    max_tokens: u32,
}

impl Args {
    fn parse(mut it: impl Iterator<Item = String>) -> Result<Self, String> {
        let (mut processor, mut model, mut input, mut max_tokens) = (None, None, None, 1024u32);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--processor" => processor = it.next(),
                "--model" => model = it.next(),
                "--input" => input = it.next(),
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
            model: model.ok_or_else(|| "missing --model <name>".to_owned())?,
            input: input.unwrap_or_else(|| "diff".to_owned()),
            max_tokens,
        })
    }
}

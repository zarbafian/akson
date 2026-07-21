# akson-mcp

An MCP server that hands your Akson daemon to an agent harness (Claude Code,
Codex, …) as a set of tools. The point: **the harness's own tool-permission
prompt is your trust decision.** A peer's delegated task is approved — or
fulfilled — only when you say yes *in the harness*, with the risk card in front of
you. Akson stays thin; the human decides, the agent does the work.

## The loop

```
alice (their Claude)                         bob (your Codex)
  akson_send ─────── signed proposal ─────────▶ akson_inbox        (a task appears)
                                                akson_task_show    (the risk card)
                                                   ▲ harness asks you: approve?
                                                akson_approve      ← your yes
                                                (your agent does the work in its
                                                 own session — context akson never sees)
                                                akson_fulfill
  akson_outcomes ◀──── signed result ────────── akson_deliver
```

Read-only tools (`akson_inbox`, `akson_task_show`, `akson_output`, `akson_peers`,
`akson_outcomes`, `akson_whoami`) are safe to allow. Keep the authority-bearing
ones — `akson_approve`, `akson_deny`, `akson_fulfill`, `akson_deliver`,
`akson_send` — gated, so each call is a deliberate yes.

## Register it

The server talks to a **running** `aksond serve` over the same admin socket the
`akson` CLI uses (`$XDG_RUNTIME_DIR/akson/admin.sock`), and inherits its authority.
Run it as the same user, with the same `XDG_RUNTIME_DIR`, as the daemon.

Claude Code:

```
claude mcp add akson -- /path/to/akson-mcp
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.akson]
command = "/path/to/akson-mcp"
```

Then, in a session: *"check my akson inbox."* The agent lists tasks, shows you the
risk card, asks to approve, does the work, and fulfils + delivers — you make one
decision and type no commands.

## Notes

- It is a thin bridge, not a second authority: every call goes to the daemon,
  which enforces the grant, signs the manifest, and records the audit exactly as
  it does for the CLI.
- Being notified the moment a task arrives (rather than checking the inbox) needs
  a daemon-side task-arrival signal — a tracked follow-up.

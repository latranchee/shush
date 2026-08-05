# Secret Manager Security Model

`secret_manager` is a practical local privacy improvement, not a hard security
boundary against the owner or administrator of the machine.

## Protects Against

- Plaintext API keys committed to the repo.
- Plaintext API keys in `.env` files.
- Casual user browsing of project folders.
- Accidental copy/paste exposure.
- Screenshots of config files.
- Basic script reuse where users should not need to know the API key.

## Does Not Protect Against

- A determined Windows administrator.
- Malware running as the same user.
- Debuggers attached to the child process.
- Process memory inspection.
- A modified child command that prints its environment.
- Tools that log environment variables.
- API providers receiving requests made with the key.

If a local script can use a secret without asking the user for a password each
time, a sufficiently privileged local user can eventually extract it.

## Secret Exposure Points

Even with Credential Manager, secret values exist briefly in:

- The PowerShell process retrieving the credential.
- The child process environment for `run`.
- The child process memory.
- Any subprocesses that inherit the environment.

The implementation must avoid creating extra exposure points:

- Do not write secret values to files.
- Do not print secret values.
- Do not include secret values in structured logs.
- Do not include secret values in thrown exception messages.
- Do not pass secret values on command lines.

## Preferred Workflow

Use `run` for tools that require environment variables:

```powershell
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key
```

This keeps the secret out of the repo and avoids persistent `.env` files.

## Future Stronger Workflow

A local proxy can reduce exposure further by keeping the raw API key out of the
agent/tool environment. In that model, the agent requests an allowed API call by
secret name, and the proxy injects the credential into the outbound HTTP
request.

That model is documented separately in `proxy_future.md` and should come after
the basic Credential Manager runner is working.


# Rough edges

Friction points hit while building this plugin against the published
`forge-plugin-sdk`. Append as we go. Each entry: what was awkward, the
workaround, and a one-line idea for an upstream fix.

## SDK

- **`forge_ir::HttpMethod` has no `Display` impl.** `format!("{}", op.method)`
  fails to compile. Workaround: `op.method.as_str()`. Fix: add
  `impl Display for HttpMethod` that delegates to `as_str()`.

- **`OutputFile` field is `content` (singular), not `contents`.** Easy to
  misname when transcribing from WIT (which uses `output-file`). The SDK
  already exposes `OutputFile::text(path, content)` / `::binary` /
  `::executable`, which sidestep the field-name question entirely. Fix:
  the plugin-authoring docs should lead with those constructors before
  showing struct-literal usage.

## Distribution / OCI

- **GHCR user-owned packages default to private even when the source repo
  is public.** First publish leaves the artifact unpullable by `forge`'s
  anonymous OCI client (ADR-0010). There is no REST API to flip
  visibility for user-owned packages — only the web UI at
  `https://github.com/users/<owner>/packages/container/<name>/settings`.
  Fix: document this gotcha in `docs/plugin-authoring.md` under
  "Distributing your plugin", with the direct settings URL.

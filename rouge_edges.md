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


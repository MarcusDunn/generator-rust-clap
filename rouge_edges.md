# Rough edges

Friction points hit while building this plugin against the published
`forge-plugin-sdk` and `forge` CLI. Append as we go. Each entry: what
was awkward, the workaround, and a one-line idea for an upstream fix.

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

- **Local plugin development needs Nix or a manual `wasm32-wasip2`
  install.** `forge-plugin-sdk` deliberately refuses to build for the
  host (ADR-0004 / WASM-only). On a fresh machine without `rustup`
  (e.g. Nix-managed Rust), there's no convenient `cargo check` for a
  fast feedback loop — the only signal is the GitHub Actions build.
  Workaround: rely on the `flake.nix` shipped with this repo. Fix:
  the SDK README could lead with a one-line `nix develop -c cargo
  build --release --target wasm32-wasip2` recipe.

## CLI / pipeline

- **`forge generate` config-less mode (`--input`/`--generator`/`-o`)
  has no way to pass plugin config.** Plugins that *require* config
  (e.g. this generator's OAuth block needs `oauth.clientId`) force the
  user back to project mode (`forge.toml`). Workaround: write a
  three-line `forge.toml` and run `forge generate <dir>`. Fix: a
  `--generator-config <json>` flag (or `@file.json` / `-` for stdin)
  on config-less mode, mirroring the existing pattern.

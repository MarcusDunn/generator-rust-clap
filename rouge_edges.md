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

## Standards

- **OpenAPI has no native vocabulary for parameterized-audience tokens.**
  RFC 8693 token exchange + path-derived audience is a real pattern —
  any multi-tenant API whose backend is fronted by per-resource-server
  IdP clients lands here — but there's no OAS field that says "ops
  whose path uses `{tenant}` need a JWT minted with audience
  `urn:vendor:tenant:{tenant}`." We define a generic
  `x-token-exchange` extension on the `oauth2` security scheme rather
  than a vendor-specific knob; the plugin honors it and degrades
  gracefully when absent. Worth proposing upstream if/when OAS picks up
  RFC 8707 vocabulary. Shape:
  ```yaml
  x-token-exchange:
    audience-template: "urn:vendor:tenant:{tenant}"   # placeholder ↔ path-param name
    resource-template: "https://api/.../{tenant}"     # optional, RFC 8707
    scope: ["roles"]                                  # optional, requested on exchange
  ```

- **Keycloak 26's standard token exchange requires confidential clients.**
  Public PKCE clients have nothing to authenticate with on the token
  endpoint. The generator now supports an `oauth.clientSecretEnv`
  config option: when set, every token-endpoint call (login, refresh,
  exchange) attaches `Authorization: Basic`. The secret is per-operator
  via env var, never embedded in the binary. This is the same posture
  `gcloud` / AWS CLI use for their internal-developer clients.

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

- **`SecurityScheme.extensions` (and the rest of the IR's `x-*`
  extension vecs) don't signpost the resolver.** The field is
  `Vec<(String, ValueRef)>`; turning the `ValueRef` into something
  walkable requires `forge_plugin_sdk::values_ext::resolve_to_serde`,
  which I had to find by reading the SDK's `lib.rs`. Fix: the
  rustdoc on every `extensions:` field could point at the resolver in
  one line, e.g. `// Resolve via [`crate::values_ext::resolve_to_serde`].`

- **No SDK helper for emitting source-tree-shaped output that's
  syntax-checked at generator-author time.** The Rust auth runtime in
  this plugin lives as a ~430-line `&str` template with
  `__PLACEHOLDER__` substitutions; no rustfmt, no compile-check on
  the template until the *generated* crate is built. A SDK pattern
  for "emit this Rust crate as files, compile it as a sub-target of
  the plugin's own build" would catch typos at the generator's CI
  rather than the consumer's. Fix: at minimum, `forge` could
  optionally `rustfmt` Rust outputs (heuristic: file ends in `.rs`)
  before writing them — same idea as the prettier post-step in the
  TS-fetch generator's `update-openapi-client.sh`.

- **Plugin-authoring docs don't draw a line between "spec belongs"
  and "plugin config belongs."** OAuth `clientId` lives in plugin
  config (per-installation), `audience-template` lives in the spec
  (contract), `clientSecretEnv` lives in plugin config but the actual
  secret is runtime env. The boundary is judgment-y and each plugin
  author redraws it. Fix: a short section in `plugin-authoring.md`
  laying out the principle ("contract → spec; per-installation →
  plugin config; per-operator → runtime env") with one or two
  worked examples.

## CLI / pipeline

- **`forge generate` config-less mode (`--input`/`--generator`/`-o`)
  has no way to pass plugin config.** Plugins that *require* config
  (e.g. this generator's OAuth block needs `oauth.clientId`) force the
  user back to project mode (`forge.toml`). Workaround: write a
  three-line `forge.toml` and run `forge generate <dir>`. Fix: a
  `--generator-config <json>` flag (or `@file.json` / `-` for stdin)
  on config-less mode, mirroring the existing pattern.

- **First-time OCI publish ergonomics aren't surfaced by
  `plugin-authoring.md`.** Pushing the wasm to GHCR (or any registry
  whose owner-default visibility is private) leaves the artifact
  unpullable until the operator flips the package to public via the
  web UI. `forge`'s OCI client is anonymous-only (ADR-0010), so a
  consumer's first `forge generate` against a freshly-published
  plugin will fail until that step. Fix: the "Distributing your
  plugin" section in `docs/plugin-authoring.md` could call out the
  visibility-flip step with a direct link to
  `https://github.com/users/<owner>/packages/container/<name>/settings`
  for GHCR, and an equivalent note for ECR/Docker Hub.

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

- **OAS security schemes hold one auth/token URL pair.** Real APIs
  deploy across dev/staging/prod with different IdP hostnames; the
  spec describes the contract in one place. Workaround: the
  generator emits `<PREFIX>_AUTH_URL` / `<PREFIX>_TOKEN_URL` runtime
  env-var overrides on top of the spec values. Fix would be in OAS
  itself (server-variable-style templating on flow URLs); not
  something the SDK or `forge` can address downstream.

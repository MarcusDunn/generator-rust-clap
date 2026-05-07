# generator-rust-clap

OpenAPI Forge generator that emits a Rust CLI crate (clap derive + reqwest) for an OpenAPI spec.

**Status: shipping.** The plugin emits a buildable Rust CLI crate with:

- One clap subcommand per OpenAPI operation, grouped by tag (OAS 3.2 `parent`-aware nesting).
- OAuth 2.0 PKCE login/logout when the spec declares an `oauth2.authorizationCode` flow + plugin config supplies `clientId`. Optional `client_secret_basic` on the token endpoint via `oauth.clientSecretEnv` (env-var-supplied).
- RFC 8693 standard token exchange driven by a generic `x-token-exchange` extension on the spec's `oauth2` security scheme — operations whose path includes the placeholder use a separately-audienced JWT.
- Shell completions for bash / zsh / fish / powershell / elvish via `clap_complete`: `<bin> completion <shell>`.
- Runtime env-var overrides for `<PREFIX>_AUTH_URL` / `<PREFIX>_TOKEN_URL` / `<PREFIX>_BASE_URL` / `<PREFIX>_TOKEN` so a single binary moves between dev / staging / prod.

This is an *external* plugin — it depends on the published
[`forge-plugin-sdk`](https://crates.io/crates/forge-plugin-sdk) crate, not on
the in-tree workspace. Its purpose is partly to surface rough edges in the
SDK from a downstream-consumer perspective.

## Use

```toml
# forge.toml
[generator]
oci = "ghcr.io/marcusdunn/generator-rust-clap:latest"
```

Pin by digest for reproducibility:

```toml
[generator]
oci = "ghcr.io/marcusdunn/generator-rust-clap@sha256:…"
```

## Build locally

```sh
cargo build --release --target wasm32-wasip2
# → target/wasm32-wasip2/release/generator_rust_clap.wasm
```

`forge-plugin-sdk` is wasm-only by design (ADR-0004); plain `cargo check`
without `--target wasm32-wasip2` will fail with a deliberate `compile_error!`.

## Publish

Tag a release (`v0.0.1`) or fire the release workflow manually from the
Actions tab. Either path builds the wasm component and pushes it to
`ghcr.io/marcusdunn/generator-rust-clap` via `oras`.

## License

Apache-2.0 OR MIT

//! Plugin config — parsed from the JSON string the host hands us.
//!
//! The OAuth block activates `login`/`logout` subcommand emission when
//! the spec also declares an `oauth2.authorizationCode` flow with both
//! `authorizationUrl` and `tokenUrl` populated. See `emit::oauth`.

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    /// Override the package / bin name. Defaults to a kebab-case form
    /// of `info.title`.
    pub name: Option<String>,
    /// Override the API base URL. Falls back to `servers[0].url`.
    pub base_url: Option<String>,
    /// Per-installation OAuth client configuration. Required to enable
    /// `login`/`logout` subcommand emission. See `OAuthConfig`.
    pub oauth: Option<OAuthConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OAuthConfig {
    /// OAuth client ID for the public CLI client. Never derivable
    /// from the spec.
    pub client_id: String,
    /// Spec security-scheme id to target when more than one
    /// `oauth2.authorizationCode` flow is declared. Optional.
    pub scheme_id: Option<String>,
    /// Loopback redirect port. Defaults to 8848.
    pub redirect_port: Option<u16>,
    /// Per-installation scope override. Defaults to the union of
    /// per-op scopes referencing the chosen scheme.
    pub scopes: Option<Vec<String>>,
}

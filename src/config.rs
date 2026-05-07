//! Plugin config — parsed from the JSON string the host hands us.
//!
//! Future phases (tag grouping is fully spec-driven so adds nothing
//! here; OAuth adds an `oauth` object — see plan).

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    /// Override the package / bin name. Defaults to a kebab-case form
    /// of `info.title`.
    pub name: Option<String>,
    /// Override the API base URL. Falls back to `servers[0].url`.
    pub base_url: Option<String>,
}

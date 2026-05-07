//! `generator-rust-clap` — emits a Rust CLI crate (clap derive + reqwest)
//! for an OpenAPI spec.
//!
//! Status: bootstrap. Today this returns a single `README.md` summarizing
//! the spec — just enough to validate the OCI publish pipeline end-to-end.
//! The real emission (Cargo.toml + src/main.rs with one subcommand per
//! operation) lands in follow-ups.

#![forbid(unsafe_code)]

use forge_plugin_sdk::convert::generator as conv;
use forge_plugin_sdk::generator::exports::forge::plugin::generator_api::{
    GenerationOutput as WitGenerationOutput, Guest,
};
use forge_plugin_sdk::generator::forge::plugin::stage::StageError;
use forge_plugin_sdk::generator::forge::plugin::types::{Ir as WitIr, PluginInfo as WitPluginInfo};
use forge_plugin_sdk::{ir, FileMode, GenerationOutput, OutputFile};

#[derive(Debug, serde::Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {}

pub fn generate(spec: &ir::Ir, _cfg: &Config) -> GenerationOutput {
    let mut body = String::new();
    body.push_str(&format!("# {}\n\n", spec.info.title));
    if !spec.info.version.is_empty() {
        body.push_str(&format!("Version: {}\n\n", spec.info.version));
    }
    body.push_str(&format!("Operations: {}\n\n", spec.operations.len()));
    for op in &spec.operations {
        body.push_str(&format!("- `{}` — {} {}\n", op.id, op.method, op.path_template));
    }
    GenerationOutput {
        files: vec![OutputFile {
            path: "README.md".into(),
            contents: body.into_bytes(),
            mode: FileMode::Text,
        }],
        diagnostics: vec![],
    }
}

struct RustClap;

impl Guest for RustClap {
    fn info() -> WitPluginInfo {
        conv::plugin_info_to_wit(ir::PluginInfo {
            name: "generator-rust-clap".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    fn config_schema() -> String {
        include_str!("../schema.json").into()
    }

    fn generate(spec: WitIr, config: String) -> Result<WitGenerationOutput, StageError> {
        let cfg: Config = if config.trim().is_empty() {
            Config::default()
        } else {
            forge_plugin_sdk::serde_json::from_str(&config)
                .map_err(|e| conv::config_invalid(e.to_string()))?
        };
        let canonical = conv::ir_from_wit(spec);
        let out = generate(&canonical, &cfg);
        Ok(conv::generation_output_to_wit(out))
    }
}

forge_plugin_sdk::generator::export!(RustClap with_types_in forge_plugin_sdk::generator);

//! Generation entry point. Emits a buildable Rust CLI crate (clap
//! derive + reqwest) with tag-grouped subcommands and, when the spec
//! + plugin config opt in, OAuth 2.0 PKCE login/logout plus optional
//! RFC 8693 token exchange driven by a generic `x-token-exchange`
//! extension on the chosen oauth2 security scheme.

use std::collections::BTreeSet;

use forge_plugin_sdk::ir::{
    Body, HttpMethod, Ir, OAuth2Flow, OAuth2FlowKind, Operation, Parameter, SecurityScheme,
    SecuritySchemeKind, ValueRef,
};
use forge_plugin_sdk::{values_ext, GenerationOutput, OutputFile};

use crate::config::{Config, OAuthConfig};
use crate::naming::{kebab_case, pascal_case, screaming_snake, snake_case};
use crate::tags::{self, TagGroup, TagTree};

pub fn all(ir: &Ir, cfg: &Config) -> GenerationOutput {
    let bin_name = bin_name(ir, cfg);
    let pkg_name = format!("{bin_name}-cli");
    let oauth = detect_oauth(ir, cfg);

    let mut files = vec![
        OutputFile::text(
            "Cargo.toml",
            emit_cargo_toml(&pkg_name, &bin_name, oauth.is_some()),
        ),
        OutputFile::text("src/main.rs", emit_main_rs(ir, cfg, &bin_name, oauth.as_ref())),
        OutputFile::text("src/client.rs", emit_client_rs(ir)),
        OutputFile::text("src/runtime.rs", emit_runtime_rs()),
        OutputFile::text("README.md", emit_readme(ir, &bin_name, oauth.as_ref())),
    ];
    if let Some(oa) = &oauth {
        files.push(OutputFile::text("src/auth.rs", emit_auth_rs(&bin_name, oa)));
    }

    GenerationOutput { files, diagnostics: vec![] }
}

fn bin_name(ir: &Ir, cfg: &Config) -> String {
    if let Some(n) = cfg.name.as_deref().filter(|s| !s.is_empty()) {
        return kebab_case(n);
    }
    let title = ir.info.title.trim();
    if title.is_empty() {
        "api-cli".into()
    } else {
        kebab_case(title)
    }
}

fn default_base_url(ir: &Ir, cfg: &Config) -> String {
    if let Some(u) = cfg.base_url.as_deref().filter(|s| !s.is_empty()) {
        return u.to_string();
    }
    ir.servers
        .first()
        .map(|s| s.url.clone())
        .unwrap_or_else(|| "http://localhost".into())
}

fn env_prefix(bin_name: &str) -> String {
    screaming_snake(bin_name)
}

// ---------------------------------------------------------------------------
// OAuth activation + token-exchange detection
// ---------------------------------------------------------------------------

struct OauthInfo<'a> {
    flow: &'a OAuth2Flow,
    config: &'a OAuthConfig,
    scopes: Vec<String>,
    exchange: Option<TokenExchangeInfo>,
}

#[derive(Debug, Clone)]
struct TokenExchangeInfo {
    /// Audience template like `"urn:vendor:tenant:{tenant}"`.
    audience_template: String,
    /// Single placeholder name extracted from the template. v0.0.6
    /// supports exactly one placeholder; multi-placeholder is a
    /// followup.
    placeholder: String,
    /// Optional RFC 8707 `resource` template.
    resource_template: Option<String>,
    /// Optional extra scopes to request on the exchange.
    extra_scope: Vec<String>,
}

fn detect_oauth<'a>(ir: &'a Ir, cfg: &'a Config) -> Option<OauthInfo<'a>> {
    let oc = cfg.oauth.as_ref()?;
    if oc.client_id.is_empty() {
        return None;
    }
    let mut candidates: Vec<&SecurityScheme> = ir
        .security_schemes
        .iter()
        .filter(|s| matches!(s.kind, SecuritySchemeKind::Oauth2(_)))
        .collect();
    if let Some(want_id) = &oc.scheme_id {
        candidates.retain(|s| s.id == *want_id);
    }
    candidates.sort_by(|a, b| a.id.cmp(&b.id));

    for s in candidates {
        if let SecuritySchemeKind::Oauth2(scheme) = &s.kind {
            for f in &scheme.flows {
                let usable = matches!(f.kind, OAuth2FlowKind::AuthorizationCode)
                    && f.authorization_url.is_some()
                    && f.token_url.is_some();
                if !usable {
                    continue;
                }
                let scopes = if let Some(o) = &oc.scopes {
                    o.clone()
                } else {
                    let mut set: BTreeSet<String> = BTreeSet::new();
                    for op in &ir.operations {
                        for req in &op.security {
                            if req.scheme_id == s.id {
                                for sc in &req.scopes {
                                    set.insert(sc.clone());
                                }
                            }
                        }
                    }
                    set.into_iter().collect()
                };
                let exchange = parse_token_exchange(ir, s);
                return Some(OauthInfo { flow: f, config: oc, scopes, exchange });
            }
        }
    }
    None
}

fn parse_token_exchange(ir: &Ir, scheme: &SecurityScheme) -> Option<TokenExchangeInfo> {
    let (_, vref) = scheme.extensions.iter().find(|(k, _)| k == "x-token-exchange")?;
    let json = values_ext::resolve_to_serde(&ir.values, *vref);
    let obj = json.as_object()?;

    let audience_template = obj.get("audience-template")?.as_str()?.to_string();
    let placeholders = extract_placeholders(&audience_template);
    if placeholders.len() != 1 {
        // v0.0.6 supports exactly one placeholder. Multi-placeholder is a
        // followup. Falling back to non-exchange mode.
        return None;
    }
    let placeholder = placeholders.into_iter().next().unwrap();

    let resource_template = obj
        .get("resource-template")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let extra_scope: Vec<String> = obj
        .get("scope")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Some(TokenExchangeInfo {
        audience_template,
        placeholder,
        resource_template,
        extra_scope,
    })
}

fn extract_placeholders(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            for c2 in chars.by_ref() {
                if c2 == '}' {
                    break;
                }
                name.push(c2);
            }
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

fn op_uses_placeholder(op: &Operation, placeholder: &str) -> bool {
    op.path_params.iter().any(|p| snake_case(&p.name) == snake_case(placeholder))
}

// ---------------------------------------------------------------------------
// Cargo.toml
// ---------------------------------------------------------------------------

fn emit_cargo_toml(pkg_name: &str, bin_name: &str, oauth: bool) -> String {
    let oauth_block = if oauth {
        r#"sha2 = "0.10"
base64 = "0.22"
rand = "0.8"
webbrowser = "1"
directories = "6"
"#
    } else {
        ""
    };
    format!(
        r#"# Generated by openapi-forge / generator-rust-clap.
[package]
name = "{pkg_name}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "{bin_name}"
path = "src/main.rs"

[dependencies]
clap = {{ version = "4", features = ["derive", "env"] }}
tokio = {{ version = "1", features = ["macros", "rt-multi-thread", "net", "io-util", "sync"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
anyhow = "1"
reqwest = {{ version = "0.12", default-features = false, features = ["json", "rustls-tls"] }}
urlencoding = "2"
{oauth_block}"#
    )
}

// ---------------------------------------------------------------------------
// src/main.rs
// ---------------------------------------------------------------------------

fn emit_main_rs(ir: &Ir, cfg: &Config, bin_name: &str, oauth: Option<&OauthInfo>) -> String {
    let title = escape_rust_string(&ir.info.title);
    let version = escape_rust_string(&ir.info.version);
    let base_url = escape_rust_string(&default_base_url(ir, cfg));
    let prefix = env_prefix(bin_name);

    let tree = tags::build(ir);
    let oauth_active = oauth.is_some();
    let exchange = oauth.and_then(|o| o.exchange.as_ref());
    let placeholder_kebab = exchange.map(|e| kebab_case(&e.placeholder));
    let placeholder_snake = exchange.map(|e| snake_case(&e.placeholder));
    let placeholder_pascal = exchange.map(|e| pascal_case(&e.placeholder));

    let mut out = String::new();
    out.push_str("// Generated by openapi-forge / generator-rust-clap; do not edit by hand.\n#![allow(clippy::needless_late_init, clippy::redundant_field_names, clippy::too_many_arguments, clippy::collapsible_if)]\n\n");
    if oauth_active {
        out.push_str("mod auth;\n");
    }
    out.push_str("mod client;\nmod runtime;\n\nuse clap::{Args, Parser, Subcommand};\nuse client::ApiClient;\nuse runtime::OutputMode;\n\n");

    out.push_str(&format!(
        "#[derive(Parser)]\n#[command(name = \"{bin_name}\", version = \"{version}\", about = \"{title}\", long_about = None)]\nstruct Cli {{\n    /// API base URL.\n    #[arg(long, global = true, env = \"{prefix}_BASE_URL\", default_value = \"{base_url}\")]\n    base_url: String,\n\n    /// Bearer token. Overrides any stored OAuth or exchanged token.\n    #[arg(long, global = true, env = \"{prefix}_TOKEN\")]\n    token: Option<String>,\n\n    /// Output mode for response bodies.\n    #[arg(long, global = true, value_enum, default_value_t = OutputMode::Json)]\n    output: OutputMode,\n\n"
    ));

    if let (Some(kebab), Some(snake)) = (&placeholder_kebab, &placeholder_snake) {
        let env_name = format!("{}_{}", prefix, screaming_snake(snake));
        out.push_str(&format!(
            "    /// Slug used to template the RFC 8693 exchange audience for tenant-scoped operations.\n    #[arg(long = \"{kebab}\", global = true, env = \"{env_name}\")]\n    {snake}: Option<String>,\n\n"
        ));
    }

    out.push_str("    #[command(subcommand)]\n    cmd: Cmd,\n}\n\n");

    if ir.operations.is_empty() && !oauth_active {
        out.push_str("#[derive(Subcommand)]\nenum Cmd {\n    /// (No operations declared in the spec.)\n    #[command(hide = true)]\n    Noop,\n}\n\n");
    } else {
        emit_root_enum(&mut out, &tree, oauth_active, exchange, placeholder_pascal.as_deref(), placeholder_kebab.as_deref());
        for root in &tree.roots {
            emit_group_types(&mut out, root, "", exchange);
        }
    }

    // main()
    out.push_str("#[tokio::main(flavor = \"multi_thread\")]\nasync fn main() -> anyhow::Result<()> {\n    let cli = Cli::parse();\n");

    // Built-in handlers for login / logout / placeholder-config subcommands.
    if oauth_active {
        out.push_str("    if matches!(cli.cmd, Cmd::Login) {\n        auth::login().await?;\n        eprintln!(\"logged in\");\n        return Ok(());\n    }\n    if matches!(cli.cmd, Cmd::Logout) {\n        let removed = auth::logout().await?;\n        eprintln!(\"{}\", if removed { \"logged out\" } else { \"no stored token\" });\n        return Ok(());\n    }\n");
    }
    if let Some(pascal) = &placeholder_pascal {
        let kebab = placeholder_kebab.as_ref().unwrap();
        out.push_str(&format!(
            "    if let Cmd::Set{pascal} {{ value }} = &cli.cmd {{\n        auth::write_persisted(\"{kebab}\", value)?;\n        eprintln!(\"persisted {kebab} = {{}}\", value);\n        return Ok(());\n    }}\n    if matches!(cli.cmd, Cmd::Unset{pascal}) {{\n        let removed = auth::delete_persisted(\"{kebab}\")?;\n        eprintln!(\"{{}}\", if removed {{ \"unset\" }} else {{ \"no persisted value\" }});\n        return Ok(());\n    }}\n    if matches!(cli.cmd, Cmd::Show{pascal}) {{\n        match auth::read_persisted(\"{kebab}\")? {{\n            Some(v) => println!(\"{{}}\", v),\n            None => eprintln!(\"(none)\"),\n        }}\n        return Ok(());\n    }}\n"
        ));
    }

    // Resolve effective placeholder value (flag/env via clap → persisted default).
    if let Some(snake) = &placeholder_snake {
        let kebab = placeholder_kebab.as_ref().unwrap();
        out.push_str(&format!(
            "    let __resolved_{snake}: Option<String> = match cli.{snake}.clone() {{\n        Some(v) => Some(v),\n        None => auth::read_persisted(\"{kebab}\")?,\n    }};\n"
        ));
    }

    out.push_str("    let client = ApiClient::new(cli.base_url)?;\n");
    out.push_str("    let result: serde_json::Value = match cli.cmd {\n");
    if oauth_active {
        out.push_str("        Cmd::Login | Cmd::Logout => unreachable!(\"handled above\"),\n");
    }
    if placeholder_pascal.is_some() {
        let pascal = placeholder_pascal.as_ref().unwrap();
        out.push_str(&format!(
            "        Cmd::Set{pascal} {{ .. }} | Cmd::Unset{pascal} | Cmd::Show{pascal} => unreachable!(\"handled above\"),\n"
        ));
    }
    if ir.operations.is_empty() && !oauth_active {
        out.push_str("        Cmd::Noop => return Ok(()),\n");
    } else {
        for root in &tree.roots {
            emit_root_match_arms(&mut out, root, "", oauth, exchange);
        }
    }
    out.push_str("    };\n    runtime::print_output(&result, cli.output)\n}\n");

    out
}

fn emit_root_enum(
    out: &mut String,
    tree: &TagTree,
    oauth_active: bool,
    exchange: Option<&TokenExchangeInfo>,
    placeholder_pascal: Option<&str>,
    placeholder_kebab: Option<&str>,
) {
    out.push_str("#[derive(Subcommand)]\nenum Cmd {\n");
    if oauth_active {
        out.push_str("    /// Run OAuth 2.0 authorization-code flow with PKCE; persists the access token.\n    Login,\n    /// Delete the stored OAuth token.\n    Logout,\n");
    }
    if exchange.is_some() {
        let pascal = placeholder_pascal.unwrap();
        let kebab = placeholder_kebab.unwrap();
        out.push_str(&format!(
            "    /// Persist a default `{kebab}` so subsequent calls can omit `--{kebab}`.\n    Set{pascal} {{ value: String }},\n    /// Clear the persisted default `{kebab}`.\n    Unset{pascal},\n    /// Print the persisted default `{kebab}`.\n    Show{pascal},\n"
        ));
    }
    for root in &tree.roots {
        if root.is_misc() {
            for op in &root.direct_ops {
                out.push_str(&render_op_variant(op, "    ", exchange));
            }
        } else {
            let variant = pascal_case(&root.name);
            let qualified = qualified_pascal("", &root.name);
            push_doc(out, group_doc(root), "    ");
            out.push_str(&format!("    {variant}({qualified}Args),\n"));
        }
    }
    out.push_str("}\n\n");
}

fn emit_group_types(out: &mut String, group: &TagGroup, prefix: &str, exchange: Option<&TokenExchangeInfo>) {
    if group.is_misc() {
        return;
    }
    let q = qualified_pascal(prefix, &group.name);
    let about = group_doc(group).unwrap_or_default();
    out.push_str(&format!(
        "#[derive(Args)]\n#[command(about = {})]\npub struct {q}Args {{\n    #[command(subcommand)]\n    cmd: {q}Cmd,\n}}\n\n",
        json_string(&about),
    ));

    out.push_str(&format!("#[derive(Subcommand)]\npub enum {q}Cmd {{\n"));
    for child in &group.children {
        let child_q = qualified_pascal(&q, &child.name);
        let variant = pascal_case(&child.name);
        push_doc(out, group_doc(child), "    ");
        out.push_str(&format!("    {variant}({child_q}Args),\n"));
    }
    for op in &group.direct_ops {
        out.push_str(&render_op_variant(op, "    ", exchange));
    }
    out.push_str("}\n\n");

    for child in &group.children {
        emit_group_types(out, child, &q, exchange);
    }
}

fn emit_root_match_arms(
    out: &mut String,
    root: &TagGroup,
    prefix: &str,
    oauth: Option<&OauthInfo>,
    exchange: Option<&TokenExchangeInfo>,
) {
    if root.is_misc() {
        for op in &root.direct_ops {
            out.push_str(&render_op_match_arm(op, "Cmd", "        ", oauth, exchange));
        }
        return;
    }
    let variant = pascal_case(&root.name);
    let q = qualified_pascal(prefix, &root.name);
    out.push_str(&format!("        Cmd::{variant}(__g) => match __g.cmd {{\n"));
    emit_group_match_arms(out, root, &q, "            ", oauth, exchange);
    out.push_str("        },\n");
}

fn emit_group_match_arms(
    out: &mut String,
    group: &TagGroup,
    q: &str,
    indent: &str,
    oauth: Option<&OauthInfo>,
    exchange: Option<&TokenExchangeInfo>,
) {
    let cmd_ty = format!("{q}Cmd");
    for child in &group.children {
        let child_variant = pascal_case(&child.name);
        let child_q = qualified_pascal(q, &child.name);
        out.push_str(&format!("{indent}{cmd_ty}::{child_variant}(__g) => match __g.cmd {{\n"));
        emit_group_match_arms(out, child, &child_q, &format!("{indent}    "), oauth, exchange);
        out.push_str(&format!("{indent}}},\n"));
    }
    for op in &group.direct_ops {
        out.push_str(&render_op_match_arm(op, &cmd_ty, indent, oauth, exchange));
    }
}

fn render_op_variant(op: &Operation, indent: &str, exchange: Option<&TokenExchangeInfo>) -> String {
    let variant = pascal_case(&op.id);
    let summary = first_line(op.documentation.as_deref()).unwrap_or_default();
    let mut s = String::new();
    if !summary.is_empty() {
        s.push_str(&format!("{indent}/// {}\n", escape_doc(&summary)));
    }

    let exclude = exchange
        .filter(|ex| op_uses_placeholder(op, &ex.placeholder))
        .map(|ex| ex.placeholder.as_str());
    let fields = collect_fields(op, exclude);
    if fields.is_empty() {
        s.push_str(&format!("{indent}{variant},\n"));
    } else {
        s.push_str(&format!("{indent}{variant} {{\n"));
        for f in &fields {
            if let Some(doc) = &f.doc {
                s.push_str(&format!("{indent}    /// {}\n", escape_doc(doc)));
            }
            for attr in &f.attrs {
                s.push_str(&format!("{indent}    {attr}\n"));
            }
            s.push_str(&format!("{indent}    {}: {},\n", f.ident, f.ty));
        }
        s.push_str(&format!("{indent}}},\n"));
    }
    s
}

fn render_op_match_arm(
    op: &Operation,
    cmd_ty: &str,
    indent: &str,
    oauth: Option<&OauthInfo>,
    exchange: Option<&TokenExchangeInfo>,
) -> String {
    let variant = pascal_case(&op.id);
    let method_ident = snake_case(&op.id);

    // Bearer resolution per op. Three modes:
    //   - this op references the placeholder ⇒ resolve via RFC 8693
    //     exchange (or pass `--token` through unchanged).
    //   - oauth is active but op doesn't reference the placeholder ⇒
    //     fall back to the main token (`--token` ⇒ stored ⇒ none).
    //   - oauth not active ⇒ raw `--token` flag, possibly None.
    let needs_exchange = exchange.is_some_and(|ex| op_uses_placeholder(op, &ex.placeholder));
    let exclude = if needs_exchange { exchange.map(|ex| ex.placeholder.as_str()) } else { None };

    // Fields the variant destructures — excludes the path param that
    // duplicates the global `--<placeholder>` flag.
    let destruct_fields = collect_fields(op, exclude);
    let destruct_pat = if destruct_fields.is_empty() {
        String::new()
    } else {
        format!(" {{ {} }}", destruct_fields.iter().map(|f| f.ident.as_str()).collect::<Vec<_>>().join(", "))
    };

    // Client method arg expressions — in declaration order. Path
    // params matching the placeholder are sourced from `__slug`;
    // everything else from the destructured field of the same name.
    let mut call_args: Vec<String> = vec!["__bearer.as_deref()".into()];
    for p in &op.path_params {
        let ident = snake_case(&p.name);
        if exclude.is_some_and(|ph| snake_case(ph) == ident) {
            call_args.push("__slug.clone()".into());
        } else {
            call_args.push(ident);
        }
    }
    for p in &op.query_params { call_args.push(snake_case(&p.name)); }
    for p in &op.header_params { call_args.push(snake_case(&p.name)); }
    for p in &op.cookie_params { call_args.push(snake_case(&p.name)); }
    if op.request_body.is_some() { call_args.push("body".into()); }
    let call = format!("client.{method_ident}({}).await?", call_args.join(", "));

    let pre_block = if needs_exchange {
        let ex = exchange.unwrap();
        let ph_snake = snake_case(&ex.placeholder);
        let ph_kebab = kebab_case(&ex.placeholder);
        format!(
            "let __slug: String = __resolved_{ph_snake}.clone().ok_or_else(|| \
                anyhow::anyhow!(\"--{ph_kebab} is required for this operation (or run `set-{ph_kebab} <slug>`)\"))?;\n{indent}    "
        )
    } else {
        String::new()
    };

    let bearer_block = if needs_exchange {
        let ex = exchange.unwrap();
        let aud_fmt = ex.audience_template.replace(&format!("{{{}}}", ex.placeholder), "{}");
        let res_let = match &ex.resource_template {
            Some(rt) => {
                let rt_fmt = rt.replace(&format!("{{{}}}", ex.placeholder), "{}");
                format!("Some(format!(\"{}\", __slug))", escape_rust_string(&rt_fmt))
            }
            None => "None".into(),
        };
        let scope_let = if ex.extra_scope.is_empty() {
            "None".into()
        } else {
            format!("Some(\"{}\")", escape_rust_string(&ex.extra_scope.join(" ")))
        };
        format!(
            "if let Some(t) = cli.token.clone() {{ Some(t) }} else {{ \
                let __aud = format!(\"{aud_fmt}\", __slug); \
                let __res: Option<String> = {res_let}; \
                let __scope: Option<&str> = {scope_let}; \
                auth::audience_access_token(&__aud, __res.as_deref(), __scope).await? \
            }}"
        )
    } else if oauth.is_some() {
        "if let Some(t) = cli.token.clone() { Some(t) } else { auth::access_token().await? }".into()
    } else {
        "cli.token.clone()".into()
    };

    format!(
        "{indent}{cmd_ty}::{variant}{destruct_pat} => {{\n{indent}    {pre_block}let __bearer: Option<String> = {bearer_block};\n{indent}    {call}\n{indent}}},\n",
    )
}

struct Field {
    ident: String,
    ty: String,
    doc: Option<String>,
    attrs: Vec<String>,
}

fn collect_fields(op: &Operation, exclude_path_param: Option<&str>) -> Vec<Field> {
    let mut out = Vec::new();
    let exclude_snake = exclude_path_param.map(snake_case);
    for p in &op.path_params {
        if exclude_snake.as_deref().is_some_and(|ex| ex == snake_case(&p.name)) {
            continue;
        }
        out.push(field_for_param(p, FieldKind::Positional));
    }
    for p in &op.query_params {
        out.push(field_for_param(p, FieldKind::Flag));
    }
    for p in &op.header_params {
        out.push(field_for_param(p, FieldKind::Flag));
    }
    for p in &op.cookie_params {
        out.push(field_for_param(p, FieldKind::Flag));
    }
    if let Some(body) = &op.request_body {
        out.push(field_for_body(body));
    }
    out
}

#[derive(Copy, Clone)]
enum FieldKind {
    Positional,
    Flag,
}

fn field_for_param(p: &Parameter, kind: FieldKind) -> Field {
    let ident = snake_case(&p.name);
    let (ty, attrs) = match (kind, p.required) {
        (FieldKind::Positional, _) => ("String".to_string(), vec![]),
        (FieldKind::Flag, true) => (
            "String".to_string(),
            vec![format!("#[arg(long = \"{}\")]", kebab_case(&p.name))],
        ),
        (FieldKind::Flag, false) => (
            "Option<String>".to_string(),
            vec![format!("#[arg(long = \"{}\")]", kebab_case(&p.name))],
        ),
    };
    let doc = first_line(p.documentation.as_deref());
    Field { ident, ty, doc, attrs }
}

fn field_for_body(body: &Body) -> Field {
    let ty = if body.required { "String" } else { "Option<String>" };
    Field {
        ident: "body".into(),
        ty: ty.into(),
        doc: Some("Request body: inline JSON, @file.json, or - for stdin.".into()),
        attrs: vec!["#[arg(long = \"body\")]".into()],
    }
}

fn group_doc(group: &TagGroup) -> Option<String> {
    let tag = group.tag?;
    if let Some(s) = &tag.summary {
        if !s.is_empty() {
            return Some(s.clone());
        }
    }
    first_line(tag.description.as_deref())
}

fn push_doc(out: &mut String, doc: Option<String>, indent: &str) {
    if let Some(d) = doc.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("{indent}/// {}\n", escape_doc(d)));
    }
}

fn qualified_pascal(prefix: &str, name: &str) -> String {
    format!("{prefix}{}", pascal_case(name))
}

// ---------------------------------------------------------------------------
// src/client.rs
// ---------------------------------------------------------------------------

fn emit_client_rs(ir: &Ir) -> String {
    let mut out = String::new();
    out.push_str("// Generated by openapi-forge / generator-rust-clap; do not edit by hand.\n#![allow(clippy::too_many_arguments, clippy::needless_borrow)]\n\nuse anyhow::{anyhow, Context, Result};\nuse serde_json::Value;\n\nuse crate::runtime::parse_body_arg;\n\npub struct ApiClient {\n    http: reqwest::Client,\n    base_url: String,\n}\n\nimpl ApiClient {\n    pub fn new(base_url: String) -> Result<Self> {\n        Ok(Self {\n            http: reqwest::Client::builder().build()?,\n            base_url: base_url.trim_end_matches('/').to_string(),\n        })\n    }\n\n    fn req(&self, token: Option<&str>, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {\n        let mut b = self.http.request(method, format!(\"{}{}\", self.base_url, path));\n        if let Some(t) = token { b = b.bearer_auth(t); }\n        b\n    }\n\n");

    for op in &ir.operations {
        out.push_str(&render_client_method(op));
    }

    out.push_str("}\n");
    out
}

fn render_client_method(op: &Operation) -> String {
    let method_ident = snake_case(&op.id);
    let http_method = method_path(&op.method);
    let path_template = &op.path_template;

    let mut sig_args: Vec<String> = vec!["__bearer: Option<&str>".into()];
    for p in &op.path_params {
        sig_args.push(format!("{}: String", snake_case(&p.name)));
    }
    for p in &op.query_params {
        let ident = snake_case(&p.name);
        let ty = if p.required { "String" } else { "Option<String>" };
        sig_args.push(format!("{ident}: {ty}"));
    }
    for p in &op.header_params {
        let ident = snake_case(&p.name);
        let ty = if p.required { "String" } else { "Option<String>" };
        sig_args.push(format!("{ident}: {ty}"));
    }
    for p in &op.cookie_params {
        let ident = snake_case(&p.name);
        let ty = if p.required { "String" } else { "Option<String>" };
        sig_args.push(format!("{ident}: {ty}"));
    }
    if let Some(body) = &op.request_body {
        let ty = if body.required { "String" } else { "Option<String>" };
        sig_args.push(format!("body: {ty}"));
    }
    let sig = sig_args.join(", ");

    let mut body = String::new();

    let (path_fmt, path_args) = render_path_interpolation(path_template, &op.path_params);
    if path_args.is_empty() {
        body.push_str(&format!("        let __path = String::from(\"{}\");\n", escape_rust_string(&path_fmt)));
    } else {
        body.push_str(&format!(
            "        let __path = format!(\"{}\", {});\n",
            escape_rust_string(&path_fmt),
            path_args.join(", "),
        ));
    }
    body.push_str(&format!(
        "        let mut __r = self.req(__bearer, {http_method}, &__path);\n"
    ));

    for p in &op.query_params {
        let ident = snake_case(&p.name);
        let raw = &p.name;
        if p.required {
            body.push_str(&format!(
                "        __r = __r.query(&[(\"{raw}\", &{ident})]);\n"
            ));
        } else {
            body.push_str(&format!(
                "        if let Some(v) = &{ident} {{ __r = __r.query(&[(\"{raw}\", v)]); }}\n"
            ));
        }
    }
    for p in &op.header_params {
        let ident = snake_case(&p.name);
        let raw = &p.name;
        if p.required {
            body.push_str(&format!(
                "        __r = __r.header(\"{raw}\", &{ident});\n"
            ));
        } else {
            body.push_str(&format!(
                "        if let Some(v) = &{ident} {{ __r = __r.header(\"{raw}\", v); }}\n"
            ));
        }
    }
    if !op.cookie_params.is_empty() {
        body.push_str("        let mut __cookies: Vec<String> = Vec::new();\n");
        for p in &op.cookie_params {
            let ident = snake_case(&p.name);
            let raw = &p.name;
            if p.required {
                body.push_str(&format!(
                    "        __cookies.push(format!(\"{raw}={{}}\", urlencoding::encode(&{ident})));\n"
                ));
            } else {
                body.push_str(&format!(
                    "        if let Some(v) = &{ident} {{ __cookies.push(format!(\"{raw}={{}}\", urlencoding::encode(v))); }}\n"
                ));
            }
        }
        body.push_str("        if !__cookies.is_empty() { __r = __r.header(\"Cookie\", __cookies.join(\"; \")); }\n");
    }
    if let Some(b) = &op.request_body {
        if b.required {
            body.push_str("        let __body_value = parse_body_arg(&body).context(\"--body\")?;\n");
            body.push_str("        __r = __r.json(&__body_value);\n");
        } else {
            body.push_str("        if let Some(s) = &body {\n            let v = parse_body_arg(s).context(\"--body\")?;\n            __r = __r.json(&v);\n        }\n");
        }
    }

    body.push_str("        let __resp = __r.send().await.context(\"sending request\")?;\n");
    body.push_str("        let __status = __resp.status();\n");
    body.push_str("        let __text = __resp.text().await.context(\"reading response\")?;\n");
    body.push_str("        let __json: Value = if __text.is_empty() { Value::Null } else { serde_json::from_str(&__text).unwrap_or(Value::String(__text.clone())) };\n");
    body.push_str("        if !__status.is_success() {\n            return Err(anyhow!(\"HTTP {}: {}\", __status, __json));\n        }\n");
    body.push_str("        Ok(__json)\n");

    let mut s = String::new();
    if let Some(doc) = first_line(op.documentation.as_deref()) {
        s.push_str(&format!("    /// {}\n", escape_doc(&doc)));
    }
    s.push_str(&format!("    pub async fn {method_ident}(&self, {sig}) -> Result<Value> {{\n"));
    s.push_str(&body);
    s.push_str("    }\n\n");
    s
}

fn method_path(m: &HttpMethod) -> &'static str {
    match m {
        HttpMethod::Get => "reqwest::Method::GET",
        HttpMethod::Post => "reqwest::Method::POST",
        HttpMethod::Put => "reqwest::Method::PUT",
        HttpMethod::Delete => "reqwest::Method::DELETE",
        HttpMethod::Patch => "reqwest::Method::PATCH",
        HttpMethod::Options => "reqwest::Method::OPTIONS",
        HttpMethod::Head => "reqwest::Method::HEAD",
        HttpMethod::Trace => "reqwest::Method::TRACE",
        HttpMethod::Other(_) => "reqwest::Method::GET",
    }
}

fn render_path_interpolation(template: &str, path_params: &[Parameter]) -> (String, Vec<String>) {
    let mut out_template = String::with_capacity(template.len());
    let mut args = Vec::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            for c2 in chars.by_ref() {
                if c2 == '}' {
                    break;
                }
                name.push(c2);
            }
            let ident = snake_case(&name);
            if path_params.iter().any(|p| snake_case(&p.name) == ident) {
                out_template.push_str("{}");
                args.push(format!("urlencoding::encode(&{ident})"));
            } else {
                out_template.push('{');
                out_template.push_str(&name);
                out_template.push('}');
            }
        } else if c == '}' {
            out_template.push('}');
        } else {
            out_template.push(c);
        }
    }
    (out_template, args)
}

// ---------------------------------------------------------------------------
// src/runtime.rs
// ---------------------------------------------------------------------------

fn emit_runtime_rs() -> String {
    r#"// Generated by openapi-forge / generator-rust-clap; do not edit by hand.
use anyhow::{Context, Result};
use serde_json::Value;
use std::io::Read;

pub fn parse_body_arg(s: &str) -> Result<Value> {
    if s == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).context("reading stdin")?;
        return serde_json::from_str(&buf).context("parsing stdin as JSON");
    }
    if let Some(path) = s.strip_prefix('@') {
        let buf = std::fs::read_to_string(path)
            .with_context(|| format!("reading file {path}"))?;
        return serde_json::from_str(&buf)
            .with_context(|| format!("parsing {path} as JSON"));
    }
    serde_json::from_str(s).context("parsing inline JSON")
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum OutputMode {
    Json,
    Compact,
}

pub fn print_output(v: &Value, mode: OutputMode) -> Result<()> {
    if v.is_null() {
        return Ok(());
    }
    let s = match mode {
        OutputMode::Json => serde_json::to_string_pretty(v)?,
        OutputMode::Compact => serde_json::to_string(v)?,
    };
    println!("{s}");
    Ok(())
}
"#
    .into()
}

// ---------------------------------------------------------------------------
// src/auth.rs
// ---------------------------------------------------------------------------

fn emit_auth_rs(bin_name: &str, oa: &OauthInfo) -> String {
    let auth_url = oa.flow.authorization_url.as_deref().unwrap();
    let token_url = oa.flow.token_url.as_deref().unwrap();
    let client_id = &oa.config.client_id;
    let port = oa.config.redirect_port.unwrap_or(8848);
    let scopes_lit: String = oa
        .scopes
        .iter()
        .map(|s| format!("\"{}\"", escape_rust_string(s)))
        .collect::<Vec<_>>()
        .join(", ");
    let client_secret_env = oa.config.client_secret_env.as_deref().unwrap_or("");
    let exchange_active = oa.exchange.is_some();

    let mut composed = String::with_capacity(AUTH_RS_PROLOGUE.len() + AUTH_RS_EXCHANGE_TAIL.len());
    composed.push_str(AUTH_RS_PROLOGUE);
    if exchange_active {
        composed.push_str(AUTH_RS_EXCHANGE_TAIL);
    }

    composed
        .replace("__BIN_NAME__", bin_name)
        .replace("__CLIENT_ID__", &escape_rust_string(client_id))
        .replace("__AUTH_URL__", &escape_rust_string(auth_url))
        .replace("__TOKEN_URL__", &escape_rust_string(token_url))
        .replace("__REDIRECT_PORT__", &port.to_string())
        .replace("__SCOPES__", &scopes_lit)
        .replace("__CLIENT_SECRET_ENV__", &escape_rust_string(client_secret_env))
        .replace("__PREFIX__", &env_prefix(bin_name))
}

const AUTH_RS_PROLOGUE: &str = r##"// Generated by openapi-forge / generator-rust-clap; do not edit by hand.
//! OAuth 2.0 PKCE authorization-code flow + token persistence.
//!
//! When `__CLIENT_SECRET_ENV__` resolves to a non-empty value at
//! runtime, the runtime authenticates as a confidential client via
//! `Authorization: Basic`. When unset, no client auth is sent (suitable
//! for IdPs that accept public clients).

#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::RngCore;
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN_NAME: &str = "__BIN_NAME__";
const CLIENT_ID: &str = "__CLIENT_ID__";
const AUTH_URL_DEFAULT: &str = "__AUTH_URL__";
const TOKEN_URL_DEFAULT: &str = "__TOKEN_URL__";
const AUTH_URL_ENV: &str = "__PREFIX___AUTH_URL";
const TOKEN_URL_ENV: &str = "__PREFIX___TOKEN_URL";
const REDIRECT_PORT: u16 = __REDIRECT_PORT__;
const SCOPES: &[&str] = &[__SCOPES__];
const CLIENT_SECRET_ENV: &str = "__CLIENT_SECRET_ENV__";
const REFRESH_SKEW_SECS: u64 = 30;

fn auth_endpoint() -> String {
    std::env::var(AUTH_URL_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| AUTH_URL_DEFAULT.to_string())
}

fn token_endpoint() -> String {
    std::env::var(TOKEN_URL_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| TOKEN_URL_DEFAULT.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub obtained_at: u64,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge_from(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn config_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", BIN_NAME)
        .context("computing config dir")?;
    let dir = dirs.config_dir().to_path_buf();
    std::fs::create_dir_all(&dir).context("creating config dir")?;
    Ok(dir)
}

fn token_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("auth.json"))
}

fn persisted_path(name: &str) -> Result<PathBuf> {
    let safe: String = name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    Ok(config_dir()?.join(format!("{safe}.json")))
}

pub fn read_persisted(name: &str) -> Result<Option<String>> {
    let p = persisted_path(name)?;
    if !p.exists() { return Ok(None); }
    let s = std::fs::read_to_string(&p).context("reading persisted value")?;
    let v: serde_json::Value = serde_json::from_str(&s).context("parsing persisted value")?;
    Ok(v.get("value").and_then(|x| x.as_str()).map(|x| x.to_string()))
}

pub fn write_persisted(name: &str, value: &str) -> Result<()> {
    let p = persisted_path(name)?;
    let json = serde_json::json!({ "value": value });
    let s = serde_json::to_string_pretty(&json)?;
    std::fs::write(&p, s).context("writing persisted value")?;
    set_user_only_perms(&p)?;
    Ok(())
}

pub fn delete_persisted(name: &str) -> Result<bool> {
    let p = persisted_path(name)?;
    if p.exists() {
        std::fs::remove_file(&p).context("removing persisted value")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn set_user_only_perms(_p: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(_p)?.permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(_p, perm)?;
    }
    Ok(())
}

pub fn read_stored() -> Result<Option<StoredToken>> {
    let p = token_path()?;
    if !p.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&p).context("reading auth.json")?;
    Ok(Some(serde_json::from_str(&s).context("parsing auth.json")?))
}

fn write_stored(t: &StoredToken) -> Result<()> {
    let p = token_path()?;
    let s = serde_json::to_string_pretty(t).context("serializing token")?;
    std::fs::write(&p, &s).context("writing auth.json")?;
    set_user_only_perms(&p)?;
    Ok(())
}

pub async fn logout() -> Result<bool> {
    let p = token_path()?;
    if p.exists() {
        std::fs::remove_file(&p).context("removing auth.json")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Returns the value of the configured client-secret env var, or None
/// when the env var is unset / blank.
fn client_secret() -> Option<String> {
    if CLIENT_SECRET_ENV.is_empty() {
        return None;
    }
    std::env::var(CLIENT_SECRET_ENV).ok().filter(|s| !s.is_empty())
}

/// Attaches `Authorization: Basic` to a token-endpoint request when a
/// client secret is configured. No-op for public clients.
fn maybe_client_auth(b: RequestBuilder) -> RequestBuilder {
    match client_secret() {
        Some(secret) => {
            let pair = format!("{}:{}", CLIENT_ID, secret);
            let header = format!("Basic {}", B64_STANDARD.encode(pair));
            b.header(reqwest::header::AUTHORIZATION, header)
        }
        None => b,
    }
}

pub async fn login() -> Result<StoredToken> {
    let verifier = random_verifier();
    let challenge = challenge_from(&verifier);
    let state = random_state();
    let redirect_uri = format!("http://127.0.0.1:{}/callback", REDIRECT_PORT);

    let scope_joined = SCOPES.join(" ");
    let mut params = vec![
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state.as_str()),
    ];
    if !scope_joined.is_empty() {
        params.push(("scope", scope_joined.as_str()));
    }
    let qs: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();
    let auth_base = auth_endpoint();
    let join = if auth_base.contains('?') { "&" } else { "?" };
    let auth_url = format!("{}{}{}", auth_base, join, qs.join("&"));

    eprintln!("Opening browser to authorize: {}", auth_url);
    let _ = webbrowser::open(&auth_url);
    eprintln!("(if your browser doesn't open, paste the URL above)");

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", REDIRECT_PORT))
        .await
        .with_context(|| format!("binding 127.0.0.1:{} for OAuth callback", REDIRECT_PORT))?;
    let (mut socket, _) = listener.accept().await.context("accepting OAuth callback")?;
    let mut buf = vec![0u8; 8192];
    let n = socket.read(&mut buf).await.context("reading callback request")?;
    let req = std::str::from_utf8(&buf[..n]).context("UTF-8 in callback request")?;
    let first = req.lines().next().unwrap_or("");
    let path_qs = first.split_whitespace().nth(1).unwrap_or("");
    let qs_part = path_qs.split('?').nth(1).unwrap_or("");

    let mut got_code: Option<String> = None;
    let mut got_state: Option<String> = None;
    let mut got_error: Option<String> = None;
    for kv in qs_part.split('&') {
        let mut sp = kv.splitn(2, '=');
        let k = sp.next().unwrap_or("");
        let v_raw = sp.next().unwrap_or("");
        let v = urlencoding::decode(v_raw)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| v_raw.to_string());
        match k {
            "code" => got_code = Some(v),
            "state" => got_state = Some(v),
            "error" => got_error = Some(v),
            _ => {}
        }
    }

    let html = b"<!doctype html><html><body style=\"font-family:sans-serif\"><h2>Login complete</h2><p>You can close this window.</p></body></html>";
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        html.len(),
    );
    socket.write_all(head.as_bytes()).await.ok();
    socket.write_all(html).await.ok();
    socket.shutdown().await.ok();

    if let Some(err) = got_error {
        bail!("OAuth provider returned error: {err}");
    }
    let code = got_code.ok_or_else(|| anyhow!("authorization code missing from callback"))?;
    let st = got_state.ok_or_else(|| anyhow!("state missing from callback"))?;
    if st != state {
        bail!("state mismatch (CSRF check failed)");
    }

    let http = reqwest::Client::new();
    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", "authorization_code".into()),
        ("code", code.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("code_verifier", verifier.clone()),
    ];
    if client_secret().is_none() {
        // Public client: send client_id in the body.
        form.push(("client_id", CLIENT_ID.to_string()));
    }
    let req = http.post(&token_endpoint()).form(&form);
    let req = maybe_client_auth(req);
    let resp = req.send().await.context("posting to token endpoint")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("token endpoint {status}: {body}");
    }
    let tr: TokenResponse = resp.json().await.context("parsing token response")?;

    let now = now_secs();
    let stored = StoredToken {
        access_token: tr.access_token,
        refresh_token: tr.refresh_token,
        token_type: tr.token_type.unwrap_or_else(|| "bearer".into()),
        expires_at: tr.expires_in.map(|s| now + s),
        obtained_at: now,
        scope: tr.scope,
    };
    write_stored(&stored)?;
    Ok(stored)
}

pub async fn access_token() -> Result<Option<String>> {
    let Some(t) = read_stored()? else {
        return Ok(None);
    };
    let now = now_secs();
    let needs_refresh = t
        .expires_at
        .map(|e| e.saturating_sub(REFRESH_SKEW_SECS) <= now)
        .unwrap_or(false);
    if !needs_refresh {
        return Ok(Some(t.access_token));
    }
    let Some(rt) = t.refresh_token.as_deref() else {
        return Ok(Some(t.access_token));
    };

    let http = reqwest::Client::new();
    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", rt.to_string()),
    ];
    if client_secret().is_none() {
        form.push(("client_id", CLIENT_ID.to_string()));
    }
    let req = http.post(&token_endpoint()).form(&form);
    let req = maybe_client_auth(req);
    let resp = req.send().await.context("refreshing OAuth token")?;
    if !resp.status().is_success() {
        let _ = std::fs::remove_file(token_path()?);
        return Ok(None);
    }
    let tr: TokenResponse = resp.json().await.context("parsing refresh response")?;
    let now2 = now_secs();
    let stored = StoredToken {
        access_token: tr.access_token.clone(),
        refresh_token: tr.refresh_token.or(t.refresh_token),
        token_type: tr.token_type.unwrap_or(t.token_type),
        expires_at: tr.expires_in.map(|s| now2 + s),
        obtained_at: now2,
        scope: tr.scope.or(t.scope),
    };
    write_stored(&stored)?;
    Ok(Some(stored.access_token))
}
"##;

const AUTH_RS_EXCHANGE_TAIL: &str = r##"

// ---------------------------------------------------------------------------
// RFC 8693 standard token exchange — tenant / per-audience access tokens.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use tokio::sync::Mutex;

static EXCHANGE_CACHE: tokio::sync::OnceCell<Mutex<HashMap<String, StoredToken>>> =
    tokio::sync::OnceCell::const_new();

async fn cache() -> &'static Mutex<HashMap<String, StoredToken>> {
    EXCHANGE_CACHE
        .get_or_init(|| async { Mutex::new(HashMap::new()) })
        .await
}

/// Returns a Bearer scoped to `audience`. Performs RFC 8693 standard
/// token exchange against TOKEN_URL on first use per audience and
/// caches the result in-process. Refreshes lazily on a 30s skew.
pub async fn audience_access_token(
    audience: &str,
    resource: Option<&str>,
    extra_scope: Option<&str>,
) -> Result<Option<String>> {
    {
        let map = cache().await.lock().await;
        if let Some(tok) = map.get(audience) {
            let now = now_secs();
            let stale = tok.expires_at.map(|e| e.saturating_sub(REFRESH_SKEW_SECS) <= now).unwrap_or(false);
            if !stale {
                return Ok(Some(tok.access_token.clone()));
            }
        }
    }

    let Some(subject) = access_token().await? else {
        return Ok(None);
    };

    let http = reqwest::Client::new();
    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange".into()),
        ("subject_token", subject.clone()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token".into()),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:access_token".into()),
        ("audience", audience.to_string()),
    ];
    if let Some(r) = resource {
        form.push(("resource", r.to_string()));
    }
    if let Some(sc) = extra_scope.filter(|s| !s.is_empty()) {
        form.push(("scope", sc.to_string()));
    }
    if client_secret().is_none() {
        form.push(("client_id", CLIENT_ID.to_string()));
    }
    let req = http.post(&token_endpoint()).form(&form);
    let req = maybe_client_auth(req);
    let resp = req.send().await.context("posting RFC 8693 token exchange")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "token exchange {status}: {body}\n\
             (audience={audience}; if the IdP requires client authentication, \
             set the `{}` env var to the client secret)",
            CLIENT_SECRET_ENV,
        );
    }
    let tr: TokenResponse = resp.json().await.context("parsing exchange response")?;
    let now = now_secs();
    let stored = StoredToken {
        access_token: tr.access_token.clone(),
        refresh_token: tr.refresh_token,
        token_type: tr.token_type.unwrap_or_else(|| "bearer".into()),
        expires_at: tr.expires_in.map(|s| now + s),
        obtained_at: now,
        scope: tr.scope,
    };
    let bearer = stored.access_token.clone();
    cache().await.lock().await.insert(audience.to_string(), stored);
    Ok(Some(bearer))
}
"##;

// ---------------------------------------------------------------------------
// README.md
// ---------------------------------------------------------------------------

fn emit_readme(ir: &Ir, bin_name: &str, oauth: Option<&OauthInfo>) -> String {
    let prefix = env_prefix(bin_name);
    let oauth_section = if let Some(oa) = oauth {
        let mut s = format!(
            "\n## OAuth\n\nThis CLI was generated with OAuth 2.0 (PKCE authorization-code) wired up.\n\n```sh\n{bin_name} login    # opens a browser, persists the access token\n{bin_name} logout   # deletes the stored token\n```\n\nThe token is stored at the platform config dir under `{bin_name}/auth.json` (mode 0600 on Unix).\nThe token is refreshed lazily on a 30-second skew.\n\n### Targeting a different IdP host\n\nThe authorization and token URLs from the spec are baked in as defaults. Override at runtime to point at a different environment's Keycloak / IdP:\n\n```sh\nexport {prefix}_AUTH_URL=https://auth.dev.example.com/realms/<realm>/protocol/openid-connect/auth\nexport {prefix}_TOKEN_URL=https://auth.dev.example.com/realms/<realm>/protocol/openid-connect/token\n```\n\nBoth env vars must be set together; an empty value falls back to the spec default.\n"
        );
        if let Some(env) = oa.config.client_secret_env.as_deref().filter(|s| !s.is_empty()) {
            s.push_str(&format!(
                "\nThe configured OAuth client is **confidential** — set `{env}` to the client secret in your shell before running `{bin_name} login` (or any tenant-scoped operation).\n"
            ));
        }
        if let Some(ex) = &oa.exchange {
            let kebab = kebab_case(&ex.placeholder);
            s.push_str(&format!(
                "\n## Per-`{kebab}` token exchange (RFC 8693)\n\nOperations whose path includes `{{{ph}}}` use a tenant-scoped JWT minted via standard RFC 8693 token exchange against the IdP's token endpoint.\n\n```sh\n{bin_name} --{kebab} <slug> <op>           # one-off\n{bin_name} set-{kebab} <slug>                # persist a default\n{bin_name} unset-{kebab}                     # clear it\n{bin_name} show-{kebab}                      # show the current default\n```\n",
                ph = ex.placeholder,
            ));
        }
        s
    } else {
        String::new()
    };
    format!(
        "# {bin_name}\n\nGenerated by openapi-forge / generator-rust-clap.\n\nSpec: {title} v{version}\n\nOperations: {n}\n\n## Build\n\n```sh\ncargo build --release\n```\n\n## Auth\n\nBearer token via `--token <jwt>` or the env var `{prefix}_TOKEN`.\n{oauth_section}",
        title = ir.info.title,
        version = ir.info.version,
        n = ir.operations.len(),
    )
}

fn first_line(s: Option<&str>) -> Option<String> {
    s.and_then(|s| s.lines().next()).map(|l| l.trim().to_string()).filter(|s| !s.is_empty())
}

fn escape_rust_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_doc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\r', "")
}

fn json_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_placeholders_simple() {
        assert_eq!(extract_placeholders("urn:x:tenant:{tenant}"), vec!["tenant"]);
        assert_eq!(extract_placeholders("https://api/{a}/{b}/items"), vec!["a", "b"]);
        assert_eq!(extract_placeholders("static"), Vec::<String>::new());
    }
}

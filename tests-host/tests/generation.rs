//! Host-side integration tests for the rust-clap generator plugin.
//!
//! These build the plugin to `wasm32-wasip2`, load it through the
//! `forge-host` wasmtime runtime, run `generate(ir, config)`, and
//! assert on the emitted file contents. Construct minimal `Ir`
//! values via `serde_json` rather than building each struct field
//! by hand — lots of fields default to empty.

use std::path::Path;
use std::sync::OnceLock;

use forge_host::GenerationOutput;
use forge_ir::Ir;
use forge_test_harness::PluginRunner;
use serde_json::{json, Value};

/// Build the plugin once per test run. `cargo test` executes tests
/// concurrently by default; the harness's incremental cargo build is
/// idempotent, but caching the loaded `Plugin` avoids re-loading the
/// component for every test.
fn runner() -> &'static PluginRunner {
    static RUNNER: OnceLock<PluginRunner> = OnceLock::new();
    RUNNER.get_or_init(|| {
        let plugin_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tests-host has a parent directory");
        PluginRunner::build_and_load(plugin_dir).expect("build and load plugin")
    })
}

/// Deserialize a JSON document into an `Ir`. Missing fields default
/// to empty per the IR's serde annotations, so test fixtures only
/// need to spell out the parts they care about — plus the four
/// non-default top-level fields (`operations`, `types`,
/// `security_schemes`, `servers`).
fn ir_from_json(v: Value) -> Ir {
    serde_json::from_value(v).expect("ir_from_json: deserialize Ir from fixture")
}

fn generate(ir: Ir, config: Value) -> GenerationOutput {
    runner()
        .generate(ir, config)
        .expect("plugin returned StageError")
}

fn file_named<'a>(out: &'a GenerationOutput, path: &str) -> &'a str {
    let f = out
        .files
        .iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("expected output file {path:?}, got {:?}", paths(out)));
    std::str::from_utf8(&f.content).expect("output file is UTF-8")
}

fn paths(out: &GenerationOutput) -> Vec<&str> {
    out.files.iter().map(|f| f.path.as_str()).collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// IR with a single GET operation, no body, no responses-with-content.
fn ir_minimal() -> Ir {
    ir_from_json(json!({
        "info": { "title": "Test API", "version": "1.0.0" },
        "operations": [{
            "id": "ping",
            "method": "get",
            "path_template": "/ping",
            "responses": [
                { "status": { "kind": "explicit", "code": 204 } }
            ]
        }],
        "types": [],
        "security_schemes": [],
        "servers": [{ "url": "https://example.com" }]
    }))
}

/// IR with a body-having op (POST /pets) plus a response with content.
fn ir_with_body() -> Ir {
    ir_from_json(json!({
        "info": { "title": "Pets", "version": "1.0.0" },
        "operations": [{
            "id": "createPet",
            "method": "post",
            "path_template": "/pets",
            "request_body": {
                "required": true,
                "content": [{
                    "media_type": "application/json",
                    "type": "Pet"
                }]
            },
            "responses": [
                {
                    "status": { "kind": "explicit", "code": 201 },
                    "content": [{ "media_type": "application/json", "type": "Pet" }]
                },
                {
                    "status": { "kind": "explicit", "code": 400 },
                    "content": [{ "media_type": "application/json", "type": "Error" }]
                }
            ]
        }],
        "types": [
            {
                "id": "Pet",
                "definition": {
                    "def": "object",
                    "properties": [
                        { "name": "id",   "type": "Pet.id",   "required": true },
                        { "name": "name", "type": "Pet.name", "required": true }
                    ],
                    "additional_properties": { "kind": "forbidden" },
                    "constraints": {}
                }
            },
            {
                "id": "Pet.id",
                "definition": { "def": "primitive", "kind": "string", "constraints": {} }
            },
            {
                "id": "Pet.name",
                "definition": { "def": "primitive", "kind": "string", "constraints": {} }
            },
            {
                "id": "Error",
                "definition": {
                    "def": "object",
                    "properties": [
                        { "name": "message", "type": "Error.message", "required": true }
                    ],
                    "additional_properties": { "kind": "any" },
                    "constraints": {}
                }
            },
            {
                "id": "Error.message",
                "definition": { "def": "primitive", "kind": "string", "constraints": {} }
            }
        ],
        "security_schemes": [],
        "servers": [{ "url": "https://example.com" }]
    }))
}

/// IR with a recursive type — body whose schema references itself.
fn ir_recursive_type() -> Ir {
    ir_from_json(json!({
        "info": { "title": "Tree", "version": "1.0.0" },
        "operations": [{
            "id": "addNode",
            "method": "post",
            "path_template": "/nodes",
            "request_body": {
                "required": true,
                "content": [{ "media_type": "application/json", "type": "Node" }]
            },
            "responses": []
        }],
        "types": [
            {
                "id": "Node",
                "definition": {
                    "def": "object",
                    "properties": [
                        { "name": "name",     "type": "Node.name",     "required": true },
                        { "name": "children", "type": "Node.children", "required": false }
                    ],
                    "additional_properties": { "kind": "forbidden" },
                    "constraints": {}
                }
            },
            {
                "id": "Node.name",
                "definition": { "def": "primitive", "kind": "string", "constraints": {} }
            },
            {
                "id": "Node.children",
                "definition": {
                    "def": "array",
                    "items": "Node",
                    "constraints": {}
                }
            }
        ],
        "security_schemes": [],
        "servers": [{ "url": "https://example.com" }]
    }))
}

/// IR with a path-positional + a body — exercises the schema-flag
/// relaxation regression.
fn ir_path_param_with_body() -> Ir {
    ir_from_json(json!({
        "info": { "title": "Files", "version": "1.0.0" },
        "operations": [{
            "id": "editFile",
            "method": "put",
            "path_template": "/files/{file_name}",
            "path_params": [
                { "name": "file_name", "type": "FileName", "required": true }
            ],
            "request_body": {
                "required": true,
                "content": [{ "media_type": "application/json", "type": "FileBody" }]
            },
            "responses": []
        }],
        "types": [
            {
                "id": "FileName",
                "definition": { "def": "primitive", "kind": "string", "constraints": {} }
            },
            {
                "id": "FileBody",
                "definition": { "def": "primitive", "kind": "string", "constraints": {} }
            }
        ],
        "security_schemes": [],
        "servers": [{ "url": "https://example.com" }]
    }))
}

/// IR with OAuth2 + an `x-token-exchange` extension on the scheme,
/// plus a tenant-scoped op. Drives the long_about's auth + tenancy
/// sections.
fn ir_oauth_with_tenancy() -> Ir {
    ir_from_json(json!({
        "info": { "title": "Multi", "version": "1.0.0" },
        "operations": [{
            "id": "listThings",
            "method": "get",
            "path_template": "/org/{tenant}/things",
            "path_params": [
                { "name": "tenant", "type": "Tenant", "required": true }
            ],
            "security": [
                { "scheme_id": "oauth", "scopes": ["openid"] }
            ],
            "responses": []
        }],
        "types": [{
            "id": "Tenant",
            "definition": { "def": "primitive", "kind": "string", "constraints": {} }
        }],
        "security_schemes": [{
            "id": "oauth",
            "kind": {
                "type": "oauth2",
                "flows": [{
                    "kind": "authorization-code",
                    "authorization_url": "https://auth.example/authorize",
                    "token_url": "https://auth.example/token",
                    "scopes": [["openid", "OpenID"]]
                }]
            },
            "extensions": [
                ["x-token-exchange", 0]
            ]
        }],
        "servers": [{ "url": "https://example.com" }],
        "values": [
            { "kind": "object", "fields": [
                ["audience-template", 1]
            ]},
            { "kind": "string", "value": "urn:test:tenant:{tenant}" }
        ]
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn smoke_minimal_spec_emits_expected_file_set() {
    let out = generate(ir_minimal(), json!({}));
    let names: Vec<&str> = paths(&out);
    for expected in &[
        "Cargo.toml",
        "src/main.rs",
        "src/client.rs",
        "src/runtime.rs",
        "README.md",
    ] {
        assert!(
            names.contains(expected),
            "missing {expected:?} in output: {names:?}"
        );
    }
    assert!(
        out.diagnostics.is_empty(),
        "unexpected diagnostics: {:?}",
        out.diagnostics
    );
}

#[test]
fn body_schema_constant_is_emitted_when_op_has_a_body() {
    let out = generate(ir_with_body(), json!({}));
    let main_rs = file_named(&out, "src/main.rs");
    assert!(
        main_rs.contains("const BODY_SCHEMA_CREATE_PET"),
        "expected BODY_SCHEMA_CREATE_PET constant in main.rs"
    );
    // Sanity: the constant carries a JSON Schema preamble.
    assert!(main_rs.contains("https://json-schema.org/draft/2020-12/schema"));
}

#[test]
fn response_schema_is_a_flat_status_keyed_map() {
    let out = generate(ir_with_body(), json!({}));
    let main_rs = file_named(&out, "src/main.rs");
    assert!(
        main_rs.contains("const RESPONSE_SCHEMA_CREATE_PET"),
        "expected RESPONSE_SCHEMA_CREATE_PET constant in main.rs"
    );
    // Top-level keys are status codes + $defs, not wrapped under "properties".
    // Embedded literal escapes newlines; assert the key strings appear.
    assert!(main_rs.contains("\\\"201\\\""));
    assert!(main_rs.contains("\\\"400\\\""));
    // No wrapper "type": "object" sitting above the status map.
    let resp_const = main_rs
        .split("RESPONSE_SCHEMA_CREATE_PET")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .unwrap_or("");
    // The flat-map form means the substring `"type": "object"` only appears
    // for nested per-status schemas, not at the root.
    let outer_type_object = resp_const.matches("\\\"type\\\": \\\"object\\\"").count();
    let status_count = 2; // 201, 400
    assert!(
        outer_type_object <= status_count,
        "looks like the response-schema regained its wrapper schema: {outer_type_object} occurrences"
    );
}

#[test]
fn required_path_positional_relaxes_when_schema_flag_present() {
    // Regression: the bug that prompted v0.0.14. Required positionals
    // need `required_unless_present_any = ["body_schema"]` (or
    // `"response_schema"`) so `--body-schema` short-circuits before
    // clap rejects the missing positional.
    let out = generate(ir_path_param_with_body(), json!({}));
    let main_rs = file_named(&out, "src/main.rs");
    assert!(
        main_rs.contains("required_unless_present_any"),
        "expected required_unless_present_any on a positional with --body-schema"
    );
    assert!(
        main_rs.contains("\"body_schema\""),
        "expected body_schema in the unless list"
    );
    // Variant body should unwrap with .expect on the API call branch.
    assert!(
        main_rs.contains("file_name.expect"),
        "expected file_name.expect(...) on the API-call branch"
    );
}

#[test]
fn recursive_type_uses_dollar_ref_in_body_schema() {
    let out = generate(ir_recursive_type(), json!({}));
    let main_rs = file_named(&out, "src/main.rs");
    // The body schema for `Node` (which contains a Node[] in `children`)
    // should resolve recursion via $defs / $ref rather than blowing up
    // the schema or stack-overflowing the renderer.
    assert!(
        main_rs.contains("BODY_SCHEMA_ADD_NODE"),
        "expected BODY_SCHEMA_ADD_NODE constant"
    );
    let const_blob = main_rs
        .split("BODY_SCHEMA_ADD_NODE")
        .nth(1)
        .and_then(|s| s.split("const ").next())
        .unwrap_or(main_rs);
    assert!(
        const_blob.contains("$ref") && const_blob.contains("$defs"),
        "expected $ref + $defs in recursive body schema"
    );
}

#[test]
fn long_about_includes_oauth_and_tenancy_when_active() {
    let out = generate(
        ir_oauth_with_tenancy(),
        json!({ "oauth": { "clientId": "test" } }),
    );
    let main_rs = file_named(&out, "src/main.rs");
    assert!(
        main_rs.contains("Authentication and profiles"),
        "long_about should mention auth/profiles when OAuth is active"
    );
    assert!(
        main_rs.contains("Multi-tenant operations"),
        "long_about should mention tenancy when x-token-exchange is present"
    );
    assert!(
        main_rs.contains("set-tenant"),
        "long_about should reference the set-tenant helper for the placeholder"
    );
}

#[test]
fn long_about_omits_oauth_section_when_oauth_is_off() {
    let out = generate(ir_minimal(), json!({}));
    let main_rs = file_named(&out, "src/main.rs");
    assert!(
        !main_rs.contains("Authentication and profiles"),
        "long_about should not mention auth/profiles when OAuth is inactive"
    );
    assert!(
        !main_rs.contains("Multi-tenant operations"),
        "long_about should not mention tenancy when no x-token-exchange"
    );
}

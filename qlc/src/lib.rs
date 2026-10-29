//! `qlc` is the front end of the credential query language compiler
//! described in `dashboard-src/DESIGN.md`, sections 3 and 4.
//!
//! The pipeline has six stages, one module each:
//!
//! 1. [`lexer`] and [`parser`] turn source text into an [`ast::Formula`].
//! 2. [`desugar`] removes `->`, `Active` and `SameHolder`.
//! 3. [`nnf`] pushes negation to the leaves and records every rewrite step.
//! 4. [`classify`] decides the class (monotone, antitone, non-monotone or
//!    state-independent), the footprint, the interference table, the
//!    contract requirement and the warnings.
//! 5. [`plan`] builds the proof plan.
//! 6. [`json`] serialises the result.
//!
//! Call [`compile`] from Rust. From JavaScript, use the exported functions
//! `qlc_alloc`, `qlc_compile`, `qlc_result_free` and `qlc_free`; README.md
//! has a loader.

pub mod ast;
pub mod classify;
pub mod desugar;
pub mod error;
pub mod json;
pub mod lexer;
pub mod nnf;
pub mod parser;
pub mod plan;

use ast::Formula;
use classify::Classification;
use error::CompileError;
use json::Json;
use nnf::RewriteStep;
use plan::PlanNode;

/// The result of a successful compilation. [`Output::result`] holds this.
#[derive(Clone, Debug)]
pub struct Compiled {
    /// The formula as parsed.
    pub ast: Formula,
    /// The formula after desugaring.
    pub desugared: Formula,
    /// The formula in negation normal form.
    pub nnf: Formula,
    /// The desugaring steps followed by the negation-normal-form steps.
    pub rewrite_steps: Vec<RewriteStep>,
    pub classification: Classification,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    pub plan: PlanNode,
}

/// What [`compile`] returns: either the compiled query or the first error.
#[derive(Clone, Debug)]
pub struct Output {
    pub result: Result<Compiled, CompileError>,
}

/// Compiles a query. This function does not panic on any input; syntax and
/// scope errors are returned inside the [`Output`].
pub fn compile(src: &str) -> Output {
    Output { result: run(src) }
}

fn run(src: &str) -> Result<Compiled, CompileError> {
    let ast = parser::parse(src)?;
    let mut rewrite_steps = Vec::new();
    let mut notes = Vec::new();
    let mut warnings = Vec::new();
    let desugared = desugar::desugar(&ast, &mut rewrite_steps, &mut notes);
    let nnf = nnf::to_nnf(&desugared, &mut rewrite_steps, &mut warnings);
    let classification = classify::classify(&nnf);
    let (lint_warnings, lint_notes) = classify::lint(&nnf, &classification);
    warnings.extend(lint_warnings);
    notes.extend(lint_notes);
    let plan = plan::plan(&nnf);
    Ok(Compiled { ast, desugared, nnf, rewrite_steps, classification, warnings, notes, plan })
}

impl Output {
    /// True when the query compiled.
    pub fn ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Builds the JSON value documented in README.md. On an error the shape
    /// is the same: strings are empty, lists are empty and trees are `null`.
    pub fn to_json_value(&self) -> Json {
        match &self.result {
            Ok(c) => {
                let k = &c.classification;
                Json::obj(vec![
                    ("ok", Json::Bool(true)),
                    ("error", Json::Null),
                    ("source_pretty", Json::str(&c.ast.pretty())),
                    ("ast", c.ast.to_tree()),
                    ("desugared_pretty", Json::str(&c.desugared.pretty())),
                    ("nnf_pretty", Json::str(&c.nnf.pretty())),
                    ("nnf", c.nnf.to_tree()),
                    ("rewrite_steps", Json::Arr(c.rewrite_steps.iter().map(RewriteStep::to_json).collect())),
                    ("class", Json::str(k.class.text())),
                    ("class_gloss", Json::str(k.class.gloss())),
                    ("explanation", Json::str(&k.explanation)),
                    ("polarity", Json::Arr(k.occurrences.iter().map(|o| o.to_json()).collect())),
                    ("footprint", Json::strs(&k.footprint)),
                    (
                        "interference",
                        Json::Arr(
                            k.interference
                                .iter()
                                .map(|r| {
                                    Json::obj(vec![
                                        ("update", Json::str(r.update)),
                                        ("can_falsify", Json::Bool(r.can_falsify)),
                                        ("why", Json::str(&r.why)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                    ("contract", Json::obj(vec![("mode", Json::str(k.contract.mode)), ("detail", Json::str(&k.contract.detail))])),
                    ("warnings", Json::strs(&c.warnings)),
                    ("notes", Json::strs(&c.notes)),
                    ("plan", c.plan.to_json()),
                ])
            }
            Err(e) => error_json(e),
        }
    }

    /// Serialises the output to the JSON text documented in README.md.
    pub fn to_json(&self) -> String {
        self.to_json_value().write()
    }
}

/// The error form of the output, with the same keys as the success form.
fn error_json(e: &CompileError) -> Json {
    let empty = || Json::str("");
    Json::obj(vec![
        ("ok", Json::Bool(false)),
        ("error", e.to_json()),
        ("source_pretty", empty()),
        ("ast", Json::Null),
        ("desugared_pretty", empty()),
        ("nnf_pretty", empty()),
        ("nnf", Json::Null),
        ("rewrite_steps", Json::Arr(vec![])),
        ("class", empty()),
        ("class_gloss", empty()),
        ("explanation", empty()),
        ("polarity", Json::Arr(vec![])),
        ("footprint", Json::Arr(vec![])),
        ("interference", Json::Arr(vec![])),
        ("contract", Json::obj(vec![("mode", empty()), ("detail", empty())])),
        ("warnings", Json::Arr(vec![])),
        ("notes", Json::Arr(vec![])),
        ("plan", Json::Null),
    ])
}

// ---------------------------------------------------------------------------
// The C ABI used from WebAssembly. No wasm-bindgen is involved: the host
// copies the query into memory obtained from `qlc_alloc`, calls
// `qlc_compile`, reads the length-prefixed JSON, and frees both buffers.
// ---------------------------------------------------------------------------

/// Allocates `len` bytes that the host fills with the UTF-8 query. Release
/// the buffer with [`qlc_free`] and the same `len`.
#[no_mangle]
pub extern "C" fn qlc_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Frees a buffer obtained from [`qlc_alloc`].
///
/// # Safety
/// `ptr` must come from `qlc_alloc(len)` with the same `len` and must not be
/// used afterwards.
#[no_mangle]
pub unsafe extern "C" fn qlc_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
    }
}

/// Compiles the UTF-8 query at `ptr..ptr+len`. Returns a buffer whose first
/// four bytes are the little-endian `u32` length of the UTF-8 JSON that
/// follows. Invalid UTF-8 produces an error JSON, not a trap. Release the
/// result with [`qlc_result_free`].
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or `len` must be 0.
#[no_mangle]
pub unsafe extern "C" fn qlc_compile(ptr: *const u8, len: usize) -> *mut u8 {
    let bytes: &[u8] = if ptr.is_null() || len == 0 { &[] } else { std::slice::from_raw_parts(ptr, len) };
    let json = match std::str::from_utf8(bytes) {
        Ok(src) => compile(src).to_json(),
        Err(e) => {
            let err = CompileError {
                message: format!("the query is not valid UTF-8 (first bad byte at offset {})", e.valid_up_to()),
                line: 1,
                col: 1,
                excerpt: String::new(),
            };
            error_json(&err).write()
        }
    };
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(json.as_bytes());
    Box::into_raw(out.into_boxed_slice()) as *mut u8
}

/// Frees a buffer returned by [`qlc_compile`].
///
/// # Safety
/// `ptr` must come from `qlc_compile` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn qlc_result_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let mut len_bytes = [0u8; 4];
    std::ptr::copy_nonoverlapping(ptr, len_bytes.as_mut_ptr(), 4);
    let total = 4 + u32::from_le_bytes(len_bytes) as usize;
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, total)));
}

#[cfg(test)]
mod tests;

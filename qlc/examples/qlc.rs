//! A command-line front end for the compiler.
//!
//! ```text
//! cargo run --example qlc -- 'forall x in S. NotRevoked(x)'
//! echo 'exists x in S. Revoked(x)' | cargo run --example qlc
//! ```
//!
//! The query is taken from the arguments, joined with spaces. Without
//! arguments it is read from standard input. The JSON goes to standard
//! output and the exit code is 1 when the query has an error.

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let src = if args.is_empty() {
        let mut text = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut text) {
            eprintln!("cannot read standard input: {}", e);
            std::process::exit(2);
        }
        text
    } else {
        args.join(" ")
    };
    let out = qlc::compile(&src);
    println!("{}", out.to_json());
    if let Err(e) = &out.result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

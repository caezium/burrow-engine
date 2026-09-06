//! `burrow-engine` — the engine's own binary. A thin shim over `burrow_engine::cli::dispatch`: it
//! turns argv into a Burrow envelope on stdout and the matching process exit code. All logic lives
//! in the library (so it's unit-tested); this file just wires stdin/args → stdout/exit.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, code) = burrow_engine::cli::dispatch(&args);
    // Streaming commands (e.g. `clean --stream`) print their own NDJSON and return an empty buffer;
    // don't emit a trailing blank line for them.
    if !out.is_empty() {
        println!("{out}");
    }
    std::process::exit(code);
}

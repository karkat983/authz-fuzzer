//! The `authz` command-line scanner.
//!
//! ```text
//! authz discover --spec openapi.json
//! authz plan     --manifest scan.json
//! authz scan     --manifest scan.json --sarif out.sarif --json out.json --events out.jsonl
//! ```
//!
//! `scan` exits 0 when the CI gate passes and 2 when it fails, so it can gate a pipeline.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use authz_cli::manifest::Manifest;
use authz_cli::{discover_only, events, plan_only, run_scan};
use authz_exec::EnvSecretStore;
use authz_http::ReqwestTransport;

/// Authorized API authorization tester (the Lattivant AuthZ Fuzzer).
#[derive(Parser)]
#[command(name = "authz", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse an OpenAPI document and list the operations discovered.
    Discover {
        /// Path to the OpenAPI JSON document.
        #[arg(long)]
        spec: PathBuf,
    },
    /// Plan the probes a scan would run, without sending any request.
    Plan {
        /// Path to the scan manifest.
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Run a scan against the target described by the manifest.
    Scan {
        /// Path to the scan manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Write a SARIF 2.1.0 report here.
        #[arg(long)]
        sarif: Option<PathBuf>,
        /// Write the JSON findings report here.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Write findings as common-envelope events (JSON lines) here.
        #[arg(long)]
        events: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::Discover { spec } => {
            let spec_json = read(&spec)?;
            let (registry, report) = discover_only(&spec_json).context("discovery failed")?;
            println!("discovered {} operations:", registry.len());
            for op in registry.iter() {
                let refs: Vec<&str> = op.object_references().map(|p| p.name.as_str()).collect();
                println!(
                    "  {:7} {:30} class={:<10} refs=[{}]",
                    op.key.method,
                    op.key.normalized_path,
                    op.resource_class.0,
                    refs.join(", ")
                );
            }
            if !report.is_clean() {
                println!("\n{} discovery warning(s):", report.warnings.len());
                for w in &report.warnings {
                    println!("  - {w}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Plan { manifest } => {
            let m = load_manifest(&manifest)?;
            let spec_json = read(&spec_path(&manifest, &m))?;
            let lines = plan_only(&m, &spec_json).context("planning failed")?;
            println!("{} probe(s) planned:", lines.len());
            for l in lines {
                println!("  {l}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan {
            manifest,
            sarif,
            json,
            events: events_path,
        } => {
            let m = load_manifest(&manifest)?;
            let spec_json = read(&spec_path(&manifest, &m))?;
            let transport = Arc::new(
                ReqwestTransport::new(m.request_timeout_ms)
                    .map_err(|e| anyhow::anyhow!("building HTTP client: {e}"))?,
            );
            let secrets = Arc::new(EnvSecretStore);

            let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
            let results = runtime
                .block_on(run_scan(&m, &spec_json, transport, secrets))
                .context("scan failed")?;

            println!("{}", results.report.headline());
            for f in results.report.findings.iter() {
                println!(
                    "  [{:?}/{:?}] {} {} — {}",
                    f.severity, f.confidence, f.operation.method, f.operation.normalized_path, f.summary
                );
            }
            if !results.summary.notes.is_empty() {
                println!("notes:");
                for n in &results.summary.notes {
                    println!("  - {n}");
                }
            }

            if let Some(path) = sarif {
                write(&path, &authz_findings::to_sarif(&results.findings, env!("CARGO_PKG_VERSION")))?;
                println!("wrote SARIF to {}", path.display());
            }
            if let Some(path) = json {
                write(&path, &results.report.to_json())?;
                println!("wrote JSON report to {}", path.display());
            }
            if let Some(path) = events_path {
                let jsonl = events::findings_as_jsonl(&results.report.findings, &m.target.name)
                    .map_err(|e| anyhow::anyhow!("building events: {e}"))?;
                write(&path, &jsonl)?;
                println!("wrote events to {}", path.display());
            }

            println!(
                "gate: {} ({} of {} finding(s) above threshold)",
                if results.gate.passed { "pass" } else { "FAIL" },
                results.gate.failing_count,
                results.gate.total_count
            );
            Ok(ExitCode::from(results.gate.exit_code() as u8))
        }
    }
}

/// Read a file to a string.
fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Write a string to a file.
fn write(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Load and parse a manifest.
fn load_manifest(path: &Path) -> Result<Manifest> {
    let json = read(path)?;
    Manifest::from_json(&json).with_context(|| format!("parsing manifest {}", path.display()))
}

/// Resolve the spec path, interpreting a relative path against the manifest's directory.
fn spec_path(manifest_path: &Path, manifest: &Manifest) -> PathBuf {
    let spec = PathBuf::from(&manifest.spec);
    if spec.is_absolute() {
        spec
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(spec)
    }
}

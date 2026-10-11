//! Run the reference orders API as a standalone server.
//!
//! ```text
//! authz-target --port 8080 --vuln none        # correctly authorized
//! authz-target --port 8080 --vuln bola-read   # leaks any order to any authenticated caller
//! ```
//!
//! Bearer tokens: `tok-alpha-admin`, `tok-alpha-viewer`, `tok-bravo-admin`.

use std::net::SocketAddr;

use clap::Parser;

use authz_target::{serve, Vulnerability};

#[derive(Parser)]
#[command(name = "authz-target", about)]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value_t = 8080)]
    port: u16,
    /// Vulnerability mode: none | bola-read | bola-write | missing-auth | shared-write.
    #[arg(long, default_value = "none")]
    vuln: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let vulnerability = Vulnerability::parse(&args.vuln).unwrap_or_else(|| {
        eprintln!("unknown --vuln {:?}; using 'none'", args.vuln);
        Vulnerability::None
    });
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let (bound, guard) = serve(addr, vulnerability).await?;
    println!("reference orders API on http://{bound} (mode: {:?})", vulnerability);
    println!("tokens: tok-alpha-admin, tok-alpha-viewer, tok-bravo-admin");
    // Run until Ctrl-C.
    let _ = tokio::signal::ctrl_c().await;
    guard.stop().await;
    Ok(())
}

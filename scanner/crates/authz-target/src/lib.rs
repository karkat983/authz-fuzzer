//! A reference multi-tenant orders API used to validate the scanner.
//!
//! In [`state::Vulnerability::None`] the API is correctly authorized and a scan must find
//! nothing. Each other mode reintroduces one classic authorization bug (cross-tenant read,
//! cross-tenant write, missing authentication, writable shared resource), and a scan must
//! find exactly that weakness. This is the integrated lab's self-check, runnable entirely
//! in-process with no external services.

pub mod app;
pub mod spec;
pub mod state;

pub use app::build_app;
pub use spec::openapi_json;
pub use state::{AppState, Order, Principal, Vulnerability};

use std::net::SocketAddr;

/// Bind to `addr` and serve the API in the given vulnerability mode until the returned
/// handle is dropped. Returns the bound address (useful when binding to port 0) and a
/// shutdown-on-drop guard.
pub async fn serve(
    addr: SocketAddr,
    vulnerability: Vulnerability,
) -> std::io::Result<(SocketAddr, ServerGuard)> {
    let state = AppState::seeded(vulnerability);
    serve_state(addr, state).await
}

/// Like [`serve`] but with a caller-provided state (e.g. a pre-shared order).
pub async fn serve_state(
    addr: SocketAddr,
    state: AppState,
) -> std::io::Result<(SocketAddr, ServerGuard)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let app = build_app(state);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = rx.await;
        });
        let _ = server.await;
    });
    Ok((local, ServerGuard { shutdown: Some(tx), handle }))
}

/// Shuts the server down when dropped.
pub struct ServerGuard {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl ServerGuard {
    /// Explicitly stop the server and wait for it to finish.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.handle).await;
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.handle.abort();
    }
}

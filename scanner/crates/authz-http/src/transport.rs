//! The [`Transport`] trait and its backends.
//!
//! [`Transport`] abstracts "send a request, get a response" so the oracle and executor can
//! be exercised against a deterministic [`MockTransport`] in tests and the real
//! [`ReqwestTransport`] in production — the oracle logic never changes between the two.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use async_trait::async_trait;
use thiserror::Error;

use authz_core::HttpMethod;

use crate::request::{HttpRequest, HttpResponse};

/// Errors a transport can return.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The request URL was malformed.
    #[error("invalid URL {url:?}: {reason}")]
    InvalidUrl {
        /// The offending URL.
        url: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A network or protocol error occurred.
    #[error("transport error: {0}")]
    Network(String),
    /// The mock had no canned response for the request.
    #[error("no mock response for {method} {url}")]
    NoMock {
        /// The method that was not mocked.
        method: HttpMethod,
        /// The URL that was not mocked.
        url: String,
    },
    /// The request timed out.
    #[error("request timed out after {0} ms")]
    Timeout(u64),
}

/// Sends HTTP requests.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a request and return the response.
    async fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// A real HTTP transport backed by reqwest with rustls.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with the given per-request timeout in milliseconds.
    pub fn new(timeout_ms: u64) -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            // Do not follow redirects: an out-of-scope redirect must surface as a 3xx, not
            // be chased to a host the scope never approved.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| TransportError::Network(e.to_string()))?;
        Ok(ReqwestTransport { client })
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
            .map_err(|e| TransportError::Network(e.to_string()))?;
        let mut builder = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }
        let start = Instant::now();
        let resp = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                TransportError::Timeout(start.elapsed().as_millis() as u64)
            } else {
                TransportError::Network(e.to_string())
            }
        })?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
            elapsed_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// A deterministic in-memory transport for tests.
///
/// Responses are keyed by `"METHOD URL"`. A fallback may be set to answer any unmatched
/// request; without one, an unmatched request is a [`TransportError::NoMock`]. The mock
/// records every request it receives, so tests can assert on what the scanner sent.
#[derive(Default)]
pub struct MockTransport {
    responses: Mutex<HashMap<String, HttpResponse>>,
    fallback: Mutex<Option<HttpResponse>>,
    received: Mutex<Vec<HttpRequest>>,
}

impl MockTransport {
    /// An empty mock.
    pub fn new() -> Self {
        MockTransport::default()
    }

    /// Program a canned response for a method and URL.
    pub fn on(&self, method: HttpMethod, url: &str, response: HttpResponse) -> &Self {
        self.responses
            .lock()
            .unwrap()
            .insert(key(method, url), response);
        self
    }

    /// Program a fallback response used for any unmatched request.
    pub fn fallback(&self, response: HttpResponse) -> &Self {
        *self.fallback.lock().unwrap() = Some(response);
        self
    }

    /// The requests the mock has received, in order.
    pub fn received(&self) -> Vec<HttpRequest> {
        self.received.lock().unwrap().clone()
    }

    /// How many requests the mock has received.
    pub fn request_count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

fn key(method: HttpMethod, url: &str) -> String {
    format!("{method} {url}")
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError> {
        self.received.lock().unwrap().push(req.clone());
        if let Some(resp) = self.responses.lock().unwrap().get(&key(req.method, &req.url)) {
            return Ok(resp.clone());
        }
        if let Some(resp) = self.fallback.lock().unwrap().clone() {
            return Ok(resp);
        }
        Err(TransportError::NoMock {
            method: req.method,
            url: req.url.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_programmed_response_and_records_request() {
        let mock = MockTransport::new();
        mock.on(
            HttpMethod::Get,
            "https://x/orders/1",
            HttpResponse::new(200, r#"{"id":1}"#),
        );
        let req = HttpRequest::new(HttpMethod::Get, "https://x/orders/1").as_identity("alpha");
        let resp = mock.send(&req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(mock.request_count(), 1);
        assert_eq!(mock.received()[0].identity_id.as_deref(), Some("alpha"));
    }

    #[tokio::test]
    async fn unmatched_without_fallback_is_an_error() {
        let mock = MockTransport::new();
        let req = HttpRequest::new(HttpMethod::Delete, "https://x/orders/1");
        assert!(matches!(
            mock.send(&req).await,
            Err(TransportError::NoMock { .. })
        ));
    }

    #[tokio::test]
    async fn fallback_answers_unmatched() {
        let mock = MockTransport::new();
        mock.fallback(HttpResponse::new(404, ""));
        let req = HttpRequest::new(HttpMethod::Get, "https://x/anything");
        assert_eq!(mock.send(&req).await.unwrap().status, 404);
    }

    #[test]
    fn reqwest_transport_builds() {
        assert!(ReqwestTransport::new(5000).is_ok());
    }
}

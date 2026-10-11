//! The axum application: routes and authorization logic for the reference orders API.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use crate::spec::openapi_json;
use crate::state::{AppState, Order, Principal, Vulnerability};

/// Build the router for a given state.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/openapi.json", get(openapi))
        .route("/orders", post(create_order))
        .route(
            "/orders/:id",
            get(get_order).patch(patch_order).delete(delete_order),
        )
        .with_state(state)
}

async fn openapi() -> Json<Value> {
    Json(openapi_json())
}

/// Resolve the bearer principal from the Authorization header.
fn principal(state: &AppState, headers: &HeaderMap) -> Option<Principal> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))?;
    state.principal(token)
}

/// Whether `who` may read `order` under the configured vulnerability mode.
fn can_read(state: &AppState, who: &Option<Principal>, order: &Order) -> bool {
    match state.vulnerability {
        Vulnerability::MissingAuth => true, // no authentication required (the bug)
        Vulnerability::BolaRead => who.is_some(), // any authenticated caller (the bug)
        _ => match who {
            None => false,
            Some(p) => p.tenant == order.owner_tenant || order.shared_with.contains(&p.tenant),
        },
    }
}

/// Whether `who` may write `order` under the configured vulnerability mode.
fn can_write(state: &AppState, who: &Option<Principal>, order: &Order) -> bool {
    match (state.vulnerability, who) {
        (_, None) => false,
        (Vulnerability::BolaWrite, Some(_)) => true, // any authenticated caller (the bug)
        (Vulnerability::SharedWrite, Some(p)) => {
            // sharing should be read-only; this mode lets a grantee write (the bug)
            p.tenant == order.owner_tenant || order.shared_with.contains(&p.tenant)
        }
        (_, Some(p)) => p.tenant == order.owner_tenant,
    }
}

async fn get_order(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let who = principal(&state, &headers);
    let Some(order) = state.order(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})));
    };
    if can_read(&state, &who, &order) {
        (StatusCode::OK, Json(order.view()))
    } else if who.is_none() {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})))
    } else {
        (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"})))
    }
}

async fn patch_order(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let who = principal(&state, &headers);
    let Some(order) = state.order(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})));
    };
    if !can_write(&state, &who, &order) {
        return deny(&who);
    }
    let status = body
        .and_then(|Json(v)| v.get("status").and_then(Value::as_str).map(String::from))
        .unwrap_or_else(|| "cancelled".to_string());
    let updated = state.set_status(&id, &status).expect("order exists");
    (StatusCode::OK, Json(updated.view()))
}

async fn delete_order(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let who = principal(&state, &headers);
    let Some(order) = state.order(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})));
    };
    if !can_write(&state, &who, &order) {
        return deny(&who);
    }
    state.delete(&id);
    (StatusCode::NO_CONTENT, Json(json!(null)))
}

async fn create_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let Some(p) = principal(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    };
    let note = body
        .and_then(|Json(v)| v.get("note").and_then(Value::as_str).map(String::from))
        .unwrap_or_default();
    let order = state.create(&p.tenant, &note);
    (StatusCode::CREATED, Json(order.view()))
}

fn deny(who: &Option<Principal>) -> (StatusCode, Json<Value>) {
    if who.is_none() {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})))
    } else {
        (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"})))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(tenant: &str) -> Option<Principal> {
        Some(Principal {
            tenant: tenant.into(),
            admin: false,
        })
    }

    fn order() -> Order {
        Order {
            id: "order-1".into(),
            owner_tenant: "alpha".into(),
            status: "open".into(),
            note: "x".into(),
            shared_with: vec![],
        }
    }

    #[test]
    fn hardened_read_authorization() {
        let s = AppState::seeded(Vulnerability::None);
        assert!(can_read(&s, &p("alpha"), &order())); // owner
        assert!(!can_read(&s, &p("bravo"), &order())); // cross-tenant
        assert!(!can_read(&s, &None, &order())); // unauthenticated
    }

    #[test]
    fn bola_read_mode_leaks_to_any_authenticated() {
        let s = AppState::seeded(Vulnerability::BolaRead);
        assert!(can_read(&s, &p("bravo"), &order()));
        assert!(!can_read(&s, &None, &order())); // still needs a token
    }

    #[test]
    fn missing_auth_mode_leaks_to_anyone() {
        let s = AppState::seeded(Vulnerability::MissingAuth);
        assert!(can_read(&s, &None, &order()));
    }

    #[test]
    fn hardened_write_is_owner_only() {
        let s = AppState::seeded(Vulnerability::None);
        assert!(can_write(&s, &p("alpha"), &order()));
        assert!(!can_write(&s, &p("bravo"), &order()));
    }

    #[test]
    fn bola_write_mode_lets_cross_tenant_write() {
        let s = AppState::seeded(Vulnerability::BolaWrite);
        assert!(can_write(&s, &p("bravo"), &order()));
    }

    #[test]
    fn shared_write_mode_lets_grantee_write() {
        let s = AppState::seeded(Vulnerability::SharedWrite);
        let mut o = order();
        o.shared_with.push("bravo".into());
        assert!(can_write(&s, &p("bravo"), &o));
        // a non-grantee cross-tenant caller still cannot
        assert!(!can_write(&s, &p("charlie"), &o));
    }
}

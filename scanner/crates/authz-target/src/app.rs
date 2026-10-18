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
    if order.public {
        return true; // a public order is readable by anyone (legitimate)
    }
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
        // viewers are read-only; a same-tenant admin may write any order (legitimate)
        (Vulnerability::AdminLegit, Some(p)) => p.tenant == order.owner_tenant && p.admin,
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
    } else if who.is_some() && state.vulnerability == Vulnerability::Leaky404 {
        // "not found" on the status line, the owner's order in the body (the bug)
        (StatusCode::NOT_FOUND, Json(order.view()))
    } else if who.is_none() {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
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
    let status = body
        .and_then(|Json(v)| v.get("status").and_then(Value::as_str).map(String::from))
        .unwrap_or_else(|| "cancelled".to_string());
    if !can_write(&state, &who, &order) {
        if who.is_some() {
            match state.vulnerability {
                // denied on the status line, applied anyway (the bug)
                Vulnerability::SilentWrite => {
                    state.set_status(&id, &status);
                }
                // success on the status line, nothing applied (the lie)
                Vulnerability::LyingSuccess => {
                    let mut claimed = order.clone();
                    claimed.status = status;
                    return (StatusCode::OK, Json(claimed.view()));
                }
                _ => {}
            }
        }
        return deny(&who);
    }
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
        if who.is_some() {
            match state.vulnerability {
                Vulnerability::SilentWrite => {
                    state.delete(&id);
                }
                Vulnerability::LyingSuccess => return (StatusCode::NO_CONTENT, Json(json!(null))),
                _ => {}
            }
        }
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
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        );
    };
    let note = body
        .and_then(|Json(v)| v.get("note").and_then(Value::as_str).map(String::from))
        .unwrap_or_default();
    let order = state.create(&p.tenant, &note);
    (StatusCode::CREATED, Json(order.view()))
}

fn deny(who: &Option<Principal>) -> (StatusCode, Json<Value>) {
    if who.is_none() {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
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
            public: false,
        }
    }

    #[test]
    fn public_order_is_readable_cross_tenant_and_unauth() {
        let s = AppState::seeded(Vulnerability::None);
        let mut o = order();
        o.public = true;
        assert!(can_read(&s, &p("bravo"), &o)); // cross-tenant read of public order
        assert!(can_read(&s, &None, &o)); // even unauthenticated
    }

    #[test]
    fn shared_order_is_readable_by_grantee_but_not_writable_hardened() {
        let s = AppState::seeded(Vulnerability::None);
        let mut o = order();
        o.shared_with.push("bravo".into());
        assert!(can_read(&s, &p("bravo"), &o)); // delegated read is legitimate
        assert!(!can_write(&s, &p("bravo"), &o)); // sharing is read-only when hardened
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

    fn admin(tenant: &str) -> Option<Principal> {
        Some(Principal {
            tenant: tenant.into(),
            admin: true,
        })
    }

    #[test]
    fn admin_legit_mode_lets_only_same_tenant_admins_write() {
        let s = AppState::seeded(Vulnerability::AdminLegit);
        assert!(can_write(&s, &admin("alpha"), &order()));
        assert!(!can_write(&s, &p("alpha"), &order())); // a viewer is read-only
        assert!(!can_write(&s, &admin("bravo"), &order())); // cross-tenant admin
        assert!(can_read(&s, &p("alpha"), &order()));
    }

    #[test]
    fn status_vs_effect_modes_keep_hardened_policy() {
        // the bugs are in what the handlers *do* with a denial, not in the policy itself
        for mode in [
            Vulnerability::SilentWrite,
            Vulnerability::LyingSuccess,
            Vulnerability::Leaky404,
        ] {
            let s = AppState::seeded(mode);
            assert!(!can_write(&s, &p("bravo"), &order()));
            assert!(!can_read(&s, &p("bravo"), &order()));
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    fn patch_body() -> Option<Json<Value>> {
        Some(Json(json!({"status": "cancelled"})))
    }

    #[tokio::test]
    async fn silent_write_answers_403_but_applies_the_change() {
        let s = AppState::seeded(Vulnerability::SilentWrite);
        let (code, _) = patch_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-bravo-admin"),
            patch_body(),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert_eq!(s.order("order-1").unwrap().status, "cancelled"); // applied anyway
        let (code, _) = delete_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-bravo-admin"),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert!(s.order("order-1").is_none()); // deleted anyway
    }

    #[tokio::test]
    async fn lying_success_answers_2xx_but_changes_nothing() {
        let s = AppState::seeded(Vulnerability::LyingSuccess);
        let (code, Json(body)) = patch_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-bravo-admin"),
            patch_body(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "cancelled"); // claims the change
        assert_eq!(s.order("order-1").unwrap().status, "open"); // but nothing changed
        let (code, _) = delete_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-bravo-admin"),
        )
        .await;
        assert_eq!(code, StatusCode::NO_CONTENT);
        assert!(s.order("order-1").is_some());
        // the owner's own write still works
        let (code, _) = patch_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-alpha-admin"),
            patch_body(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(s.order("order-1").unwrap().status, "cancelled");
    }

    #[tokio::test]
    async fn admin_legit_applies_admin_writes_and_denies_viewers() {
        let s = AppState::seeded(Vulnerability::AdminLegit);
        let (code, _) = patch_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-alpha-viewer"),
            patch_body(),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert_eq!(s.order("order-1").unwrap().status, "open");
        let (code, _) = patch_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-alpha-admin"),
            patch_body(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(s.order("order-1").unwrap().status, "cancelled");
    }

    #[tokio::test]
    async fn leaky_404_returns_the_owners_order_under_a_404() {
        let s = AppState::seeded(Vulnerability::Leaky404);
        let (_, Json(owner_view)) = get_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-alpha-admin"),
        )
        .await;
        let (code, Json(body)) = get_order(
            State(s.clone()),
            Path("order-1".into()),
            bearer("tok-bravo-admin"),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert_eq!(body, owner_view);
        // unauthenticated callers still get a plain 401
        let (code, _) = get_order(State(s), Path("order-1".into()), HeaderMap::new()).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
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

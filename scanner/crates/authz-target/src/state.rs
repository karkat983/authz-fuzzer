//! The in-memory state of the reference orders API.
//!
//! The server is deliberately small but *correct* in its hardened mode, and offers a set of
//! [`Vulnerability`] modes that each reintroduce one classic authorization bug. The scanner
//! must find nothing in [`Vulnerability::None`] and must find the specific weakness in each
//! other mode — the self-check the integrated-lab spec requires.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// An authorization weakness the target can be configured to exhibit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vulnerability {
    /// Correctly authorized. The scanner must find nothing.
    None,
    /// GET skips the tenant/ownership check: any authenticated caller reads any order.
    BolaRead,
    /// PATCH/DELETE skip the tenant/ownership check: any authenticated caller writes any order.
    BolaWrite,
    /// GET requires no authentication: anyone reads any order.
    MissingAuth,
    /// A shared resource is writable by the grantee (sharing should be read-only).
    SharedWrite,
}

impl Vulnerability {
    /// Parse from a CLI string.
    pub fn parse(s: &str) -> Option<Vulnerability> {
        match s {
            "none" => Some(Vulnerability::None),
            "bola-read" => Some(Vulnerability::BolaRead),
            "bola-write" => Some(Vulnerability::BolaWrite),
            "missing-auth" => Some(Vulnerability::MissingAuth),
            "shared-write" => Some(Vulnerability::SharedWrite),
            _ => None,
        }
    }
}

/// A test principal recognized by the server, keyed by bearer token.
#[derive(Clone, Debug)]
pub struct Principal {
    /// The principal's tenant.
    pub tenant: String,
    /// Whether the principal is a tenant admin.
    pub admin: bool,
}

/// One order resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    /// The order id.
    pub id: String,
    /// The tenant that owns it.
    pub owner_tenant: String,
    /// A mutable status field.
    pub status: String,
    /// Free-form note.
    pub note: String,
    /// Tenants this order is shared with (read access).
    #[serde(default)]
    pub shared_with: Vec<String>,
}

impl Order {
    /// The public JSON view of the order (what a GET returns).
    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "owner": self.owner_tenant,
            "status": self.status,
            "note": self.note,
        })
    }
}

/// Shared server state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<Inner>>,
    /// The configured vulnerability mode.
    pub vulnerability: Vulnerability,
}

struct Inner {
    tokens: HashMap<String, Principal>,
    orders: HashMap<String, Order>,
    next_id: u64,
}

impl AppState {
    /// A state seeded with the standard lab identities and one alpha-owned order, in the
    /// given vulnerability mode.
    pub fn seeded(vulnerability: Vulnerability) -> Self {
        let mut tokens = HashMap::new();
        tokens.insert("tok-alpha-admin".into(), Principal { tenant: "alpha".into(), admin: true });
        tokens.insert("tok-alpha-viewer".into(), Principal { tenant: "alpha".into(), admin: false });
        tokens.insert("tok-bravo-admin".into(), Principal { tenant: "bravo".into(), admin: true });

        let mut orders = HashMap::new();
        orders.insert(
            "order-1".into(),
            Order {
                id: "order-1".into(),
                owner_tenant: "alpha".into(),
                status: "open".into(),
                note: "alpha private order".into(),
                shared_with: Vec::new(),
            },
        );
        AppState {
            inner: Arc::new(Mutex::new(Inner {
                tokens,
                orders,
                next_id: 2,
            })),
            vulnerability,
        }
    }

    /// Resolve a bearer token to a principal.
    pub fn principal(&self, token: &str) -> Option<Principal> {
        self.inner.lock().unwrap().tokens.get(token).cloned()
    }

    /// Fetch an order by id.
    pub fn order(&self, id: &str) -> Option<Order> {
        self.inner.lock().unwrap().orders.get(id).cloned()
    }

    /// Replace an order's status, returning the updated order.
    pub fn set_status(&self, id: &str, status: &str) -> Option<Order> {
        let mut inner = self.inner.lock().unwrap();
        let order = inner.orders.get_mut(id)?;
        order.status = status.to_string();
        Some(order.clone())
    }

    /// Delete an order.
    pub fn delete(&self, id: &str) -> bool {
        self.inner.lock().unwrap().orders.remove(id).is_some()
    }

    /// Create a new order owned by `tenant`, returning it.
    pub fn create(&self, tenant: &str, note: &str) -> Order {
        let mut inner = self.inner.lock().unwrap();
        let id = format!("order-{}", inner.next_id);
        inner.next_id += 1;
        let order = Order {
            id: id.clone(),
            owner_tenant: tenant.to_string(),
            status: "open".into(),
            note: note.to_string(),
            shared_with: Vec::new(),
        };
        inner.orders.insert(id, order.clone());
        order
    }

    /// Share an order with a tenant (read access).
    pub fn share(&self, id: &str, tenant: &str) {
        if let Some(o) = self.inner.lock().unwrap().orders.get_mut(id) {
            if !o.shared_with.contains(&tenant.to_string()) {
                o.shared_with.push(tenant.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerability_parse() {
        assert_eq!(Vulnerability::parse("none"), Some(Vulnerability::None));
        assert_eq!(Vulnerability::parse("bola-read"), Some(Vulnerability::BolaRead));
        assert_eq!(Vulnerability::parse("nonsense"), None);
    }

    #[test]
    fn seeded_state_has_identities_and_order() {
        let s = AppState::seeded(Vulnerability::None);
        assert_eq!(s.principal("tok-alpha-admin").unwrap().tenant, "alpha");
        assert!(s.principal("tok-bravo-admin").unwrap().admin);
        assert!(s.principal("unknown").is_none());
        assert_eq!(s.order("order-1").unwrap().owner_tenant, "alpha");
    }

    #[test]
    fn mutations_work() {
        let s = AppState::seeded(Vulnerability::None);
        assert_eq!(s.set_status("order-1", "cancelled").unwrap().status, "cancelled");
        let created = s.create("bravo", "note");
        assert_eq!(created.owner_tenant, "bravo");
        assert!(s.delete(&created.id));
        assert!(!s.delete("missing"));
    }
}

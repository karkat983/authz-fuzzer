//! The operation registry produced by discovery.

use indexmap::IndexMap;

use authz_core::{HttpMethod, Operation, OperationKey};

/// A deduplicated, queryable set of discovered operations.
///
/// Operations are keyed by [`OperationKey`]; adding an operation whose key already exists
/// replaces the earlier one (the later discovery wins), so re-running discovery over a
/// revised spec is idempotent.
#[derive(Debug, Default, Clone)]
pub struct OperationRegistry {
    operations: IndexMap<OperationKey, Operation>,
}

impl OperationRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        OperationRegistry::default()
    }

    /// Insert or replace an operation. Returns the previous operation at that key, if any.
    pub fn insert(&mut self, op: Operation) -> Option<Operation> {
        self.operations.insert(op.key.clone(), op)
    }

    /// Number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Look up an operation by key.
    pub fn get(&self, key: &OperationKey) -> Option<&Operation> {
        self.operations.get(key)
    }

    /// Iterate over all operations in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Operation> {
        self.operations.values()
    }

    /// Operations that take at least one object-reference parameter — the authorization
    /// testing targets.
    pub fn with_object_references(&self) -> impl Iterator<Item = &Operation> {
        self.iter().filter(|op| op.object_references().next().is_some())
    }

    /// Operations that create resources, usable to seed owned fixtures.
    pub fn creators(&self) -> impl Iterator<Item = &Operation> {
        self.iter().filter(|op| op.creates_resource)
    }

    /// Operations using the given HTTP method.
    pub fn with_method(&self, method: HttpMethod) -> impl Iterator<Item = &Operation> {
        self.iter().filter(move |op| op.key.method == method)
    }

    /// A stable, sorted list of the normalized paths present.
    pub fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .iter()
            .map(|op| op.key.normalized_path.clone())
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{Operation, ParamLocation, Parameter, ResourceClass};

    fn op(method: HttpMethod, path: &str, creates: bool, with_ref: bool) -> Operation {
        let key = OperationKey::new(method, path, "1.0").unwrap();
        let resource_class = ResourceClass::from_path(&key.normalized_path);
        let params = if with_ref {
            vec![Parameter::new("id", ParamLocation::Path).object_reference()]
        } else {
            vec![]
        };
        Operation {
            key,
            raw_path: path.into(),
            operation_id: None,
            parameters: params,
            security: vec![],
            resource_class,
            ownership: vec![],
            creates_resource: creates,
        }
    }

    #[test]
    fn insert_dedupes_by_key() {
        let mut r = OperationRegistry::new();
        assert!(r.insert(op(HttpMethod::Get, "/orders/{id}", false, true)).is_none());
        // same key (different param name normalizes equal) replaces
        let prev = r.insert(op(HttpMethod::Get, "/orders/{orderId}", false, true));
        assert!(prev.is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn filters() {
        let mut r = OperationRegistry::new();
        r.insert(op(HttpMethod::Get, "/orders/{id}", false, true));
        r.insert(op(HttpMethod::Post, "/orders", true, false));
        r.insert(op(HttpMethod::Get, "/health", false, false));
        assert_eq!(r.with_object_references().count(), 1);
        assert_eq!(r.creators().count(), 1);
        assert_eq!(r.with_method(HttpMethod::Get).count(), 2);
        assert_eq!(r.paths(), vec!["/health", "/orders", "/orders/{}"]);
    }
}

//! The OpenAPI document the reference target serves at `/openapi.json`.
//!
//! The scanner discovers operations from exactly this document, so keeping it next to the
//! handlers means discovery and the server never drift apart.

use serde_json::{json, Value};

/// The OpenAPI 3.0 document describing the orders API.
pub fn openapi_json() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Reference Orders API", "version": "1.0.0"},
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"}
            }
        },
        "security": [{"bearer": []}],
        "paths": {
            "/orders": {
                "post": {
                    "operationId": "createOrder",
                    "requestBody": {
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {"note": {"type": "string"}}
                        }}}
                    }
                }
            },
            "/orders/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
                ],
                "get": {"operationId": "getOrder"},
                "patch": {
                    "operationId": "patchOrder",
                    "requestBody": {
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {"status": {"type": "string"}}
                        }}}
                    }
                },
                "delete": {"operationId": "deleteOrder"}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_is_well_formed_and_has_the_instance_operations() {
        let spec = openapi_json();
        assert_eq!(spec["openapi"], "3.0.3");
        let item = &spec["paths"]["/orders/{id}"];
        assert!(item["get"].is_object());
        assert!(item["patch"].is_object());
        assert!(item["delete"].is_object());
    }
}

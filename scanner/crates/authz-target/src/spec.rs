//! The OpenAPI document the reference target serves at `/openapi.json`.
//!
//! The scanner discovers operations from exactly this document, so keeping it next to the
//! handlers means discovery and the server never drift apart.

use serde_json::{json, Value};

/// The OpenAPI 3.0 document describing the orders API.
pub fn openapi_json() -> Value {
    // Response schemas let any client (including generic fuzzers) see that `POST /orders`
    // produces the `id` that `/orders/{id}` consumes.
    let order = json!({"$ref": "#/components/schemas/Order"});
    let error = json!({"$ref": "#/components/schemas/Error"});
    let body = |schema: &Value, description: &str| json!({"description": description, "content": {"application/json": {"schema": schema}}});
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Reference Orders API", "version": "1.0.0"},
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"}
            },
            "schemas": {
                "Order": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "owner": {"type": "string"},
                        "status": {"type": "string"},
                        "note": {"type": "string"}
                    },
                    "required": ["id", "owner", "status", "note"]
                },
                "Error": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}},
                    "required": ["error"]
                }
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
                    },
                    "responses": {
                        "201": body(&order, "created"),
                        "401": body(&error, "unauthenticated")
                    }
                }
            },
            "/orders/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
                ],
                "get": {
                    "operationId": "getOrder",
                    "responses": {
                        "200": body(&order, "the order"),
                        "401": body(&error, "unauthenticated"),
                        "403": body(&error, "forbidden"),
                        "404": body(&error, "not found")
                    }
                },
                "patch": {
                    "operationId": "patchOrder",
                    "requestBody": {
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {"status": {"type": "string"}}
                        }}}
                    },
                    "responses": {
                        "200": body(&order, "the updated order"),
                        "401": body(&error, "unauthenticated"),
                        "403": body(&error, "forbidden"),
                        "404": body(&error, "not found")
                    }
                },
                "delete": {
                    "operationId": "deleteOrder",
                    "responses": {
                        "204": {"description": "deleted"},
                        "401": body(&error, "unauthenticated"),
                        "403": body(&error, "forbidden"),
                        "404": body(&error, "not found")
                    }
                }
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

    #[test]
    fn every_operation_documents_its_responses_and_create_returns_an_id() {
        let spec = openapi_json();
        for (path, method) in [
            ("/orders", "post"),
            ("/orders/{id}", "get"),
            ("/orders/{id}", "patch"),
            ("/orders/{id}", "delete"),
        ] {
            assert!(
                spec["paths"][path][method]["responses"].is_object(),
                "{method} {path}"
            );
        }
        let created = &spec["paths"]["/orders"]["post"]["responses"]["201"];
        assert_eq!(
            created["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Order"
        );
        assert_eq!(
            spec["components"]["schemas"]["Order"]["properties"]["id"]["type"],
            "string"
        );
    }
}

//! The common event envelope.
//!
//! All three Lattivant engines (AuthZ, AgentTrace, EastWest) emit events in this shared
//! shape so the platform can normalize and correlate them. The AuthZ Fuzzer emits
//! `authz.request` and `authz.finding` events; this module defines the envelope and the
//! builder the executor uses.
//!
//! The envelope distinguishes **event time** (`timestamp`, when the thing happened) from
//! **ingestion time** (`observed_at`, when the collector saw it), and separates *observed*
//! facts from *inferred* ones via the [`Assertion`] kind — both requirements from the
//! platform event-schema spec.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::SCHEMA_VERSION;

/// What kind of principal performed the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// The scanner acting as a test identity.
    Scanner,
    /// A human user.
    Human,
    /// A service account.
    Service,
    /// An AI agent (used by AgentTrace; included for a shared vocabulary).
    AiAgent,
}

/// The actor that performed an event's action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The kind of actor.
    #[serde(rename = "type")]
    pub kind: ActorKind,
    /// A non-secret identifier for the actor (e.g. the test identity id).
    pub id: String,
}

/// Whether a fact in the event is directly observed or inferred by the producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assertion {
    /// Directly observed (e.g. an HTTP response the scanner received).
    Observed,
    /// Inferred by the producer (e.g. an oracle's conclusion).
    Inferred,
}

/// The outcome of an event's action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventOutcome {
    /// A short status string, e.g. "success", "denied", "error".
    pub status: String,
    /// Optional numeric detail, e.g. an HTTP status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i64>,
}

/// Where an event came from, so every record is traceable to its collector and raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The collector/engine that produced the event.
    pub collector: String,
    /// A content-addressed reference to the raw evidence, if stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
    /// Whether the event's core claim is observed or inferred.
    pub assertion: Assertion,
}

/// The common event envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The schema version of this envelope.
    pub schema_version: String,
    /// A unique event id.
    pub event_id: String,
    /// The owning tenant.
    pub tenant_id: String,
    /// A dotted event type, e.g. `authz.request`.
    pub event_type: String,
    /// Which engine produced it.
    pub source_engine: String,
    /// When the thing happened (event time).
    pub timestamp: DateTime<Utc>,
    /// When the collector observed it (ingestion time).
    pub observed_at: DateTime<Utc>,
    /// The acting principal.
    pub actor: Actor,
    /// A free-form action descriptor, e.g. `{"type":"api_request","name":"get_order"}`.
    pub action: IndexMap<String, String>,
    /// A free-form target descriptor, e.g. `{"type":"api_resource","id":"order-42"}`.
    pub target: IndexMap<String, String>,
    /// The outcome.
    pub outcome: EventOutcome,
    /// Provenance.
    pub provenance: Provenance,
    /// Optional trace id linking this to a distributed trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Optional parent event ids, for correlation.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub parent_event_ids: Vec<String>,
}

impl Event {
    /// Start building an event of the given type for a tenant.
    pub fn builder(event_type: impl Into<String>, tenant_id: impl Into<String>) -> EventBuilder {
        EventBuilder {
            event_type: event_type.into(),
            tenant_id: tenant_id.into(),
            source_engine: "authz".into(),
            timestamp: None,
            observed_at: None,
            actor: None,
            action: IndexMap::new(),
            target: IndexMap::new(),
            outcome: None,
            raw_ref: None,
            assertion: Assertion::Observed,
            trace_id: None,
            parents: Vec::new(),
            event_id: None,
        }
    }

    /// Validate the envelope's required fields are non-empty and times are coherent.
    pub fn validate(&self) -> Result<(), String> {
        if self.tenant_id.is_empty() {
            return Err("tenant_id is empty".into());
        }
        if self.event_id.is_empty() {
            return Err("event_id is empty".into());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {:?}",
                self.schema_version
            ));
        }
        if self.observed_at < self.timestamp {
            return Err("observed_at precedes timestamp".into());
        }
        Ok(())
    }
}

/// Builds an [`Event`] with required fields enforced at `build` time.
pub struct EventBuilder {
    event_type: String,
    tenant_id: String,
    source_engine: String,
    timestamp: Option<DateTime<Utc>>,
    observed_at: Option<DateTime<Utc>>,
    actor: Option<Actor>,
    action: IndexMap<String, String>,
    target: IndexMap<String, String>,
    outcome: Option<EventOutcome>,
    raw_ref: Option<String>,
    assertion: Assertion,
    trace_id: Option<String>,
    parents: Vec<String>,
    event_id: Option<String>,
}

impl EventBuilder {
    /// Set the acting principal.
    pub fn actor(mut self, kind: ActorKind, id: impl Into<String>) -> Self {
        self.actor = Some(Actor { kind, id: id.into() });
        self
    }

    /// Set the event time (defaults to now at build).
    pub fn timestamp(mut self, t: DateTime<Utc>) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// Set the ingestion time (defaults to the event time at build).
    pub fn observed_at(mut self, t: DateTime<Utc>) -> Self {
        self.observed_at = Some(t);
        self
    }

    /// Add an `action` field.
    pub fn action(mut self, key: &str, value: impl Into<String>) -> Self {
        self.action.insert(key.to_string(), value.into());
        self
    }

    /// Add a `target` field.
    pub fn target(mut self, key: &str, value: impl Into<String>) -> Self {
        self.target.insert(key.to_string(), value.into());
        self
    }

    /// Set the outcome.
    pub fn outcome(mut self, status: impl Into<String>, code: Option<i64>) -> Self {
        self.outcome = Some(EventOutcome {
            status: status.into(),
            code,
        });
        self
    }

    /// Set the raw evidence reference.
    pub fn raw_ref(mut self, uri: impl Into<String>) -> Self {
        self.raw_ref = Some(uri.into());
        self
    }

    /// Mark the event's core claim as inferred rather than observed.
    pub fn inferred(mut self) -> Self {
        self.assertion = Assertion::Inferred;
        self
    }

    /// Attach a trace id.
    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    /// Attach a parent event id.
    pub fn parent(mut self, id: impl Into<String>) -> Self {
        self.parents.push(id.into());
        self
    }

    /// Set an explicit event id (otherwise one is generated from the fields).
    pub fn event_id(mut self, id: impl Into<String>) -> Self {
        self.event_id = Some(id.into());
        self
    }

    /// Finish building. Requires an actor and an outcome; fills timestamps with `now`.
    pub fn build(self) -> Result<Event, String> {
        let actor = self.actor.ok_or("event requires an actor")?;
        let outcome = self.outcome.ok_or("event requires an outcome")?;
        let timestamp = self.timestamp.unwrap_or_else(Utc::now);
        let observed_at = self.observed_at.unwrap_or(timestamp);
        let event_id = self.event_id.unwrap_or_else(|| {
            let fp = crate::fingerprint::Fingerprint::builder()
                .field(&self.event_type)
                .field(&self.tenant_id)
                .field(&actor.id)
                .field(&timestamp.to_rfc3339())
                .finish();
            format!("evt-{}", &fp.to_hex()[..16])
        });
        let event = Event {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id,
            tenant_id: self.tenant_id,
            event_type: self.event_type,
            source_engine: self.source_engine,
            timestamp,
            observed_at,
            actor,
            action: self.action,
            target: self.target,
            outcome,
            provenance: Provenance {
                collector: "authz".into(),
                raw_ref: self.raw_ref,
                assertion: self.assertion,
            },
            trace_id: self.trace_id,
            parent_event_ids: self.parents,
        };
        event.validate()?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_valid_event() {
        let e = Event::builder("authz.request", "alpha")
            .actor(ActorKind::Scanner, "alpha-admin")
            .action("type", "api_request")
            .action("name", "get_order")
            .target("type", "api_resource")
            .target("id", "order-42")
            .outcome("denied", Some(403))
            .build()
            .unwrap();
        assert_eq!(e.schema_version, SCHEMA_VERSION);
        assert!(e.event_id.starts_with("evt-"));
        assert_eq!(e.outcome.code, Some(403));
        assert_eq!(e.provenance.assertion, Assertion::Observed);
        assert_eq!(e.observed_at, e.timestamp);
    }

    #[test]
    fn missing_actor_or_outcome_fails() {
        let no_actor = Event::builder("authz.request", "alpha")
            .outcome("ok", None)
            .build();
        assert!(no_actor.is_err());
        let no_outcome = Event::builder("authz.request", "alpha")
            .actor(ActorKind::Scanner, "x")
            .build();
        assert!(no_outcome.is_err());
    }

    #[test]
    fn observed_at_before_timestamp_is_invalid() {
        let t = Utc::now();
        let earlier = t - chrono::Duration::seconds(5);
        let e = Event::builder("authz.request", "alpha")
            .actor(ActorKind::Scanner, "x")
            .outcome("ok", None)
            .timestamp(t)
            .observed_at(earlier)
            .build();
        assert!(e.is_err());
    }

    #[test]
    fn inferred_assertion_is_recorded() {
        let e = Event::builder("authz.finding", "alpha")
            .actor(ActorKind::Scanner, "x")
            .outcome("verified", None)
            .inferred()
            .build()
            .unwrap();
        assert_eq!(e.provenance.assertion, Assertion::Inferred);
    }

    #[test]
    fn serializes_to_json_with_expected_keys() {
        let e = Event::builder("authz.request", "alpha")
            .actor(ActorKind::Scanner, "alpha-admin")
            .outcome("success", Some(200))
            .build()
            .unwrap();
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["event_type"], "authz.request");
        assert_eq!(v["source_engine"], "authz");
        assert!(v["provenance"]["collector"].is_string());
        // empty parent list is omitted
        assert!(v.get("parent_event_ids").is_none());
    }

    #[test]
    fn same_inputs_give_stable_event_id() {
        let t = Utc::now();
        let make = || {
            Event::builder("authz.request", "alpha")
                .actor(ActorKind::Scanner, "x")
                .outcome("ok", None)
                .timestamp(t)
                .build()
                .unwrap()
                .event_id
        };
        assert_eq!(make(), make());
    }
}

use core::fmt;

use nostr::{Event, Filter, SubscriptionId};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use thiserror::Error;

/// Resource limits applied before a client message reaches relay logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimits {
    pub max_frame_bytes: usize,
    pub max_subscription_id_bytes: usize,
    pub max_filters_per_req: usize,
}

/// A supported Nostr client message whose outer wire shape has been validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictClientMessage {
    Event(Event),
    Req {
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    },
    Close(SubscriptionId),
    Auth(Event),
}

/// A client message rejected at the relay's wire boundary.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("frame contains {actual} bytes, exceeding the {max}-byte limit")]
    FrameTooLarge { actual: usize, max: usize },
    #[error("frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("frame is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("client message must be a JSON array beginning with a message name")]
    InvalidEnvelope,
    #[error("unsupported client message: {0}")]
    UnsupportedMessage(String),
    #[error("invalid {message} message shape")]
    InvalidMessageShape { message: &'static str },
    #[error("invalid event: {0}")]
    InvalidEvent(#[source] serde_json::Error),
    #[error("event contains unknown top-level field {field}")]
    UnknownEventField { field: String },
    #[error("subscription ID length {actual} is outside 1..={max} bytes")]
    InvalidSubscriptionId { actual: usize, max: usize },
    #[error("REQ filter count {actual} is outside 1..={max}")]
    InvalidFilterCount { actual: usize, max: usize },
    #[error("filter {index} contains unknown top-level field {field}")]
    UnknownFilterField { index: usize, field: String },
    #[error("filter {index} field {field} has an invalid JSON type")]
    InvalidFilterField { index: usize, field: String },
    #[error("filter {index} is invalid: {source}")]
    InvalidFilter {
        index: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// Parse one complete Nostr client message using a strict, bounded wire grammar.
pub fn parse_client_message(
    raw: &[u8],
    limits: &WireLimits,
) -> Result<StrictClientMessage, WireError> {
    if raw.len() > limits.max_frame_bytes {
        return Err(WireError::FrameTooLarge {
            actual: raw.len(),
            max: limits.max_frame_bytes,
        });
    }
    core::str::from_utf8(raw).map_err(|_| WireError::InvalidUtf8)?;

    let UniqueValue(value) = serde_json::from_slice(raw).map_err(WireError::InvalidJson)?;
    let values = value.as_array().ok_or(WireError::InvalidEnvelope)?;
    let message_name = values
        .first()
        .and_then(Value::as_str)
        .ok_or(WireError::InvalidEnvelope)?;

    match message_name {
        "EVENT" => parse_event_message(values, false),
        "REQ" => parse_req_message(values, limits),
        "CLOSE" => parse_close_message(values, limits),
        "AUTH" => parse_event_message(values, true),
        other => Err(WireError::UnsupportedMessage(other.to_owned())),
    }
}

fn parse_event_message(values: &[Value], is_auth: bool) -> Result<StrictClientMessage, WireError> {
    let message = if is_auth { "AUTH" } else { "EVENT" };
    if values.len() != 2 || !values[1].is_object() {
        return Err(WireError::InvalidMessageShape { message });
    }
    validate_event_fields(values[1].as_object().expect("object checked above"))?;
    let event = serde_json::from_value(values[1].clone()).map_err(WireError::InvalidEvent)?;
    if is_auth {
        Ok(StrictClientMessage::Auth(event))
    } else {
        Ok(StrictClientMessage::Event(event))
    }
}

fn parse_req_message(
    values: &[Value],
    limits: &WireLimits,
) -> Result<StrictClientMessage, WireError> {
    if values.len() < 2 {
        return Err(WireError::InvalidMessageShape { message: "REQ" });
    }
    let subscription_id = parse_subscription_id(&values[1], limits, "REQ")?;
    let filter_count = values.len().saturating_sub(2);
    if filter_count == 0 || filter_count > limits.max_filters_per_req {
        return Err(WireError::InvalidFilterCount {
            actual: filter_count,
            max: limits.max_filters_per_req,
        });
    }

    let filters = values[2..]
        .iter()
        .enumerate()
        .map(|(index, value)| parse_filter(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StrictClientMessage::Req {
        subscription_id,
        filters,
    })
}

fn parse_close_message(
    values: &[Value],
    limits: &WireLimits,
) -> Result<StrictClientMessage, WireError> {
    if values.len() != 2 {
        return Err(WireError::InvalidMessageShape { message: "CLOSE" });
    }
    parse_subscription_id(&values[1], limits, "CLOSE").map(StrictClientMessage::Close)
}

fn parse_subscription_id(
    value: &Value,
    limits: &WireLimits,
    message: &'static str,
) -> Result<SubscriptionId, WireError> {
    let id = value
        .as_str()
        .ok_or(WireError::InvalidMessageShape { message })?;
    let actual = id.len();
    if actual == 0 || actual > limits.max_subscription_id_bytes {
        return Err(WireError::InvalidSubscriptionId {
            actual,
            max: limits.max_subscription_id_bytes,
        });
    }
    Ok(SubscriptionId::new(id))
}

fn parse_filter(value: &Value, index: usize) -> Result<Filter, WireError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_filter(index, value.clone()))?;
    validate_filter_fields(object, index)?;
    serde_json::from_value(value.clone())
        .map_err(|source| WireError::InvalidFilter { index, source })
}

fn validate_event_fields(object: &Map<String, Value>) -> Result<(), WireError> {
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "id" | "pubkey" | "created_at" | "kind" | "tags" | "content" | "sig"
        ) {
            return Err(WireError::UnknownEventField {
                field: field.clone(),
            });
        }
    }
    Ok(())
}

fn validate_filter_fields(object: &Map<String, Value>, index: usize) -> Result<(), WireError> {
    for (field, value) in object {
        if !is_allowed_filter_field(field) {
            return Err(WireError::UnknownFilterField {
                index,
                field: field.clone(),
            });
        }
        let valid_type = match field.as_str() {
            "ids" | "authors" | "kinds" => value.is_array(),
            "search" => value.is_string(),
            "since" | "until" | "limit" => value.as_u64().is_some(),
            _ => value.is_array(),
        };
        if !valid_type {
            return Err(WireError::InvalidFilterField {
                index,
                field: field.clone(),
            });
        }
    }
    Ok(())
}

fn is_allowed_filter_field(field: &str) -> bool {
    match field {
        "ids" | "authors" | "kinds" | "search" | "since" | "until" | "limit" => true,
        _ => {
            let bytes = field.as_bytes();
            bytes.len() == 2 && bytes[0] == b'#' && bytes[1].is_ascii_alphabetic()
        }
    }
}

fn invalid_filter(index: usize, value: Value) -> WireError {
    let source = serde_json::from_value::<Filter>(value).unwrap_err();
    WireError::InvalidFilter { index, source }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate JSON object key {key}"
                )));
            }
            let UniqueValue(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

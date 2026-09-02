use deaddrop_relay_core::{StrictClientMessage, WireError, WireLimits, parse_client_message};

const EVENT_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PUBLIC_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNATURE: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000"
);

fn limits() -> WireLimits {
    WireLimits {
        max_frame_bytes: 4_096,
        max_subscription_id_bytes: 8,
        max_filters_per_req: 2,
    }
}

fn event_json() -> String {
    format!(
        r#"{{"id":"{EVENT_ID}","pubkey":"{PUBLIC_KEY}","created_at":1,"kind":1,"tags":[],"content":"hello","sig":"{SIGNATURE}"}}"#
    )
}

#[test]
fn parses_each_supported_client_message() {
    let event = event_json();
    let cases = [
        (format!(r#"["EVENT",{event}]"#), "EVENT"),
        (r#"["REQ","inbox",{"kinds":[1059]}]"#.to_owned(), "REQ"),
        (r#"["CLOSE","inbox"]"#.to_owned(), "CLOSE"),
        (format!(r#"["AUTH",{event}]"#), "AUTH"),
    ];

    for (raw, expected) in cases {
        let parsed = parse_client_message(raw.as_bytes(), &limits()).unwrap();
        let actual = match parsed {
            StrictClientMessage::Event(_) => "EVENT",
            StrictClientMessage::Req { .. } => "REQ",
            StrictClientMessage::Close(_) => "CLOSE",
            StrictClientMessage::Auth(_) => "AUTH",
        };
        assert_eq!(actual, expected, "raw message: {raw}");
    }
}

#[test]
fn preserves_valid_message_values() {
    let event = event_json();
    let StrictClientMessage::Event(parsed) =
        parse_client_message(format!(r#"["EVENT",{event}]"#).as_bytes(), &limits()).unwrap()
    else {
        panic!("expected EVENT");
    };
    assert_eq!(parsed.content, "hello");

    let StrictClientMessage::Req {
        subscription_id,
        filters,
    } = parse_client_message(br#"["REQ","inbox",{"kinds":[1059]}]"#, &limits()).unwrap()
    else {
        panic!("expected REQ");
    };
    assert_eq!(subscription_id.as_str(), "inbox");
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].kinds.as_ref().unwrap().len(), 1);
}

#[test]
fn rejects_non_utf8_and_oversized_frames() {
    assert!(matches!(
        parse_client_message(&[0xff], &limits()),
        Err(WireError::InvalidUtf8)
    ));

    let mut small_limits = limits();
    small_limits.max_frame_bytes = 2;
    assert!(matches!(
        parse_client_message(br#"[]"#, &small_limits),
        Err(WireError::InvalidEnvelope)
    ));
    assert!(matches!(
        parse_client_message(br#"[] "#, &small_limits),
        Err(WireError::FrameTooLarge { actual: 3, max: 2 })
    ));
}

#[test]
fn rejects_duplicate_object_fields_at_any_depth() {
    let event = event_json();
    let duplicate_event = event.replacen(
        &format!(r#""pubkey":"{PUBLIC_KEY}""#),
        &format!(r#""pubkey":"{PUBLIC_KEY}","pubkey":"{PUBLIC_KEY}""#),
        1,
    );
    for raw in [
        format!(r#"["EVENT",{duplicate_event}]"#),
        r#"["REQ","sub",{"kinds":[0],"kinds":[30443]}]"#.to_owned(),
        r##"["REQ","sub",{"#p":["a"],"#p":["b"]}]"##.to_owned(),
    ] {
        assert!(matches!(
            parse_client_message(raw.as_bytes(), &limits()),
            Err(WireError::InvalidJson(_))
        ));
    }
}

#[test]
fn rejects_unknown_event_fields() {
    let event = event_json().replace(
        &format!(r#""sig":"{SIGNATURE}""#),
        &format!(r#""sig":"{SIGNATURE}","unexpected":true"#),
    );
    assert!(matches!(
        parse_client_message(format!(r#"["AUTH",{event}]"#).as_bytes(), &limits()),
        Err(WireError::UnknownEventField { field }) if field == "unexpected"
    ));
}

#[test]
fn rejects_null_filter_constraints() {
    for field in [
        "ids", "authors", "kinds", "search", "since", "until", "limit", "#p",
    ] {
        let raw = format!(r#"["REQ","sub",{{"{field}":null}}]"#);
        assert!(matches!(
            parse_client_message(raw.as_bytes(), &limits()),
            Err(WireError::InvalidFilterField { index: 0, field: actual }) if actual == field
        ));
    }
}

#[test]
fn rejects_unknown_message_names() {
    assert!(parse_client_message(br#"["COUNT","sub",{}]"#, &limits()).is_err());
}

#[test]
fn rejects_wrong_or_excess_array_elements() {
    let event = event_json();
    let cases = [
        r#"["EVENT"]"#.to_owned(),
        format!(r#"["EVENT",{event},null]"#),
        r#"["REQ"]"#.to_owned(),
        r#"["REQ","sub"]"#.to_owned(),
        r#"["CLOSE","sub",null]"#.to_owned(),
        r#"["AUTH",{},null]"#.to_owned(),
        r#"{"EVENT":{}}"#.to_owned(),
    ];

    for raw in cases {
        assert!(
            parse_client_message(raw.as_bytes(), &limits()).is_err(),
            "accepted invalid shape: {raw}"
        );
    }
}

#[test]
fn rejects_malformed_event_and_filter_objects() {
    let cases = [
        r#"["EVENT",{}]"#,
        r#"["AUTH",{"id":7}]"#,
        r#"["REQ","sub",{"kinds":"not-an-array"}]"#,
        r#"["REQ","sub",7]"#,
    ];

    for raw in cases {
        assert!(
            parse_client_message(raw.as_bytes(), &limits()).is_err(),
            "accepted malformed object: {raw}"
        );
    }
}

#[test]
fn rejects_empty_or_oversized_subscription_ids() {
    for raw in [
        r#"["REQ","",{}]"#,
        r#"["REQ","ninebytes",{}]"#,
        r#"["CLOSE",""]"#,
        r#"["CLOSE","ninebytes"]"#,
    ] {
        assert!(
            parse_client_message(raw.as_bytes(), &limits()).is_err(),
            "accepted invalid subscription id: {raw}"
        );
    }
}

#[test]
fn rejects_empty_or_excess_filter_lists() {
    assert!(parse_client_message(br#"["REQ","sub"]"#, &limits()).is_err());
    assert!(parse_client_message(br#"["REQ","sub",{},{},{}]"#, &limits()).is_err());
}

#[test]
fn rejects_unknown_top_level_filter_fields() {
    for raw in [
        r##"["REQ","sub",{"#p":["abc"],"private":true}]"##,
        r#"["REQ","sub",{"kinds":[1],"limit":1,"typo":[]}]"#,
    ] {
        assert!(
            parse_client_message(raw.as_bytes(), &limits()).is_err(),
            "accepted unknown filter field: {raw}"
        );
    }
}

use std::collections::BTreeSet;

use deaddrop_protocol_core::{AuthorizedScope, authorize_filters};
use deaddrop_relay_core::{StrictClientMessage, WireError, WireLimits, parse_client_message};
use nostr::PublicKey;

const RECIPIENT: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn limits() -> WireLimits {
    WireLimits {
        max_frame_bytes: 4_096,
        max_subscription_id_bytes: 64,
        max_filters_per_req: 8,
    }
}

#[test]
fn raw_private_filter_must_remain_exact_through_authorization() {
    let raw = format!(r##"["REQ","inbox",{{"kinds":[1059],"#p":["{RECIPIENT}"]}}]"##);
    let StrictClientMessage::Req { filters, .. } =
        parse_client_message(raw.as_bytes(), &limits()).unwrap()
    else {
        panic!("expected REQ");
    };
    let recipient = PublicKey::from_hex(RECIPIENT).unwrap();
    let queries = authorize_filters(&BTreeSet::from([recipient]), &filters).unwrap();
    assert_eq!(queries[0].scope(), AuthorizedScope::Inbox(&recipient));

    let duplicate =
        format!(r##"["REQ","inbox",{{"kinds":[1059],"#p":["{RECIPIENT}","{RECIPIENT}"]}}]"##);
    assert!(matches!(
        parse_client_message(duplicate.as_bytes(), &limits()),
        Err(WireError::DuplicateFilterValue { .. })
    ));
}

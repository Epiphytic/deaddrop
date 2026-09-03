use std::path::PathBuf;

use clap::Parser;
use deaddrop_server::config::{Cli, Command};

#[test]
fn relay_requires_exactly_a_data_directory() {
    assert!(Cli::try_parse_from(["deaddrop", "relay"]).is_err());

    let Cli {
        command: Command::Relay(config),
    } = Cli::try_parse_from([
        "deaddrop",
        "relay",
        "--data-dir",
        "/tmp/deaddrop-relay-state",
    ])
    .expect("relay command should accept a data directory")
    else {
        panic!("expected relay command")
    };

    let deaddrop_server::config::RelayConfig { data_dir } = config;
    assert_eq!(data_dir, PathBuf::from("/tmp/deaddrop-relay-state"));
}

#[test]
fn relay_rejects_every_network_and_content_override() {
    for flag in [
        "--bind",
        "--host",
        "--port",
        "--assets-dir",
        "--socks",
        "--proxy",
        "--fallback",
    ] {
        assert!(
            Cli::try_parse_from([
                "deaddrop",
                "relay",
                "--data-dir",
                "/tmp/deaddrop-relay-state",
                flag,
                "attacker-controlled",
            ])
            .is_err(),
            "relay unexpectedly accepted {flag}"
        );
    }
}

#[test]
fn relay_identity_settings_are_fixed() {
    let Cli {
        command: Command::Relay(config),
    } = Cli::try_parse_from([
        "deaddrop",
        "relay",
        "--data-dir",
        "/tmp/deaddrop-relay-state",
    ])
    .unwrap()
    else {
        panic!("expected relay command")
    };

    assert_eq!(config.virtual_port(), 80);
    assert_eq!(config.nickname(), "deaddrop-relay");
}

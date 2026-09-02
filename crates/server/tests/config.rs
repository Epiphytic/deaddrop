use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use deaddrop_server::config::{BindPolicyError, Cli, Command};

fn parse(bind: &str, unsafe_bind: bool) -> Cli {
    let mut arguments = vec![
        "deaddrop",
        "debug",
        "--bind",
        bind,
        "--data-dir",
        "/tmp/deaddrop-test-state",
    ];
    if unsafe_bind {
        arguments.push("--unsafe-debug-bind");
    }
    Cli::try_parse_from(arguments).expect("debug command should parse")
}

#[test]
fn debug_requires_bind_and_data_directory() {
    assert!(Cli::try_parse_from(["deaddrop", "debug"]).is_err());
    assert!(Cli::try_parse_from(["deaddrop", "debug", "--bind", "127.0.0.1:0"]).is_err());
    assert!(
        Cli::try_parse_from([
            "deaddrop",
            "debug",
            "--data-dir",
            "/tmp/deaddrop-test-state"
        ])
        .is_err()
    );
}

#[test]
fn loopback_v4_and_v6_are_safe() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let Cli {
            command: Command::Debug(config),
        } = parse(bind, false);
        assert_eq!(config.data_dir, PathBuf::from("/tmp/deaddrop-test-state"));
        assert!(!config.unsafe_debug_bind);
        config.validate_bind_policy().expect("loopback is safe");
    }
}

#[test]
fn wildcard_lan_and_public_addresses_are_rejected_by_default() {
    for bind in ["0.0.0.0:0", "[::]:0", "192.168.1.10:0", "8.8.8.8:0"] {
        let Cli {
            command: Command::Debug(config),
        } = parse(bind, false);
        assert_eq!(
            config.validate_bind_policy(),
            Err(BindPolicyError::UnsafeAddress(
                bind.parse::<SocketAddr>().unwrap()
            ))
        );
    }
}

#[test]
fn explicit_unsafe_flag_allows_non_loopback_bind() {
    let Cli {
        command: Command::Debug(config),
    } = parse("0.0.0.0:0", true);
    config
        .validate_bind_policy()
        .expect("explicit unsafe override should allow bind");
}

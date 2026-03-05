#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    unused,
    clippy::correctness,
    missing_debug_implementations,
    missing_docs,
    clippy::all,
    clippy::wildcard_imports,
    clippy::needless_borrow,
    clippy::cast_lossless,
    clippy::unused_async,
    clippy::explicit_iter_loop,
    clippy::explicit_into_iter_loop,
    clippy::cloned_instead_of_copied
)]
#![cfg_attr(not(test), forbid(clippy::indexing_slicing))]
#![cfg_attr(not(test), forbid(clippy::string_slice))]
#![allow(
    clippy::match_bool,
    clippy::mixed_read_write_in_expression,
    clippy::bool_assert_comparison,
    clippy::manual_split_once,
    clippy::format_push_string,
    clippy::bool_to_int_with_if
)]
mod config;
mod dkim_verifier;
pub(crate) mod error;
pub(crate) mod inbound;
pub(crate) mod message;
pub(crate) mod openpgp;
pub(crate) mod outbound;
pub(crate) mod smtp_client;
pub(crate) mod smtp_server;
pub(crate) mod utils;

use config::Config;
use env_logger::Env;
use inbound::IncomingBeforeQueueHandler;
use outbound::OutgoingBeforeQueueHandler;
use smtp_server::run_smtp_server;
use std::env;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::process;
use std::sync::Arc;

const ENCRYPTION_NEEDED_523: &str = "523 Encryption Needed: Invalid Unencrypted Mail";

#[tokio::main]
async fn main() {
    // default to info level
    let env = Env::new().filter_or("RUST_LOG", "info");
    env_logger::Builder::from_env(env)
        // disable timestamps - automatically added by systemd
        .format_timestamp(None)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: {} <config_file> <mode>",
            args.first().unwrap_or(&"filtermail".to_string())
        );
        eprintln!("  mode: incoming or outgoing");
        process::exit(1);
    }

    let Some(config_path) = args.get(1) else {
        unreachable!("args length checked above")
    };
    let Some(mode) = args.get(2) else {
        unreachable!("args length checked above")
    };

    if mode != "incoming" && mode != "outgoing" {
        eprintln!("Error: mode must be 'incoming' or 'outgoing'");
        process::exit(1);
    }

    let config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read config: {}", e);
            process::exit(1);
        }
    };

    let listen =
        env::var("LISTEN_IP").map_or(Ipv4Addr::LOCALHOST.into(), |s| match s.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("Cannot parse listen address: {e}");
                process::exit(1);
            }
        });

    let postfix =
        env::var("POSTFIX_HOST").map_or(Ipv4Addr::LOCALHOST.into(), |s| resolve_postfix_host(&s));

    if mode == "outgoing" {
        let addr = (listen, config.filtermail_smtp_port);
        let handler = Arc::new(OutgoingBeforeQueueHandler::new(config.clone(), postfix));
        let max_size = config.max_message_size;
        log::debug!("Outgoing SMTP server listening on {}:{}", addr.0, addr.1);

        if let Err(e) = run_smtp_server(&addr, handler, max_size).await {
            eprintln!("Server error: {}", e);
            process::exit(1);
        }
    } else {
        // Skip DKIM verification (used for tests).
        let skip_dkim = env::var("FILTERMAIL_SKIP_DKIM")
            .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if skip_dkim {
            log::warn!("DKIM verification DISABLED! This should not be used in production.");
        }

        let addr = (listen, config.filtermail_smtp_port_incoming);
        let handler = Arc::new(
            // We want to panic here if the handler cannot be created.
            IncomingBeforeQueueHandler::new(config.clone(), skip_dkim, postfix).unwrap(),
        );
        let max_size = config.max_message_size;
        log::debug!("Incoming SMTP server listening on {}:{}", addr.0, addr.1);

        if let Err(e) = run_smtp_server(&addr, handler, max_size).await {
            eprintln!("Server error: {}", e);
            process::exit(1);
        }
    }
}

fn resolve_postfix_host(s: &str) -> IpAddr {
    match (s, 0).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => {
                eprintln!("Cannot resolve postfix host");
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Cannot resolve postfix host: {e}");
            process::exit(1);
        }
    }
}

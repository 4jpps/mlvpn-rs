//! End-to-end test of the WireGuard-style settled-primary bypass path
//! (`handle_incoming`'s `PacketType::Data` arm in `tunnel.rs`,
//! `ReorderBuffer::note_delivered`) -- specifically the C1 regression
//! found in code review after that feature first shipped
//! (`.superpowers/sdd/2026-09-01-wireguard-style-immediate-delivery/`):
//! `Scheduler::primary` is driven purely by monitor/probe ticks, not by
//! Data-packet or session activity, so once bypass mode engages, the
//! *buffered* branch (the one that resets `peer_primary_link` on a
//! session-id change) is not guaranteed to run again for the rest of
//! the tunnel's lifetime. Left unfixed, a `follow_peer_primary` host's
//! adopted `peer_primary_link` would never get cleared across a rekey
//! while bypass mode is active.
//!
//! Configures the server with `scheduler.primary_link_mode` (decides
//! its own primary locally) and the client with
//! `scheduler.follow_peer_primary` (adopts whatever the server
//! advertises over `VersionInfo`) -- the exact two-sided topology this
//! feature is for. A single link on each side is enough: with only one
//! Up link, `primary_link_mode` settles on it immediately, and the
//! client's `follow_peer_primary` scheduler mirrors that choice, which
//! is exactly what puts the client's `handle_incoming` into the bypass
//! branch for its own inbound Data traffic (the server's *own* Data
//! never reordering also happens, but this test only asserts on the
//! client side, since that's the side actually maintaining
//! `peer_primary_link`).
//!
//! History: this file originally also asserted that a rekey's
//! `session_id` change cleared a stale `peer_primary_link` from the bypass
//! branch (the C1 regression). Since the 0.7.0 per-link WireGuard rewrite
//! there is no app-level session or rekey event at all (each link's own
//! `WgTunnel` rekeys invisibly), so that regression can no longer occur
//! and the assertion was removed. What remains is the end-to-end check
//! that the topology above really does settle the client into bypass mode
//! and keeps delivering traffic.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_wireguard_style_immediate_delivery -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn follow_peer_primary_client_settles_into_bypass_mode_and_keeps_delivering() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mwsdc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mwsds{id}")).expect("create server netns");

    let vc0 = format!("mwdc0{id}");
    let vs0 = format!("mwds0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("wgstyle", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    // Server: decides its own primary locally (only one link configured,
    // so it settles on it immediately once Up).
    let server_cfg = write_config(
        &tmp,
        "server",
        "mwsdsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides {
            primary_link_mode: true,
            ..Default::default()
        },
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6300,
            local_addr: None,
            remote_addr: None,
        }],
        &server_ctl,
        None,
    )
    .expect("write server config");

    // Client: adopts whatever the server advertises over VersionInfo,
    // rather than deciding locally.
    let client_cfg = write_config(
        &tmp,
        "client",
        "mwsdcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            follow_peer_primary: true,
            ..Default::default()
        },
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6300,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6300")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before settling could even start");

    // The client adopts the server's advertised primary over the periodic
    // VersionInfo exchange (same cadence as StatsShare/probes), which is
    // what puts its `handle_incoming` into the bypass branch.
    poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        s.links.iter().any(|l| l.name == "link0" && l.is_primary)
    })
    .await
    .expect("client never adopted the server's primary link, so bypass mode never engaged");

    // Real traffic must flow normally while in bypass mode, and the link
    // must stay up afterward.
    ns_client
        .exec("ping", &["-c", "5", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed while the client was in bypass mode");
    poll_snapshot_until(&client_ctl, Duration::from_secs(5), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 not reported 'up' after traffic in bypass mode");
}

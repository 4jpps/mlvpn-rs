//! End-to-end test of graceful shutdown (`tunnel.rs`'s `Shutdown`/
//! `ShutdownReason`, `broadcast_disconnect`, and `handle_incoming`'s
//! `PacketType::Disconnect` handling -- see `ARCHITECTURE.md` §11 item
//! "`PacketType::Disconnect` is parsed but unhandled", now closed).
//!
//! Sends the client process a real `SIGTERM` (the same signal
//! `systemctl stop` sends) and checks two things: that the client
//! itself exits promptly instead of hanging (the local half of
//! graceful shutdown -- receiving the signal, notifying the peer, and
//! tearing its own tasks down), and that the server -- which never
//! received any signal itself -- also exits promptly once it processes
//! the client's `Disconnect` frame (the peer-initiated half). If either
//! half were broken (a signal handler that doesn't fire, a
//! `Disconnect` that doesn't get sent or doesn't get recognized on
//! receipt), the corresponding process would instead hang until this
//! test's own timeout, or -- in the `Drop`-triggered `SIGKILL` case --
//! never get the chance to prove it could exit cleanly on its own at
//! all.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_disconnect -- --ignored --nocapture
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
    SERVER_TUNNEL_ADDR,
};

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn sigterm_triggers_graceful_disconnect_on_both_sides() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtdc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtds{id}")).expect("create server netns");

    let vc0 = format!("mdc0{id}");
    let vs0 = format!("mds0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("disconnect", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mtdsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
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

    let client_cfg = write_config(
        &tmp,
        "client",
        "mtdcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
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

    let mut server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let mut client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before shutdown could even be tested");

    // The actual point of this test: SIGTERM to the client should make
    // *both* processes exit promptly -- the client because it caught
    // the signal directly, the server because the client's Disconnect
    // frame told it to.
    client.terminate().expect("send SIGTERM to client");

    let client_status = client
        .wait_for_exit(Duration::from_secs(10))
        .expect("client did not exit promptly after SIGTERM");
    assert!(
        client_status.success(),
        "client should exit 0 on a graceful shutdown, got {client_status}"
    );

    let server_status = server.wait_for_exit(Duration::from_secs(10)).expect(
        "server did not exit promptly after the client's Disconnect -- \
             peer-initiated shutdown handling is broken",
    );
    assert!(
        server_status.success(),
        "server should exit 0 on a peer-initiated graceful shutdown, got {server_status}"
    );
}

//! End-to-end test of link-quality failover and recovery: both bonded
//! links start reachable, one is then taken down (`ip link set ... down`
//! on its veth), and the test confirms the daemon's own probe/hysteresis
//! pipeline (`monitor.rs`, `scheduler.rs`'s SWRR up/down transitions --
//! see `ARCHITECTURE.md` §5/§6) marks it `down` while the other link
//! stays `up`, then confirms it recovers to `up` again once the veth
//! comes back. A ping across the tunnel at the end confirms the
//! data plane (TUN, encryption, the reorder buffer) is actually carrying
//! traffic throughout, not just that the control socket's numbers move.
//!
//! **What this does *not* test**: toggling a veth's admin state up/down
//! never changes its kernel ifindex, so this only exercises the
//! already-existing quality-based hysteresis recovery -- not
//! `link::LinkHandle::reconnect` (self-healing socket rebind after an
//! interface is fully removed and recreated). See `tests/support/mod.rs`'s
//! module doc comment for why that's a separate, not-yet-written test.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_failover -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up, link_state,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn link_down_and_up_transitions_reflect_in_control_socket_and_data_still_flows() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtfc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtfs{id}")).expect("create server netns");

    let vc0 = format!("mtc0{id}");
    let vs0 = format!("mts0{id}");
    let vc1 = format!("mtc1{id}");
    let vs1 = format!("mts1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir("failover", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();
    let server_addr_1 = addr_s1.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mtfsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6100,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6101,
                local_addr: None,
                remote_addr: None,
            },
        ],
        &server_ctl,
        None,
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "mtfcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6100,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6100")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6101,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6101")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    // Both links reachable this time -- wait for both to come up before
    // touching anything.
    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up' before the down/up test could even start");

    // Confirm the data plane actually works before breaking anything, so
    // a later ping failure can only mean the failover itself is broken,
    // not that the tunnel never carried traffic in the first place.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("baseline ping across the tunnel failed before any link was touched");

    // Take link0's client-side veth down. down_threshold defaults to 5
    // consecutive missed probes at the default 200ms probe_interval_ms
    // (~1s), so this should show up well within the timeout below even
    // on a slow runner.
    ns_client
        .exec("ip", &["link", "set", vc0.as_str(), "down"])
        .expect("bring link0's veth down");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_state(s, "link0") == Some("down")
    })
    .await
    .expect("link0 never transitioned to 'down' after its veth was taken down");
    assert_eq!(
        link_state(&snapshot, "link1"),
        Some("up"),
        "link1 should have stayed 'up' the whole time link0 was down"
    );

    // Data should still flow across the surviving link -- this is the
    // actual point of bonding: zero downtime unless every link is down
    // (see ARCHITECTURE.md §6).
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed while link0 was down but link1 was up");

    // Bring it back. up_threshold defaults to 3 consecutive successful
    // probes, so recovery should be faster than the initial down
    // detection above.
    ns_client
        .exec("ip", &["link", "set", vc0.as_str(), "up"])
        .expect("bring link0's veth back up");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never recovered to 'up' after its veth was brought back up");

    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after link0 recovered");
}

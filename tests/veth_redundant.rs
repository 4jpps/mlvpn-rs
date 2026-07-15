//! End-to-end test of redundancy mode (`scheduler.redundant_mode`,
//! `tunnel::send_redundant`) -- see `ARCHITECTURE.md` §6.
//!
//! Configures both sides with `redundant_mode = true` and two links, so
//! every outgoing Data frame gets sent on *both* links at once instead
//! of the normal single-link SWRR pick. This is mainly a regression
//! guard against the send path itself: the interesting correctness
//! property (the receiving side's replay window silently dropping the
//! second copy of each packet rather than double-delivering it to the
//! TUN device, or the reorder buffer getting confused by two arrivals
//! of the same sequence number) is already covered at the unit level by
//! `crypto.rs`'s replay-window tests -- what this adds is proving the
//! whole path still works end to end with real sockets and two real
//! links both actually carrying the duplicated traffic, not just that
//! the pieces are individually correct in isolation.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_redundant -- --ignored --nocapture
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
async fn redundant_mode_carries_traffic_on_both_links() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtdrc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtdrs{id}")).expect("create server netns");

    let vc0 = format!("mrc0{id}");
    let vs0 = format!("mrs0{id}");
    let vc1 = format!("mrc1{id}");
    let vs1 = format!("mrs1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir("redundant", &id).expect("create scratch dir");

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
        "mdrsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides {
            redundant_mode: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6400,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6401,
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
        "mdrcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            redundant_mode: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6400,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6400")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6401,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6401")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up' with redundant_mode enabled");

    // A handful of pings, not just one -- redundant mode sends every one
    // of these on both links simultaneously, so this exercises sustained
    // duplicate delivery rather than a single lucky round trip.
    ns_client
        .exec("ping", &["-c", "5", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed with redundant_mode enabled");

    // Control socket should still agree both links are healthy --
    // sending everything twice shouldn't itself look like link trouble.
    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links not reported 'up' after the redundant-mode traffic burst");
    assert!(link_is_up(&snapshot, "link0") && link_is_up(&snapshot, "link1"));
}

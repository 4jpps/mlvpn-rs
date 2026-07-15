//! Regression test for handshake racing across every configured link
//! (`tunnel.rs`'s `establish_session`/`race_handshake_reply`).
//!
//! Configures the client's *first* `[[links]]` entry to point at a port
//! nothing is listening on (a real, reachable host with no `mlvpnd` bound
//! there), while a second link is fully reachable. Before the racing
//! change, `establish_session`'s `Mode::Client` arm dialed only
//! `links_guard.first()` -- this exact scenario would have exhausted all
//! 10 retry attempts against the dead first link and failed outright,
//! never even trying the second, healthy one. After the change, the
//! client broadcasts on every link at once and completes via whichever
//! replies -- so this test passing is direct evidence the fix works, and
//! this test failing (reverting to a hang/timeout) is a direct regression
//! signal if the racing behavior is ever accidentally lost.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user) and what it deliberately
//! doesn't cover. Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_handshake_race -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain: many
//! sudoers configs force `secure_path` for `PATH` regardless of `-E`,
//! and even once `cargo` itself is found, rustup's shim still consults
//! `$HOME` to pick a toolchain -- root's own `$HOME` has no toolchain
//! configured. Explicitly passing both through is what actually works.)

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
async fn client_establishes_via_second_link_when_first_is_unreachable() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtnc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtns{id}")).expect("create server netns");

    // Two veth pairs between the same client/server netns pair, standing
    // in for two physical uplinks between the same two hosts -- the
    // realistic bonding scenario.
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

    let tmp = create_scratch_dir("race", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    // server_addr_0/1 are just the veth IPs assigned above -- split out
    // for readability at the call sites below.
    let server_addr_0 = addr_s0.split('/').next().unwrap();
    let server_addr_1 = addr_s1.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mtsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6000,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6001,
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
        "mtcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[
            // link0 (configured FIRST -- this is the whole point of the
            // test) points at the right IP but the WRONG port: nothing on
            // the server side is listening there, so probes/handshake
            // attempts on this link never get a reply, ever.
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6000,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:9999")),
            },
            // link1, configured second, is fully reachable.
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6001,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6001")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    // Server before client: the client dials out immediately, so the
    // server needs to already be listening.
    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    // Old (pre-racing) behavior: 10 attempts x 500ms against the dead
    // first link alone would take ~5s to exhaust and then fail outright,
    // so the control socket would never even start serving snapshots.
    // New behavior should reach link1 "up" well within a couple of
    // probe/hysteresis cycles once the handshake completes on the first
    // attempt. 20s gives generous headroom for a slow/virtualized CI
    // runner while still failing well before it would look like a hang.
    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link1")
    })
    .await
    .expect(
        "client tunnel never reached link1 'up' -- if this hangs/times out, handshake racing \
         across every configured link may be broken (dialing only the first link again?)",
    );

    let link0 = snapshot.links.iter().find(|l| l.name == "link0");
    assert!(
        link0.is_some_and(|l| l.state != "up"),
        "link0 (deliberately unreachable) unexpectedly reports 'up': {link0:?}"
    );
}

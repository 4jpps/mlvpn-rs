//! End-to-end test of primary-aware, peer-negotiated tunnel MTU (see
//! `docs/superpowers/specs/2026-09-16-primary-aware-peer-mtu-design.md`):
//! with two links of genuinely different MTU, confirms the live tunnel
//! MTU (a) is higher while the higher-MTU link is primary than it would
//! be in plain bonded mode, (b) both peers' own `local_tunnel_mtu`
//! converge to the *same* value even though only one host's own link
//! set actually differs in MTU, and (c) failing over to the
//! lower-MTU link brings the live tunnel MTU down on both sides.
//!
//! Modeled directly on `tests/veth_primary_link_mode.rs`'s own
//! topology/failover setup -- see that file first for the base pattern
//! this one extends.
//!
//! **Cannot be run in this development sandbox**: like
//! `tests/veth_fec.rs` before it, this needs `/dev/net/tun`, which does
//! not exist here. Written and gated (build/clippy/fmt) here; needs one
//! real run on a TUN-capable host before this feature is considered
//! fully verified.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_primary_mtu -- --ignored --nocapture
//! ```

mod support;

use std::time::Duration;
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SchedulerOverrides,
    VethPair, create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config,
};

/// Sets a veth interface's own MTU inside its namespace -- neither
/// `VethPair::create` nor any other `tests/support` helper does this
/// today, so it's shelled out to directly here the same way
/// `tests/support/mod.rs`'s own `NetNs::exec` is used everywhere else
/// in these tests.
fn set_interface_mtu(ns: &NetNs, ifname: &str, mtu: u32) {
    ns.exec("ip", &["link", "set", ifname, "mtu", &mtu.to_string()])
        .unwrap_or_else(|e| panic!("failed to set {ifname} mtu to {mtu}: {e}"));
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn primary_mtu_tracks_the_active_link_and_converges_across_the_peer() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtmc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtms{id}")).expect("create server netns");

    let vc0 = format!("mtmc0{id}");
    let vs0 = format!("mtms0{id}");
    let vc1 = format!("mtmc1{id}");
    let vs1 = format!("mtms1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0 (link0, the higher-MTU link)");
    let veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1 (link1, the lower-MTU link)");

    // link0 gets a genuinely higher MTU than link1 on BOTH ends of both
    // pairs -- this is what makes the test meaningful: if primary-aware
    // selection or peer negotiation were broken, the tunnel MTU would
    // either ignore this difference entirely (always use the min, as in
    // plain bonded mode) or the two hosts would disagree.
    set_interface_mtu(&ns_client, &vc0, 1500);
    set_interface_mtu(&ns_server, &vs0, 1500);
    set_interface_mtu(&ns_client, &vc1, 1400);
    set_interface_mtu(&ns_server, &vs1, 1400);

    let tmp = create_scratch_dir("primarymtu", &id).expect("create scratch dir");

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
        "mtmsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        // The server follows the client's primary: with two independent
        // elections each side can settle on a different link (e.g. server
        // on link1, client on link0), and the test's 1388-vs-1288 steps
        // assume both sides sit on the same link.
        SchedulerOverrides {
            follow_peer_primary: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6300,
                local_addr: None,
                dual_stack: false,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6301,
                local_addr: None,
                dual_stack: false,
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
        "mtmcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            primary_link_mode: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6300,
                local_addr: None,
                dual_stack: false,
                remote_addr: Some(format!("{server_addr_0}:6300")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6301,
                local_addr: None,
                dual_stack: false,
                remote_addr: Some(format!("{server_addr_1}:6301")),
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
    .expect("both links never reached 'up' before the primary-mtu test could even start");

    // With both links healthy and near-identical scores, which one the
    // client elects is a coin flip, and the steps below assume link0 (the
    // 1500-MTU link) is primary. Make link1 clearly worse so the election
    // is deterministic.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "netem", "delay", "40ms",
            ],
        )
        .expect("failed to add netem delay to link1");

    // Give mtu_monitor_loop's now-3s tick, plus the VersionInfo
    // exchange, a few cycles to converge before asserting anything.
    // `peer_applied_tunnel_mtu` (the peer's own already-negotiated
    // value), not `peer_tunnel_mtu` (the peer's raw pre-negotiation
    // capability) -- the two happen to be equal in this test's
    // perfectly symmetric veth topology, but only `peer_applied_tunnel_mtu`
    // is actually the correct "did negotiation converge" signal in
    // general (see `ipc::DaemonSnapshot::peer_applied_tunnel_mtu`'s doc
    // comment -- this exact mixup produced a false MISMATCH in
    // mlvpn-tui on the real, asymmetric home-bgp/cloud-bgp pairing).
    // Must also wait for link0 to actually become primary and the MTU to rise
    // to reflect its 1500-byte physical MTU (1388 with WireGuard overhead):
    // before that, both sides trivially agree on the bonded-mode minimum
    // (1288, from link1's 1400), and a snapshot taken then would make the
    // post-failover "MTU shrank" check below compare 1288 against 1288.
    let converged = poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        s.links.iter().any(|l| l.name == "link0" && l.is_primary)
            && s.daemon.local_tunnel_mtu > 1300
            && s.daemon.peer_applied_tunnel_mtu == Some(s.daemon.local_tunnel_mtu)
    })
    .await
    .expect("client and server tunnel MTU never converged to the same value");

    assert!(
        converged.daemon.local_tunnel_mtu > 0,
        "sanity: live tunnel MTU must be nonzero once converged"
    );

    // The real, non-tautological proof of primary-awareness is the
    // failover comparison below, not a same-tick "is it bigger than X"
    // check: `ip link set <iface> down` does NOT remove the interface
    // or change what `query_interface_mtu` reports for it, so in plain
    // bonded mode (primary_idx: None) the computed value would stay
    // exactly the same (still min(1500, 1400)-based) whether or not
    // link0 is administratively down. Only primary-aware selection
    // actually changes the computed value across this failover -- so
    // observing a real shrink after taking link0 down is direct
    // evidence primary-aware selection is active, not an artifact of
    // a link's physical MTU becoming unqueryable.

    // Fail over: take link0's client-side veth down, forcing
    // primary_link_mode to switch to link1 (the lower-MTU link).
    ns_client
        .exec("ip", &["link", "set", &vc0, "down"])
        .expect("failed to take link0's client-side veth down");

    let after_failover = poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        // Wait for the live tunnel MTU to actually shrink from its
        // pre-failover value -- the real behavior this test exists to
        // prove, not just "some snapshot eventually arrives".
        s.daemon.local_tunnel_mtu < converged.daemon.local_tunnel_mtu
    })
    .await
    .expect(
        "client's live tunnel MTU never shrank after failing over to the lower-MTU link -- \
         primary-aware MTU tracking did not react to the failover",
    );

    // And the server, despite its own links never changing, should
    // converge down to match via peer negotiation.
    let server_after_failover = poll_snapshot_until(&server_ctl, Duration::from_secs(20), |s| {
        s.daemon.local_tunnel_mtu == after_failover.daemon.local_tunnel_mtu
    })
    .await
    .expect(
        "server's live tunnel MTU never converged down to match the client's post-failover \
         value -- peer negotiation did not propagate the change",
    );
    assert_eq!(
        server_after_failover.daemon.local_tunnel_mtu,
        after_failover.daemon.local_tunnel_mtu
    );

    // Fail BACK: bring link0's client-side veth back up and confirm both
    // sides' live tunnel MTU eventually returns to the original
    // pre-failover converged value -- the real regression guard for the
    // monotonic-ratchet bug found in this feature's final review (see
    // docs/superpowers/specs/2026-09-16-primary-aware-peer-mtu-design.md
    // §2): before that fix, negotiate_tunnel_mtu stored the ALREADY-
    // negotiated (post-min()) value back into the value advertised to the
    // peer, so once either side ever negotiated down, neither side could
    // ever advertise a higher capability again -- this assertion would
    // hang and time out under that bug, since the MTU would stay pinned
    // at the post-failover value forever.
    ns_client
        .exec("ip", &["link", "set", &vc0, "up"])
        .expect("failed to bring link0's client-side veth back up");

    let recovered = poll_snapshot_until(&client_ctl, Duration::from_secs(60), |s| {
        s.daemon.local_tunnel_mtu == converged.daemon.local_tunnel_mtu
    })
    .await
    .expect(
        "client's live tunnel MTU never recovered to its original pre-failover value after \
         link0 came back up -- this is the monotonic-ratchet regression: once a peer ever \
         negotiates down, it must still be able to rise again once local capacity does",
    );

    let server_recovered = poll_snapshot_until(&server_ctl, Duration::from_secs(30), |s| {
        s.daemon.local_tunnel_mtu == recovered.daemon.local_tunnel_mtu
    })
    .await
    .expect(
        "server's live tunnel MTU never converged back up to match the client's recovered value",
    );
    assert_eq!(
        server_recovered.daemon.local_tunnel_mtu,
        recovered.daemon.local_tunnel_mtu
    );

    drop(veth0);
    drop(veth1);
}

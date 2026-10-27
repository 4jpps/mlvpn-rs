//! Timing measurements for recovery after a link outage: how long the
//! data plane stays dead after (1) every link is down for longer than
//! boringtun's 90 s handshake-attempt window and then restored, and (2) one
//! of two bonded links dies while traffic is flowing.
//!
//! These print the measured times and assert generous upper bounds, so a
//! regression to the multi-minute recovery seen in production
//! (2026-09-16 / 2026-09-21) fails loudly. `MLVPN_OUTAGE_SECS` overrides
//! the full-outage length (default 100 s, long enough to expire the first
//! handshake attempt).
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_recovery_timing -- --ignored --nocapture --test-threads=1
//! ```

mod support;

use std::time::{Duration, Instant};
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
    SchedulerOverrides, VethPair, create_scratch_dir, ensure_mlvpn_system_user,
    generate_test_keypair, link_is_up, link_state, poll_snapshot_until, require_ip_command,
    require_root, unique_id, veth_link_addrs, write_config,
};

struct Rig {
    ns_client: NetNs,
    vc0: String,
    vc1: String,
    client_ctl: std::path::PathBuf,
    _ns_server: NetNs,
    _veths: (VethPair, VethPair),
    _procs: (MlvpnProcess, MlvpnProcess),
}

async fn rig(label: &str) -> Rig {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtrc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtrs{id}")).expect("create server netns");
    let vc0 = format!("mrc0{id}");
    let vs0 = format!("mrs0{id}");
    let vc1 = format!("mrc1{id}");
    let vs1 = format!("mrs1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);
    let veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir(label, &id).expect("create scratch dir");
    let (client_key, client_pub) = generate_test_keypair(&tmp, "client").expect("client key");
    let (server_key, server_pub) = generate_test_keypair(&tmp, "server").expect("server key");
    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");
    let s0 = addr_s0.split('/').next().unwrap();
    let s1 = addr_s1.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mtrsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key,
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
        "mtrcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6100,
                local_addr: None,
                remote_addr: Some(format!("{s0}:6100")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6101,
                local_addr: None,
                remote_addr: Some(format!("{s1}:6101")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up'");
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("baseline ping failed");

    Rig {
        ns_client,
        vc0,
        vc1,
        client_ctl,
        _ns_server: ns_server,
        _veths: (veth0, veth1),
        _procs: (server, client),
    }
}

fn ping_ok(ns: &NetNs) -> bool {
    ns.exec("ping", &["-c", "1", "-W", "1", SERVER_TUNNEL_HOST])
        .is_ok()
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn full_outage_longer_than_handshake_window_recovers_quickly() {
    let r = rig("rectime-full").await;
    let outage: u64 = std::env::var("MLVPN_OUTAGE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    for v in [&r.vc0, &r.vc1] {
        r.ns_client
            .exec_best_effort("ip", &["link", "set", v, "down"]);
    }
    tokio::time::sleep(Duration::from_secs(outage)).await;
    let t0 = Instant::now();
    for v in [&r.vc0, &r.vc1] {
        r.ns_client
            .exec_best_effort("ip", &["link", "set", v, "up"]);
    }

    let mut link_up_at = None;
    let mut ping_at = None;
    while t0.elapsed() < Duration::from_secs(240) && ping_at.is_none() {
        if link_up_at.is_none()
            && poll_snapshot_until(&r.client_ctl, Duration::from_millis(500), |s| {
                link_is_up(s, "link0") || link_is_up(s, "link1")
            })
            .await
            .is_ok()
        {
            link_up_at = Some(t0.elapsed());
        }
        if ping_ok(&r.ns_client) {
            ping_at = Some(t0.elapsed());
        }
    }
    println!(
        "full outage {outage}s: first link 'up' after {link_up_at:?}, first tunnel ping after {ping_at:?} (from restore)"
    );
    let ping_at = ping_at.expect("tunnel never carried traffic again within 240 s of restore");
    assert!(
        ping_at < Duration::from_secs(30),
        "data plane took {ping_at:?} to recover after a {outage}s full outage"
    );
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn one_bonded_link_dying_blackholes_traffic_only_briefly() {
    let r = rig("rectime-one").await;
    r.ns_client
        .exec_best_effort("ip", &["link", "set", &r.vc0, "down"]);
    let t0 = Instant::now();
    let mut last_fail = None;
    let mut first_ok_after_fail = None;
    while t0.elapsed() < Duration::from_secs(60) {
        if ping_ok(&r.ns_client) {
            if last_fail.is_some() && first_ok_after_fail.is_none() {
                first_ok_after_fail = Some(t0.elapsed());
            }
        } else {
            last_fail = Some(t0.elapsed());
            first_ok_after_fail = None;
        }
    }
    let snap = poll_snapshot_until(&r.client_ctl, Duration::from_secs(5), |s| {
        link_state(s, "link0") == Some("down")
    })
    .await;
    println!(
        "one link killed: last failed ping at {last_fail:?}, traffic stable from {first_ok_after_fail:?}; link0 marked down: {}",
        snap.is_ok()
    );
    if let Some(t) = last_fail {
        assert!(
            t < Duration::from_secs(15),
            "traffic still failing {t:?} after one of two bonded links died"
        );
    }
}

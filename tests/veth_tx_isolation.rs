//! End-to-end test of per-link TX failure isolation and recovery
//! (Phase 2 of the performance plan, `tunnel::link_tx_worker` /
//! `TxDispatcher`).
//!
//! Two bonded links carry a steady UDP stream through the tunnel. Link1
//! is then *stalled* (not taken down): a `tbf` qdisc draining at a
//! trickle, with a queue limit far larger than the socket send buffer,
//! keeps each queued skb charged to the sending socket, so once the send
//! buffer fills, link1's `send_to` blocks -- the realistic "one WAN path
//! stops draining" failure. (`netem delay` does not work for this: it
//! orphans each skb from its socket, so senders never see backpressure,
//! and the queue limit must exceed the 8 MiB `SO_SNDBUF` or the qdisc
//! silently drops instead of blocking.) Before per-link workers, the
//! single `outbound_sender` task did every link's `send_to` inline, so
//! that one blocked send froze transmission on *every* link until the
//! stall cleared.
//!
//! Acceptance criteria this covers:
//!  - Failure isolation: while link1 is stalled (its own `tx_bytes`
//!    freezes), link0's `tx_bytes` keeps growing with no multi-second
//!    gap. (`tx_queue_full_total` is printed for information only: the
//!    scheduler usually notices the stalled link via probe loss before
//!    its queue fills; queue-full spill is covered by unit tests.)
//!  - Recovery: once the stall is removed link1 returns to `up`, its
//!    `tx_bytes` grows again, and the tunnel still carries a ping.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2` incl. `tc`, `python3` for the traffic generator,
//! the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_tx_isolation -- --ignored --nocapture
//! ```

mod support;

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
    SchedulerOverrides, VethPair, create_scratch_dir, ensure_mlvpn_system_user,
    generate_test_keypair, link_is_up, poll_snapshot_until, require_ip_command, require_root,
    require_tc_command, unique_id, veth_link_addrs, write_config,
};

/// Paced UDP sender run inside the client namespace: `argv[1]` seconds
/// at `argv[2]` packets/sec of 1000-byte datagrams to the server's
/// tunnel address. Paced against the wall clock so a stall in the
/// tunnel (which only ever shows up as dropped/blocked sends downstream
/// of the TUN device) cannot slow the generator itself.
const BLASTER: &str = r#"
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dur, pps = float(sys.argv[1]), int(sys.argv[2])
payload = b"x" * 1000
start = time.time()
sent = 0
while time.time() - start < dur:
    due = int((time.time() - start) * pps)
    while sent < due:
        try:
            s.sendto(payload, (sys.argv[3], 9))
        except OSError:
            pass
        sent += 1
    time.sleep(0.001)
"#;

struct Sample {
    at: Instant,
    link0_tx: u64,
    link1_tx: u64,
    link1_queue_full: u64,
}

async fn sample(ctl: &std::path::Path) -> Sample {
    let snap = poll_snapshot_until(ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("control socket snapshot");
    let get = |name: &str| {
        snap.links
            .iter()
            .find(|l| l.name == name)
            .unwrap_or_else(|| panic!("snapshot missing link '{name}'"))
    };
    Sample {
        at: Instant::now(),
        link0_tx: get("link0").tx_bytes,
        link1_tx: get("link1").tx_bytes,
        link1_queue_full: get("link1").tx_queue_full_total,
    }
}

fn spawn_blaster(ns: &NetNs, secs: u32, pps: u32) -> Child {
    Command::new("ip")
        .args(["netns", "exec", ns.name.as_str(), "python3", "-c", BLASTER])
        .arg(secs.to_string())
        .arg(pps.to_string())
        .arg(SERVER_TUNNEL_HOST)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn UDP traffic generator (needs python3)")
}

/// Default scheduling: the scheduler tends to steer away from a stalled
/// link on its own, so this mainly guards the recovery path and the
/// "no global stall" property.
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces -- see module doc comment"]
async fn stalled_link_does_not_stall_other_links_and_recovers() {
    run_scenario(false, false).await;
}

/// `redundant_mode` sends every packet to every Up link regardless of
/// health, so the scheduler cannot route around the stalled link: without
/// per-link workers the single sender blocks on link1 and freezes link0
/// too. This is the variant that discriminates the Phase 2 change and
/// shows link1's bounded queue absorbing (and counting) the backlog.
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces -- see module doc comment"]
async fn stalled_link_does_not_stall_redundant_mode() {
    run_scenario(true, false).await;
}

/// The default-scheduling stall with P+Q FEC on: FEC data and parity both go
/// through the per-link TX workers, so a stalled link's blocked send must
/// not hold up link0 (the FEC accumulator reserves a queue slot per member
/// and never sends inline).
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces -- see module doc comment"]
async fn stalled_link_does_not_stall_other_links_with_fec() {
    run_scenario(false, true).await;
}

async fn run_scenario(redundant: bool, fec: bool) {
    let overrides = || SchedulerOverrides {
        redundant_mode: redundant,
        fec_enabled: fec,
        fec_parity: if fec { Some(2) } else { None },
        ..Default::default()
    };
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtxc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtxs{id}")).expect("create server netns");

    let vc0 = format!("mxc0{id}");
    let vs0 = format!("mxs0{id}");
    let vc1 = format!("mxc1{id}");
    let vs1 = format!("mxs1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir("txisolation", &id).expect("create scratch dir");
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
        "mtxsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        overrides(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6200,
                local_addr: None,
                dual_stack: false,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6201,
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
        "mtxcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        overrides(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6200,
                local_addr: None,
                dual_stack: false,
                remote_addr: Some(format!("{server_addr_0}:6200")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6201,
                local_addr: None,
                dual_stack: false,
                remote_addr: Some(format!("{server_addr_1}:6201")),
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
    .expect("both links never reached 'up'");
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("baseline ping across the tunnel failed");

    let mut blaster = spawn_blaster(&ns_client, 45, 8000);

    // --- Healthy baseline: traffic is spread over both links.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = sample(&client_ctl).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let healthy = sample(&client_ctl).await;
    assert!(
        healthy.link0_tx > before.link0_tx && healthy.link1_tx > before.link1_tx,
        "both links should carry traffic while healthy (link0 {}->{}, link1 {}->{})",
        before.link0_tx,
        healthy.link0_tx,
        before.link1_tx,
        healthy.link1_tx
    );

    // --- Stall link1: drain at ~100 kbit/s behind a deep queue so the
    // socket send buffer fills and `send_to` blocks.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "tbf", "rate", "100kbit", "burst", "3000",
                "limit", "128mb",
            ],
        )
        .expect("stall client's link1 veth with tbf");
    let stall_start = Instant::now();

    let mut samples = vec![sample(&client_ctl).await];
    while stall_start.elapsed() < Duration::from_millis(5500) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        samples.push(sample(&client_ctl).await);
    }

    // Longest stretch (after a short grace for the stall to take hold)
    // in which link0's tx_bytes did not advance.
    let mut max_gap = Duration::ZERO;
    let mut last_progress: Option<Instant> = None;
    for pair in samples.windows(2) {
        if pair[1].at.duration_since(stall_start) < Duration::from_millis(300) {
            continue;
        }
        let progressed = pair[1].link0_tx > pair[0].link0_tx;
        if progressed {
            last_progress = Some(pair[1].at);
        } else if let Some(lp) = last_progress {
            max_gap = max_gap.max(pair[1].at.duration_since(lp));
        } else {
            max_gap = max_gap.max(pair[1].at.duration_since(stall_start));
        }
    }
    let last = samples.last().unwrap();
    for x in &samples {
        println!(
            "t={:?} link0_tx={} link1_tx={} link1_qfull={}",
            x.at.duration_since(stall_start),
            x.link0_tx,
            x.link1_tx,
            x.link1_queue_full
        );
    }
    println!(
        "link0 tx during stall: {} -> {} bytes, longest no-progress gap {:?}, link1 queue_full={}",
        samples[0].link0_tx, last.link0_tx, max_gap, last.link1_queue_full
    );
    assert!(
        max_gap < Duration::from_millis(1200),
        "link0 stopped transmitting for {max_gap:?} while only link1 was stalled -- \
         a stalled link must not stall the others"
    );
    assert!(
        last.link0_tx - samples[0].link0_tx > 1_000_000,
        "link0 should have carried real traffic during the stall"
    );
    // Prove the stall was real (not just the scheduler never using link1):
    // link1's tx_bytes must have frozen well before the window ended.
    let tail_start = samples
        .iter()
        .find(|x| last.at.duration_since(x.at) <= Duration::from_secs(2))
        .unwrap();
    assert!(
        last.link1_tx - tail_start.link1_tx < 100_000,
        "link1 should have been stalled for the last 2s of the window (tx {} -> {})",
        tail_start.link1_tx,
        last.link1_tx
    );

    if redundant {
        assert!(
            last.link1_queue_full > 0,
            "redundant mode: link1's bounded TX queue should have filled while its socket was blocked"
        );
    }

    // --- Recovery: remove the stall; link1 must come back and carry
    // traffic again.
    ns_client
        .exec("tc", &["qdisc", "del", "dev", &vc1, "root"])
        .expect("remove tbf from client's link1 veth");
    poll_snapshot_until(&client_ctl, Duration::from_secs(25), |s| {
        link_is_up(s, "link1")
    })
    .await
    .expect("link1 never recovered to 'up' after the stall was removed");
    let recovered = sample(&client_ctl).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = sample(&client_ctl).await;
    assert!(
        after.link1_tx > recovered.link1_tx,
        "link1 should carry traffic again after recovering (tx {} -> {})",
        recovered.link1_tx,
        after.link1_tx
    );
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after link1 recovered");

    let _ = blaster.kill();
    let _ = blaster.wait();
}

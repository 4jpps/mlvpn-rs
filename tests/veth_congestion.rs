//! End-to-end test of the Phase 4 congestion telemetry and scheduling
//! (`congestion::CongestionTracker`, applied to the SWRR weights by
//! `Scheduler::update_congestion`).
//!
//! Two bonded links carry a steady ~48 Mbps UDP stream in default
//! scheduling mode. Link1 is then squeezed behind a `tbf` qdisc draining
//! at 1 Mbit/s (see `veth_tx_isolation.rs` for why `tbf` and not `netem`).
//! In this topology the pre-existing RTT/loss weighting and Down detection
//! shed link1 before its socket send ever blocks, so the congestion factor
//! itself only dips slightly here; its reaction to a genuinely backed-up
//! TX worker is covered by the `congestion` and `scheduler` unit tests.
//! This test checks what is observable end to end:
//!  - the healthy link carries the clear majority of the traffic while
//!    link1 is squeezed, with no oscillation back onto the squeezed link;
//!  - the new telemetry fields stay sane throughout (factor within
//!    [0.1, 1.0], no stuck `degraded` flag on a healthy link);
//!  - once the squeeze is removed link1 comes back up, its factor returns
//!    to ~1.0 and it carries traffic again.
//!
//! Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_congestion -- --ignored --nocapture
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
    state1: String,
    factor1: f64,
    delay1_us: u64,
    delay1_max_us: u64,
    degraded1: bool,
    queue_full1: u64,
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
    let l1 = get("link1");
    Sample {
        at: Instant::now(),
        link0_tx: get("link0").tx_bytes,
        link1_tx: l1.tx_bytes,
        state1: l1.state.clone(),
        factor1: l1.congestion_factor,
        delay1_us: l1.tx_queue_delay_us,
        delay1_max_us: l1.tx_queue_delay_max_us,
        degraded1: l1.degraded,
        queue_full1: l1.tx_queue_full_total,
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

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces -- see module doc comment"]
async fn congested_link_sheds_traffic_then_recovers() {
    let overrides = SchedulerOverrides::default;
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

    let mut blaster = spawn_blaster(&ns_client, 70, 6000);

    // --- Healthy baseline.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = sample(&client_ctl).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let healthy = sample(&client_ctl).await;
    assert!(
        healthy.link0_tx > before.link0_tx && healthy.link1_tx > before.link1_tx,
        "both links should carry traffic while healthy"
    );
    assert!(
        healthy.factor1 >= 0.9 && !healthy.degraded1,
        "a healthy link must not be penalized (factor {}, degraded {}, delay {}us)",
        healthy.factor1,
        healthy.degraded1,
        healthy.delay1_us
    );

    // --- Squeeze link1.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "tbf", "rate", "1mbit", "burst", "32kbit",
                "limit", "128mb",
            ],
        )
        .expect("squeeze client's link1 veth with tbf");
    let squeeze_start = Instant::now();
    let mut samples = vec![sample(&client_ctl).await];
    while squeeze_start.elapsed() < Duration::from_secs(14) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        samples.push(sample(&client_ctl).await);
    }
    for x in &samples {
        println!(
            "t={:5.2?} state1={} factor1={:.2} degraded={} delay={}us max={}us qfull={} l0_tx={} l1_tx={}",
            x.at.duration_since(squeeze_start),
            x.state1,
            x.factor1,
            x.degraded1,
            x.delay1_us,
            x.delay1_max_us,
            x.queue_full1,
            x.link0_tx,
            x.link1_tx
        );
    }
    let first = &samples[0];
    let last = samples.last().unwrap();
    let min_factor = samples.iter().map(|x| x.factor1).fold(1.0, f64::min);
    let any_degraded = samples.iter().any(|x| x.degraded1);
    let l0 = last.link0_tx - first.link0_tx;
    let l1 = last.link1_tx - first.link1_tx;
    println!(
        "min factor1 {min_factor:.2}, degraded seen {any_degraded}, link0 {l0} B vs link1 {l1} B"
    );
    assert!(
        samples.iter().all(|x| (0.1..=1.0).contains(&x.factor1)),
        "congestion factor left [0.1, 1.0]"
    );
    assert!(
        l0 > l1 * 3 / 2,
        "the healthy link should carry the clear majority while link1 is squeezed \
         (link0 {l0} B, link1 {l1} B)"
    );

    // --- Remove the squeeze: the factor must come back gradually.
    ns_client
        .exec("tc", &["qdisc", "del", "dev", &vc1, "root"])
        .expect("remove tbf from client's link1 veth");
    let recover_start = Instant::now();
    let mut recovered = None;
    while recover_start.elapsed() < Duration::from_secs(40) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let x = sample(&client_ctl).await;
        println!(
            "recover t={:5.2?} state1={} factor1={:.2} delay={}us",
            recover_start.elapsed(),
            x.state1,
            x.factor1,
            x.delay1_us
        );
        if x.state1 == "up" && x.factor1 >= 0.9 {
            recovered = Some(recover_start.elapsed());
            break;
        }
    }
    let recovered = recovered.expect("link1's congestion factor never recovered to >= 0.9");
    println!("link1 recovered to up / factor >= 0.9 after {recovered:?}");
    let a = sample(&client_ctl).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let b = sample(&client_ctl).await;
    assert!(
        b.link1_tx > a.link1_tx,
        "link1 should carry traffic again after recovering"
    );
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after link1 recovered");

    let _ = blaster.kill();
    let _ = blaster.wait();
}

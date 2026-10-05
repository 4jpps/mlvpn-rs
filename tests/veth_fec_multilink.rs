//! Multi-link FEC integration tests (two bonded links, `fec_parity = 2`).
//!
//! `veth_fec.rs` pins exact per-frame behavior on one link. These tests
//! instead drive a paced, sequence-numbered UDP stream through two bonded
//! links under realistic impairments and judge the outcome statistically:
//! a receiver in the server namespace counts unique, duplicate and
//! *corrupt* datagrams (every payload is a pure function of its sequence
//! number, so a parity-reconstruction bug that fabricates or mangles a
//! frame shows up as `corrupt > 0`).
//!
//! Scenarios:
//!  - random loss on link0 only, on link1 only, and on both links
//!  - a rate-limited (congested) link while FEC is on
//!  - a link whose interface goes down mid-stream, so its sends fail and
//!    are rerouted: nothing may be corrupted or duplicated, the other
//!    link must not be flooded by a reroute/bounce loop, and the link
//!    must come back afterwards
//!
//! TX isolation with FEC on (a stalled link must not stall the others)
//! lives in `veth_tx_isolation.rs`, next to its FEC-off twin.
//!
//! Needs root, `iproute2` (incl. `tc`), `python3`; see
//! `tests/support/mod.rs`. Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_fec_multilink -- --ignored --nocapture --test-threads=1
//! ```

mod support;

use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, require_tc_command, unique_id,
    veth_link_addrs, write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair,
    CLIENT_TUNNEL_ADDR, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

const PACKETS: u32 = 3000;
const PPS: u32 = 500;
const PAYLOAD_LEN: usize = 600;
const RX_PORT: u16 = 9100;

/// `argv`: host, port, count, pps. Each datagram: 4-byte big-endian seq,
/// then `PAYLOAD_LEN - 4` bytes of `(seq * 31 + i) & 0xff`.
const SENDER: &str = r#"
import socket, struct, sys, time
host, port, count, pps, plen = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
start = time.time()
sent = 0
while sent < count:
    due = min(count, int((time.time() - start) * pps) + 1)
    while sent < due:
        body = bytes(((sent * 31 + i) & 0xff) for i in range(plen - 4))
        try:
            s.sendto(struct.pack(">I", sent) + body, (host, port))
        except OSError:
            pass
        sent += 1
    time.sleep(0.001)
"#;

/// `argv`: port, seconds, plen. Prints `RESULT unique=N dup=D corrupt=C`.
const RECEIVER: &str = r#"
import socket, struct, sys, time
port, secs, plen = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
s.settimeout(0.2)
seen, dup, corrupt = set(), 0, 0
end = time.time() + secs
while time.time() < end:
    try:
        data = s.recv(4096)
    except socket.timeout:
        continue
    if len(data) != plen:
        corrupt += 1
        continue
    seq = struct.unpack(">I", data[:4])[0]
    expect = bytes(((seq * 31 + i) & 0xff) for i in range(plen - 4))
    if data[4:] != expect:
        corrupt += 1
        continue
    if seq in seen:
        dup += 1
    else:
        seen.add(seq)
print("RESULT unique=%d dup=%d corrupt=%d" % (len(seen), dup, corrupt), flush=True)
"#;

struct Rig {
    ns_client: NetNs,
    ns_server: NetNs,
    vc: [String; 2],
    _veths: [VethPair; 2],
    _server: MlvpnProcess,
    _client: MlvpnProcess,
    client_ctl: std::path::PathBuf,
    server_ctl: std::path::PathBuf,
}

async fn setup(label: &str, base_port: u16, fec: SchedulerOverrides) -> Rig {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mml{label}c{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mml{label}s{id}")).expect("create server netns");
    let vc = [format!("mmc0{id}"), format!("mmc1{id}")];
    let vs = [format!("mms0{id}"), format!("mms1{id}")];
    let (a_c0, a_s0) = veth_link_addrs(0);
    let (a_c1, a_s1) = veth_link_addrs(1);
    let veth0 =
        VethPair::create(&vc[0], &ns_client, &a_c0, &vs[0], &ns_server, &a_s0).expect("veth 0");
    let veth1 =
        VethPair::create(&vc[1], &ns_client, &a_c1, &vs[1], &ns_server, &a_s1).expect("veth 1");

    let tmp = create_scratch_dir(&format!("fecml{label}"), &id).expect("create scratch dir");
    let (client_key, client_pub) = generate_test_keypair(&tmp, "client").expect("client key");
    let (server_key, server_pub) = generate_test_keypair(&tmp, "server").expect("server key");
    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");
    let s0 = a_s0.split('/').next().unwrap();
    let s1 = a_s1.split('/').next().unwrap();
    let (p0, p1) = (base_port, base_port + 1);

    let overrides = |o: &SchedulerOverrides| SchedulerOverrides {
        fec_enabled: o.fec_enabled,
        fec_group_size: o.fec_group_size,
        fec_parity: o.fec_parity,
        fec_parity_placement: o.fec_parity_placement,
        ..Default::default()
    };
    let server_cfg = write_config(
        &tmp,
        "server",
        &format!("mml{label}s"),
        SERVER_TUNNEL_ADDR,
        &server_key,
        &client_pub,
        None,
        overrides(&fec),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs[0],
                local_port: p0,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs[1],
                local_port: p1,
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
        &format!("mml{label}c"),
        CLIENT_TUNNEL_ADDR,
        &client_key,
        &server_pub,
        None,
        overrides(&fec),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc[0],
                local_port: p0,
                local_addr: None,
                remote_addr: Some(format!("{s0}:{p0}")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc[1],
                local_port: p1,
                local_addr: None,
                remote_addr: Some(format!("{s1}:{p1}")),
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
        .expect("baseline ping across the tunnel failed");

    Rig {
        ns_client,
        ns_server,
        vc,
        _veths: [veth0, veth1],
        _server: server,
        _client: client,
        client_ctl,
        server_ctl,
    }
}

fn fec_overrides(placement: Option<&'static str>) -> SchedulerOverrides {
    SchedulerOverrides {
        fec_enabled: true,
        fec_group_size: Some(8),
        fec_parity: Some(2),
        fec_parity_placement: placement,
        ..Default::default()
    }
}

#[derive(Debug)]
struct Delivery {
    unique: u32,
    dup: u32,
    corrupt: u32,
}

impl Delivery {
    fn loss_pct(&self) -> f64 {
        100.0 * (PACKETS - self.unique.min(PACKETS)) as f64 / PACKETS as f64
    }
}

fn spawn_receiver(rig: &Rig, secs: u64) -> Child {
    let child = Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_server.name,
            "python3",
            "-c",
            RECEIVER,
        ])
        .arg(RX_PORT.to_string())
        .arg(secs.to_string())
        .arg(PAYLOAD_LEN.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn receiver (needs python3)");
    std::thread::sleep(Duration::from_millis(600));
    child
}

fn spawn_sender(rig: &Rig) -> Child {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client.name,
            "python3",
            "-c",
            SENDER,
        ])
        .arg(SERVER_TUNNEL_HOST)
        .arg(RX_PORT.to_string())
        .arg(PACKETS.to_string())
        .arg(PPS.to_string())
        .arg(PAYLOAD_LEN.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sender (needs python3)")
}

fn collect(mut sender: Child, receiver: Child) -> Delivery {
    sender.wait().expect("sender exit");
    let out = receiver.wait_with_output().expect("receiver exit");
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.starts_with("RESULT"))
        .unwrap_or_else(|| panic!("receiver printed no RESULT line: {text:?}"));
    let field = |name: &str| -> u32 {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{name}=")))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("no {name} in {line:?}"))
    };
    Delivery {
        unique: field("unique"),
        dup: field("dup"),
        corrupt: field("corrupt"),
    }
}

fn stream_secs() -> u64 {
    (PACKETS / PPS) as u64
}

/// Sends the whole stream and returns the delivery summary. `during` runs
/// concurrently once the sender is going (impairment changes mid-stream).
async fn run_stream<F, Fut>(rig: &Rig, during: F) -> Delivery
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let receiver = spawn_receiver(rig, stream_secs() + 5);
    let sender = spawn_sender(rig);
    during().await;
    collect(sender, receiver)
}

fn assert_clean(d: &Delivery, what: &str) {
    assert_eq!(d.corrupt, 0, "{what}: corrupt datagrams delivered: {d:?}");
    assert_eq!(d.dup, 0, "{what}: duplicate datagrams delivered: {d:?}");
}

async fn fec_counters(rig: &Rig) -> (u64, u64) {
    let snap = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("read server snapshot");
    (
        snap.daemon.fec_recovered_total,
        snap.daemon.fec_unrecoverable_total,
    )
}

fn netem(rig: &Rig, link: usize, loss_pct: u32) {
    rig.ns_client
        .exec(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                &rig.vc[link],
                "root",
                "netem",
                "loss",
                &format!("{loss_pct}%"),
            ],
        )
        .expect("add netem loss");
}

async fn random_loss_case(
    label: &str,
    port: u16,
    losses: [u32; 2],
    placement: Option<&'static str>,
) {
    let rig = setup(label, port, fec_overrides(placement)).await;
    let (rec0, _) = fec_counters(&rig).await;
    for (link, pct) in losses.iter().enumerate() {
        if *pct > 0 {
            netem(&rig, link, *pct);
        }
    }
    let d = run_stream(&rig, || async {}).await;
    let (rec1, unr1) = fec_counters(&rig).await;
    println!(
        "{label}: loss {losses:?}% -> delivered {}/{PACKETS} ({:.2}% lost), recovered {}, unrecoverable {unr1}, {d:?}",
        d.unique,
        d.loss_pct(),
        rec1 - rec0,
    );
    assert_clean(&d, label);
    assert!(
        rec1 > rec0,
        "{label}: FEC never recovered anything despite real loss"
    );
    assert!(
        d.loss_pct() < 1.5,
        "{label}: {:.2}% of the stream was lost despite P+Q FEC ({d:?})",
        d.loss_pct()
    );
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces"]
async fn fec_repairs_random_loss_on_link0() {
    random_loss_case("l0", 6300, [8, 0], None).await;
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces"]
async fn fec_repairs_random_loss_on_link1() {
    random_loss_case("l1", 6310, [0, 8], None).await;
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces"]
async fn fec_repairs_random_loss_on_link1_with_dominant_placement() {
    random_loss_case("ld", 6320, [0, 8], Some("dominant")).await;
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces"]
async fn fec_repairs_independent_loss_on_both_links() {
    random_loss_case("lb", 6330, [5, 5], None).await;
}

/// One link is rate-limited well below the offered load (queue overflow
/// drops, standing delay); the scheduler should lean on the other link and
/// FEC must neither corrupt nor duplicate anything while it does.
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces"]
async fn fec_with_a_congested_link_stays_clean() {
    let rig = setup("cg", 6340, fec_overrides(None)).await;
    rig.ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &rig.vc[1], "root", "tbf", "rate", "500kbit", "burst",
                "3000", "latency", "50ms",
            ],
        )
        .expect("rate-limit link1");
    let d = run_stream(&rig, || async {}).await;
    let (rec, unr) = fec_counters(&rig).await;
    println!(
        "congested: delivered {}/{PACKETS} ({:.2}% lost), recovered {rec}, unrecoverable {unr}, {d:?}",
        d.unique,
        d.loss_pct()
    );
    assert_clean(&d, "congested link");
    assert!(
        d.loss_pct() < 10.0,
        "congested link: {:.2}% lost -- the scheduler should have shifted load to link0 ({d:?})",
        d.loss_pct()
    );
    rig.ns_client
        .exec("tc", &["qdisc", "del", "dev", &rig.vc[1], "root"])
        .expect("remove rate limit");
    rig.ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("tunnel must still carry traffic after congestion");
}

/// link1's interface goes down mid-stream, so every send on it fails and is
/// rerouted to link0. With FEC on, rerouted frames and parity must still be
/// reconstructed correctly (no corruption, no duplicates), the reroute must
/// not bounce between links, and link1 must recover once the interface is
/// back.
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), python3, and network namespaces"]
async fn fec_survives_send_failure_and_reroute() {
    let rig = setup("sf", 6350, fec_overrides(None)).await;
    let before = poll_snapshot_until(&rig.client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("client snapshot");
    let tx_before: u64 = before.links.iter().map(|l| l.tx_bytes).sum();

    let d = run_stream(&rig, || async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        rig.ns_client
            .exec("ip", &["link", "set", "dev", &rig.vc[1], "down"])
            .expect("take link1's interface down");
    })
    .await;

    let after = poll_snapshot_until(&rig.client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("client snapshot");
    let link = |name: &str| after.links.iter().find(|l| l.name == name).unwrap();
    let tx_after: u64 = after.links.iter().map(|l| l.tx_bytes).sum();
    let offered = PACKETS as u64 * PAYLOAD_LEN as u64;
    let (rec, unr) = fec_counters(&rig).await;
    println!(
        "send failure: delivered {}/{PACKETS} ({:.2}% lost), recovered {rec}, unrecoverable {unr}, \
         link1 send_failed {} rerouted {}, link0 rerouted {}, bytes on wire {} for {offered} offered, {d:?}",
        d.unique,
        d.loss_pct(),
        link("link1").tx_send_failed_total,
        link("link1").tx_rerouted_total,
        link("link0").tx_rerouted_total,
        tx_after - tx_before,
    );
    assert_clean(&d, "send failure");
    assert!(
        d.loss_pct() < 10.0,
        "send failure: {:.2}% lost -- sends failing on one link should be rerouted ({d:?})",
        d.loss_pct()
    );
    // Data, parity (P+Q on 8 members = 25%), WireGuard framing and probes
    // legitimately push wire bytes well past the payload total, but a
    // reroute bounce loop would multiply them without bound.
    assert!(
        tx_after - tx_before < offered * 3,
        "wire bytes {} for {offered} offered payload bytes -- looks like a reroute loop",
        tx_after - tx_before
    );

    rig.ns_client
        .exec("ip", &["link", "set", "dev", &rig.vc[1], "up"])
        .expect("bring link1's interface back up");
    poll_snapshot_until(&rig.client_ctl, Duration::from_secs(30), |s| {
        link_is_up(s, "link1")
    })
    .await
    .expect("link1 never recovered to 'up'");
    rig.ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("tunnel must carry traffic after the link returns");
}

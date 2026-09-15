//! End-to-end test of opt-in single-erasure FEC (`scheduler.fec_enabled`,
//! `scheduler.fec_group_size`, `src/fec.rs`) -- see
//! `docs/superpowers/specs/2026-09-15-single-erasure-fec-design.md` for
//! the full design.
//!
//! Uses a single veth pair (one link, no bonding) so packet ordering and
//! group membership are fully deterministic: with only one configured
//! link, every outgoing Data frame goes out on that link's own socket in
//! the exact order `outbound_sender` reads it off the TUN device, so a
//! `tc netem loss 100%` window bracketing one `ping -c 1` invocation
//! reliably drops exactly that one frame (as opposed to `veth_diag_dump.rs`'s
//! *random*-percentage `netem loss 60%`, which is fine for driving an
//! aggregate loss-rate threshold but not for forcing an exact, individually
//! addressable frame to drop).
//!
//! Both hosts configure `fec_group_size = 4` (small and fast rather than
//! the real default of 8) and send exactly 4 ICMP pings per group, so
//! each ping maps 1:1 onto one FEC group member (client -> server
//! direction; recall reconstruction is receiver-side, so it's the
//! *server*'s `fec_recovered_total`/`fec_unrecoverable_total` that move in
//! these tests, not the client's -- see `handle_incoming`'s `FecParity`
//! arm in `tunnel.rs`).
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2` incl. `tc`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_fec -- --ignored --nocapture --test-threads=1
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::process::{Command, ExitStatus};
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, require_tc_command, unique_id,
    veth_link_addrs, write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair,
    CLIENT_TUNNEL_ADDR, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

const FEC_GROUP_SIZE: u8 = 4;

/// Runs `ping -c 1 -W <wait_secs> <host>` inside network namespace `ns`,
/// blocking until it exits. A plain wrapper around `Command` (rather than
/// `NetNs::exec`, which borrows `&self` and can't be moved into a
/// `std::thread::spawn` closure that needs to outlive the borrow) so a
/// single ping that's expected to hang waiting for a delayed/recovered
/// reply can run on its own thread while the main test thread keeps
/// driving the rest of the group's traffic concurrently.
fn ping_once(ns: &str, host: &str, wait_secs: &str) -> std::io::Result<ExitStatus> {
    Command::new("ip")
        .args([
            "netns", "exec", ns, "ping", "-c", "1", "-W", wait_secs, host,
        ])
        .status()
}

/// Test-local setup shared by all three scenarios below: two namespaces,
/// one veth pair, two `mlvpnd` processes, both configured with the given
/// `fec_enabled`/`fec_group_size` scheduler overrides. Returns everything
/// a test needs to keep driving traffic and polling snapshots -- the
/// `NetNs`/`VethPair`/`MlvpnProcess` guards must stay alive for the
/// caller's whole test body (they tear down on `Drop`), so this returns
/// them rather than taking a closure.
struct FecTestRig {
    _ns_client: NetNs,
    ns_client_name: String,
    _ns_server: NetNs,
    _veth: VethPair,
    _server: MlvpnProcess,
    _client: MlvpnProcess,
    server_ctl: std::path::PathBuf,
    vc0: String,
}

async fn setup_fec_rig(label: &str, scheduler: SchedulerOverrides) -> FecTestRig {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mfc{label}c{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mfc{label}s{id}")).expect("create server netns");

    let vc0 = format!("mfc0c{id}");
    let vs0 = format!("mfc0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let veth = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir(&format!("fec{label}"), &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    // Same `SchedulerOverrides` values on both sides -- FEC is a
    // per-direction concern (each side's own outgoing Data frames get
    // their own groups/parity), so both ends need `fec_enabled` for
    // traffic in either direction to be protected, even though these
    // tests only ever look at loss in the client -> server direction.
    let server_cfg = write_config(
        &tmp,
        "server",
        "mfcsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides {
            fec_enabled: scheduler.fec_enabled,
            fec_group_size: scheduler.fec_group_size,
            ..Default::default()
        },
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6950,
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
        "mfccli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        scheduler,
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6950,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6950")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up'");

    let ns_client_name = ns_client.name.clone();
    FecTestRig {
        _ns_client: ns_client,
        ns_client_name,
        _ns_server: ns_server,
        _veth: veth,
        _server: server,
        _client: client,
        server_ctl,
        vc0,
    }
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn single_dropped_frame_in_group_is_recovered() {
    let rig = setup_fec_rig(
        "rec",
        SchedulerOverrides {
            fec_enabled: true,
            fec_group_size: Some(FEC_GROUP_SIZE),
            ..Default::default()
        },
    )
    .await;

    // Baseline before any loss -- both counters should be 0 fresh off
    // startup, but read them explicitly rather than assuming, so this
    // test's own delta assertions below are correct even if some other
    // background traffic (a link-level probe reply, say) had somehow
    // already touched them.
    let baseline = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("read baseline server snapshot");
    let baseline_recovered = baseline.daemon.fec_recovered_total;
    let baseline_unrecoverable = baseline.daemon.fec_unrecoverable_total;

    // Member 1: sent and arrives normally, no loss yet.
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping for member 1");
    assert!(status.success(), "member 1's ping should succeed cleanly");

    // Force exactly one frame's worth of loss on the client's own egress
    // (the interface the client's Data frames actually leave on) -- 100%
    // loss, not a random percentage, so this is deterministic rather
    // than a coin flip on whether the *right* packet got dropped.
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client_name,
            "tc",
            "qdisc",
            "add",
            "dev",
            &rig.vc0,
            "root",
            "netem",
            "loss",
            "100%",
        ])
        .status()
        .expect("add netem loss to client's veth");

    // Member 2: this ping's own echo-request frame is guaranteed dropped
    // by the netem qdisc above. It should still eventually get a reply,
    // though -- FEC reconstruction only completes once members 3 and 4
    // (plus the parity frame right after member 4) have gone out, which
    // happens on the *main* test thread below while this stays blocked
    // waiting -- hence a background thread and a generous wait, instead
    // of a blocking call here on the main thread.
    let ns_for_thread = rig.ns_client_name.clone();
    let member2 = std::thread::spawn(move || ping_once(&ns_for_thread, SERVER_TUNNEL_HOST, "10"));

    // Give member 2's echo request time to actually be read off the TUN
    // device and transmitted (and thus genuinely dropped by netem)
    // before removing the qdisc -- `ping` sends its single request
    // essentially immediately on startup, so this is generous margin,
    // not a tight race.
    tokio::time::sleep(Duration::from_millis(500)).await;

    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client_name,
            "tc",
            "qdisc",
            "del",
            "dev",
            &rig.vc0,
            "root",
        ])
        .status()
        .expect("remove netem loss from client's veth");

    // Members 3 and 4: transmit normally (netem is gone). Member 4's
    // transmission is what makes `FecSender::accumulate` complete the
    // group and emit the parity frame right behind it.
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping for member 3");
    assert!(status.success(), "member 3's ping should succeed cleanly");
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping for member 4");
    assert!(status.success(), "member 4's ping should succeed cleanly");

    // Now member 2's echo-request should get reconstructed on the
    // server (once the parity frame arrives right after member 4) and
    // delivered to the server's own TUN device, producing a real ICMP
    // echo reply that eventually reaches the client -- proving actual
    // end-to-end data recovery, not just an internal counter moving.
    let member2_status = member2
        .join()
        .expect("member 2's ping thread panicked")
        .expect("run ping for member 2");
    assert!(
        member2_status.success(),
        "member 2's data should still arrive via FEC reconstruction even though its own \
         raw UDP transmission was dropped"
    );

    // And the server's own counter should reflect exactly one recovery,
    // no unrecoverable groups.
    let snapshot = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |s| {
        s.daemon.fec_recovered_total > baseline_recovered
    })
    .await
    .expect("fec_recovered_total never increased on the server");
    assert_eq!(
        snapshot.daemon.fec_recovered_total,
        baseline_recovered + 1,
        "expected exactly one FEC recovery"
    );
    assert_eq!(
        snapshot.daemon.fec_unrecoverable_total, baseline_unrecoverable,
        "a single-loss group should never count as unrecoverable"
    );
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn two_dropped_frames_in_group_are_unrecoverable() {
    let rig = setup_fec_rig(
        "unr",
        SchedulerOverrides {
            fec_enabled: true,
            fec_group_size: Some(FEC_GROUP_SIZE),
            ..Default::default()
        },
    )
    .await;

    let baseline = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("read baseline server snapshot");
    let baseline_recovered = baseline.daemon.fec_recovered_total;
    let baseline_unrecoverable = baseline.daemon.fec_unrecoverable_total;

    // Member 1: arrives normally.
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping for member 1");
    assert!(status.success(), "member 1's ping should succeed cleanly");

    // Force loss spanning exactly members 2 AND 3 -- two missing members
    // in a group of 4 is beyond single-erasure parity's own disclosed
    // limit (see `fec.rs::RecoveryOutcome::Unrecoverable`), so neither
    // should ever be recovered. Both pings are run blocking with a short
    // wait: they're expected to genuinely fail (matches today's
    // pre-FEC behavior for this case), so there's no delayed-recovery
    // reply to wait around for the way the single-loss test's member 2
    // needed a background thread for.
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client_name,
            "tc",
            "qdisc",
            "add",
            "dev",
            &rig.vc0,
            "root",
            "netem",
            "loss",
            "100%",
        ])
        .status()
        .expect("add netem loss to client's veth");

    let member2_status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "3").expect("run ping for member 2");
    assert!(
        !member2_status.success(),
        "member 2 should be genuinely lost (2-loss groups are unrecoverable)"
    );
    let member3_status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "3").expect("run ping for member 3");
    assert!(
        !member3_status.success(),
        "member 3 should be genuinely lost (2-loss groups are unrecoverable)"
    );

    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client_name,
            "tc",
            "qdisc",
            "del",
            "dev",
            &rig.vc0,
            "root",
        ])
        .status()
        .expect("remove netem loss from client's veth");

    // Member 4: transmits normally, completing the group and triggering
    // the parity frame -- which the server should find unrecoverable
    // (2 of 4 members missing) rather than crash/hang/corrupt anything.
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping for member 4");
    assert!(
        status.success(),
        "member 4's ping should still succeed normally -- a FEC failure for this group \
         must not block delivery of what did arrive"
    );

    let snapshot = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |s| {
        s.daemon.fec_unrecoverable_total > baseline_unrecoverable
    })
    .await
    .expect("fec_unrecoverable_total never increased on the server");
    assert_eq!(
        snapshot.daemon.fec_unrecoverable_total,
        baseline_unrecoverable + 1,
        "expected exactly one unrecoverable FEC group"
    );
    assert_eq!(
        snapshot.daemon.fec_recovered_total, baseline_recovered,
        "a 2-loss group should never count as recovered"
    );
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn fec_disabled_by_default_has_no_effect() {
    // Deliberately `SchedulerOverrides::default()` -- no `[scheduler]`
    // fields at all, matching a real operator who has never touched FEC
    // config. `config::SchedulerConfig::default()` already sets
    // `fec_enabled = false`, so this is the "feature never engaged"
    // baseline this whole plan needs to stay opt-in.
    let rig = setup_fec_rig("dis", SchedulerOverrides::default()).await;

    let baseline = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("read baseline server snapshot");
    assert_eq!(baseline.daemon.fec_recovered_total, 0);
    assert_eq!(baseline.daemon.fec_unrecoverable_total, 0);

    // Real traffic, including a real loss event -- if FEC's own logic
    // somehow still ran despite being disabled, this loss is exactly
    // the kind of thing that would move its counters.
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping before loss");
    assert!(status.success(), "ping should succeed cleanly");

    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client_name,
            "tc",
            "qdisc",
            "add",
            "dev",
            &rig.vc0,
            "root",
            "netem",
            "loss",
            "100%",
        ])
        .status()
        .expect("add netem loss to client's veth");
    let dropped =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "3").expect("run ping during loss");
    assert!(
        !dropped.success(),
        "this ping's frame should be genuinely dropped with no FEC to recover it"
    );
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &rig.ns_client_name,
            "tc",
            "qdisc",
            "del",
            "dev",
            &rig.vc0,
            "root",
        ])
        .status()
        .expect("remove netem loss from client's veth");
    let status =
        ping_once(&rig.ns_client_name, SERVER_TUNNEL_HOST, "5").expect("run ping after loss");
    assert!(status.success(), "ping should succeed cleanly again");

    // Poll once more (rather than just re-checking `baseline`) to give
    // any would-be-buggy FEC codepath a real chance to have moved these
    // counters by now.
    let snapshot = poll_snapshot_until(&rig.server_ctl, Duration::from_secs(5), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("read post-traffic server snapshot");
    assert_eq!(
        snapshot.daemon.fec_recovered_total, 0,
        "fec_recovered_total must stay 0 when scheduler.fec_enabled is false"
    );
    assert_eq!(
        snapshot.daemon.fec_unrecoverable_total, 0,
        "fec_unrecoverable_total must stay 0 when scheduler.fec_enabled is false"
    );
}

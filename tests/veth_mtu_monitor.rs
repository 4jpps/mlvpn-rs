//! End-to-end test of `control::mtu_monitor_loop` (Task 11): the running
//! TUN device's live MTU should track whatever the bonded links can
//! actually carry, continuously -- not just once at startup.
//!
//! Sequence:
//!
//! 1. Bring up a tunnel over a veth pair with the default (kernel) MTU,
//!    ~1500 bytes on each end.
//! 2. Confirm the TUN device's initial MTU (read directly via
//!    `ip -o link show`, since `ipc::TunSnapshot` doesn't carry MTU) is
//!    the auto-detected safe value derived from that ~1500-byte physical
//!    MTU -- specifically NOT the old hardcoded 1400 fallback, which
//!    would only apply if nothing were detected at all.
//! 3. Lower the client's own veth interface's MTU mid-test with
//!    `ip link set dev <veth> mtu 1300`, with no daemon restart.
//! 4. Wait past `control::MTU_MONITOR_INTERVAL_SECS` (30s; not directly
//!    importable here since `mtu_monitor_loop` is `pub(crate)` -- see
//!    that module's doc comment) plus a safety margin, then confirm the
//!    TUN device's live MTU has converged down to match, proving
//!    `mtu_monitor_loop` re-queried the link, recomputed
//!    `effective_tunnel_mtu`, and called `link::set_interface_mtu` on
//!    its own.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_mtu_monitor -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::process::Command;
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR,
};

/// Reads a network interface's current kernel-reported MTU inside a given
/// network namespace, via `ip -o link show dev <ifname>`. Parses the
/// plain-text `ip` output (`... mtu 1452 ...`) rather than `ip -j` +
/// JSON, since nothing else in this test suite depends on a JSON parser
/// being available and this is a simple, stable token to grep for.
fn read_interface_mtu(ns: &str, ifname: &str) -> Option<u32> {
    let output = Command::new("ip")
        .args(["netns", "exec", ns, "ip", "-o", "link", "show", "dev", ifname])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "mtu" {
            return tokens.next()?.parse().ok();
        }
    }
    None
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn tun_device_mtu_converges_after_a_live_link_mtu_change() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mmmc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mmms{id}")).expect("create server netns");

    let vc0 = format!("mmm0c{id}");
    let vs0 = format!("mmm0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("mtumonitor", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    // Fixed, short tunnel-device names (well within IFNAMSIZ's 16-byte
    // limit incl. NUL terminator) -- each test runs in its own network
    // namespace, so there's no cross-test collision risk despite not
    // suffixing these with `id` the way the veth interface names above
    // are.
    let server_tun_name = "mtumonsrv0";
    let client_tun_name = "mtumoncli0";

    let server_cfg = write_config(
        &tmp,
        "server",
        server_tun_name,
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6920,
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
        client_tun_name,
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6920,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6920")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let (_server, _server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, _client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up'");

    // Step 2: initial MTU should be the auto-detected safe value derived
    // from the veth pair's real (~1500-byte) physical MTU, not the
    // hardcoded 1400 fallback -- that fallback only applies when nothing
    // at all was detected, which isn't the case here.
    let initial_mtu = poll_until_some(
        Duration::from_secs(10),
        || read_interface_mtu(&ns_client.name, client_tun_name),
    )
    .await
    .expect("tun device never reported an MTU");
    assert_ne!(
        initial_mtu, 1400,
        "initial tunnel MTU should be auto-detected from the veth pair's real physical MTU, \
         not the hardcoded fallback"
    );
    assert!(
        initial_mtu > 1400 && initial_mtu < 1500,
        "expected initial MTU derived from a ~1500-byte physical link minus protocol overhead, \
         got {initial_mtu}"
    );

    // Step 3: lower the client's own veth interface's MTU mid-test, with
    // no daemon restart.
    ns_client
        .exec("ip", &["link", "set", "dev", &vc0, "mtu", "1300"])
        .expect("lower client veth MTU to 1300");

    // Step 4: wait past control::MTU_MONITOR_INTERVAL_SECS (30s) plus a
    // safety margin, then confirm the TUN device's live MTU converged
    // down to match the new, lower physical MTU.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(50);
    let mut converged_mtu = None;
    while tokio::time::Instant::now() < deadline {
        if let Some(mtu) = read_interface_mtu(&ns_client.name, client_tun_name) {
            if mtu < initial_mtu {
                converged_mtu = Some(mtu);
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let converged_mtu = converged_mtu.expect(
        "mtu_monitor_loop never resized the tun device's MTU down within 50s of the veth MTU drop",
    );
    assert!(
        converged_mtu < initial_mtu,
        "expected the tun device's MTU to shrink from {initial_mtu} after lowering the veth \
         MTU to 1300, got {converged_mtu}"
    );
    assert!(
        converged_mtu > 1100 && converged_mtu < 1300,
        "expected the resized MTU to be derived from the new 1300-byte physical MTU minus \
         protocol overhead, got {converged_mtu}"
    );
}

/// Polls `f` every 500ms until it returns `Some`, or `timeout` elapses
/// (returning `None`). Used above only for the initial-MTU read, which
/// should succeed almost immediately once the tun device exists but
/// needs a small grace window against the daemon's own startup timing.
async fn poll_until_some<F, T>(timeout: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Option<T>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

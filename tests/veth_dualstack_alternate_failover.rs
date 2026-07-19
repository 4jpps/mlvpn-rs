//! End-to-end test of `tunnel::resolve_remaining_alternates`, the fix
//! for a real bug: a client-mode link whose `remote_addr` hostname
//! resolves to both an `A` and `AAAA` record used to only get its own
//! primary-vs-alternate family ambiguity resolved if it happened to be
//! the *one* link whose reply won the tunnel's overall initial-handshake
//! race across every configured link (see `perform_client_handshake`'s
//! doc comment: the peer deduplicates every copy of that broadcast by
//! `session_id`, so only the very first arrival, across *all* targets,
//! ever gets a real reply -- every other link, and every other family on
//! whichever link did win, gets nothing). Every *other* link used to
//! just keep `pick_remote_addr`'s IPv6-preferred guess and silently
//! drop its untested alternate -- if that guess happened to be wrong, in
//! practice reported as "IPv6 is disabled on this interface, but the
//! link is stuck trying to use it anyway," the link would sit in
//! `Probing` forever, having never gotten a real chance to fail over.
//!
//! Reproduces exactly that shape without needing to actually disable
//! IPv6 anywhere: link0 is a plain, fast, always-reachable IPv4 link
//! (biased with `tc netem delay` on link1 to make sure it -- not
//! link1's own alternate -- reliably wins the very first handshake
//! round, so this test deterministically exercises the *post*-handshake
//! path rather than depending on which one happens to win). link1's
//! `remote_addr` is a hostname (added to `/etc/hosts` for the duration
//! of this test -- see `HostsEntryGuard` below; shared with the host
//! since `ip netns exec` isolates the network stack, not the
//! filesystem) resolving to *both* the server's real, reachable IPv6
//! address for link1 (a real ULA `/64`, genuine L3 connectivity, see
//! `veth_link_addrs6`) and its IPv4 one -- but the server's link1
//! socket, like every link's socket in this project (see
//! `link::bind_socket`'s `IPV6_V6ONLY` comment), is strictly
//! single-family, and defaults to IPv4 since its config sets no
//! `local_addr`. So link1's IPv6 primary is a real, fully-routable path
//! to a peer that simply isn't listening on it: exactly "the DNS record
//! exists and the network path works, but this specific candidate can
//! never succeed," the same failure shape IPv6-disabled-on-the-interface
//! produces, just constructed without needing root-level sysctl
//! manipulation of the veth interface itself.
//!
//! Asserts link1 still reaches "up" (via its IPv4 alternate, promoted by
//! `resolve_remaining_alternates` after losing the initial race to
//! link0) and that the client logged the alternate-promotion line for
//! it.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2` incl. `tc`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_dualstack_alternate_failover -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, require_tc_command, unique_id,
    veth_link_addrs, veth_link_addrs6, write_config, LinkSpec, MlvpnProcess, NetNs,
    SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

/// Appends a temporary `/etc/hosts` entry (two lines: one `A`, one
/// `AAAA`-equivalent -- `/etc/hosts` has no record-type distinction, an
/// IPv4 and an IPv6 line for the same hostname is exactly how a real
/// dual-stack DNS response looks to `getaddrinfo`/`tokio::net::lookup_host`)
/// and removes exactly those two lines again on drop, even if the test
/// panics. `/etc/hosts` is a real, shared, host-level file -- `ip netns
/// exec` isolates the network stack, not the filesystem -- so this is
/// the one piece of this test that touches something outside its own
/// scratch directory or network namespaces. The hostname is always
/// `unique_id()`-suffixed, so concurrent test runs (or a leftover entry
/// from a prior run that panicked before cleanup, extremely unlikely
/// given `Drop` still runs on panic) can never collide with each other.
struct HostsEntryGuard {
    hostname: String,
}

impl HostsEntryGuard {
    fn add(hostname: &str, addr4: &str, addr6: &str) -> std::io::Result<Self> {
        let mut f = OpenOptions::new().append(true).open("/etc/hosts")?;
        writeln!(f, "{addr4} {hostname} # mlvpn-test-temp")?;
        writeln!(f, "{addr6} {hostname} # mlvpn-test-temp")?;
        Ok(Self {
            hostname: hostname.to_string(),
        })
    }
}

impl Drop for HostsEntryGuard {
    fn drop(&mut self) {
        let Ok(content) = std::fs::read_to_string("/etc/hosts") else {
            return;
        };
        let filtered: String = content
            .lines()
            .filter(|line| !(line.contains(&self.hostname) && line.contains("mlvpn-test-temp")))
            .map(|line| format!("{line}\n"))
            .collect();
        let _ = std::fs::write("/etc/hosts", filtered);
    }
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn losing_link_still_fails_over_to_its_working_alternate_family() {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mdac{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mdas{id}")).expect("create server netns");

    let vc0 = format!("mda0c{id}");
    let vs0 = format!("mda0s{id}");
    let vc1 = format!("mda1c{id}");
    let vs1 = format!("mda1s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);
    let (addr_c1_6, addr_s1_6) = veth_link_addrs6(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0 (link0, plain IPv4, the fast/anchor link)");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1 (link1, IPv4 base)");
    // Layer a real, routable IPv6 address on top of link1's existing
    // IPv4 one, on *both* ends -- genuine dual-stack L3 connectivity,
    // same as a real dual-stack uplink.
    ns_client
        .exec("ip", &["addr", "add", &addr_c1_6, "dev", &vc1])
        .expect("add IPv6 address to client's link1 veth");
    ns_server
        .exec("ip", &["addr", "add", &addr_s1_6, "dev", &vs1])
        .expect("add IPv6 address to server's link1 veth");

    // Bias the initial handshake race so link0 -- not link1's own IPv4
    // alternate -- reliably wins it, so this test deterministically
    // exercises `resolve_remaining_alternates`'s *post*-handshake path
    // rather than depending on which one happens to answer first.
    // link0 has no delay at all; even the 100ms round trip this adds is
    // trivially within `perform_client_handshake`'s 500ms per-attempt
    // timeout, just not competitive against link0's real veth-speed
    // reply.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "netem", "delay", "100ms",
            ],
        )
        .expect("add netem delay to client's link1 veth");
    ns_server
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vs1, "root", "netem", "delay", "100ms",
            ],
        )
        .expect("add netem delay to server's link1 veth");

    let tmp = create_scratch_dir("dualstackfo", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();
    let server_addr_1 = addr_s1.split('/').next().unwrap();
    let server_addr_1_6 = addr_s1_6.split('/').next().unwrap();

    // A synthetic hostname resolving to *both* of the server's link1
    // addresses -- exactly what a real dual-stack DNS name looks like
    // to the resolver `link::resolve_remote_addr` calls.
    let hostname = format!("mlvpn-dualstack-test-{id}.invalid");
    let _hosts_guard = HostsEntryGuard::add(&hostname, server_addr_1, server_addr_1_6)
        .expect("add temporary /etc/hosts entry for the dual-stack test hostname");

    let server_cfg = write_config(
        &tmp,
        "server",
        "mdasrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6920,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6921,
                // No local_addr set -- link::socket_domain defaults this
                // link's socket to plain IPv4 (see that function's doc
                // comment), even though the interface itself also has a
                // real, working IPv6 address. This is the crux of the
                // reproduction: link1's IPv6 candidate is a genuinely
                // routable path to a peer that simply never listens on
                // it for this link.
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
        "mdacli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6920,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6920")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6921,
                local_addr: None,
                // The hostname, not a literal address -- this is what
                // makes `link::resolve_remote_addr` actually go through
                // DNS resolution and `pick_remote_addr`'s dual-stack
                // primary/alternate selection at all.
                remote_addr: Some(format!("{hostname}:6921")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let (_server, _server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 (the anchor link) never reached 'up'");

    // The real assertion: link1, which lost the initial handshake race
    // (per the netem delay bias above) and whose IPv6 primary can never
    // work, should still reach 'up' -- via `resolve_remaining_alternates`
    // promoting its IPv4 alternate after the fact, not by luck.
    poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        link_is_up(s, "link1")
    })
    .await
    .expect(
        "link1 never reached 'up' -- resolve_remaining_alternates should have promoted its \
         IPv4 alternate after losing the initial handshake race to link0",
    );

    assert!(
        client_logs
            .wait_for_line_containing(
                "alternate address family confirmed reachable",
                Duration::from_secs(5),
            )
            .await,
        "client never logged the alternate-promotion line for link1"
    );

    // Real Data traffic should flow across both links normally
    // afterward -- resolving link1's alternate mid-startup must not
    // have left anything in a broken state.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after dual-stack alternate failover");
}

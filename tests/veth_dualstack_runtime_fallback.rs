//! End-to-end test of the runtime address-family fallback
//! (`tunnel::family_fallback_watch` + `link::probe_other_family`): a
//! client link whose `remote_addr` hostname resolves to both an IPv4 and
//! an IPv6 address comes up on one family, that family then stops working
//! mid-session, and the link must move itself to the other family and come
//! back up without a restart. Before this existed the family was chosen
//! once at startup and a link stayed down until `mlvpnd` restarted.
//!
//! The server's link socket is `dual_stack` (one `[::]` socket for both
//! families), as on a real dual-stack server. Whichever family the startup
//! race picked is then broken by deleting the server veth's address in that
//! family, which leaves the other family's path fully working.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Takes about a minute:
//! the fallback deliberately waits 30 s of downtime before acting. Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_dualstack_runtime_fallback -- --ignored --nocapture
//! ```

mod support;

use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
    SchedulerOverrides, VethPair, create_scratch_dir, ensure_mlvpn_system_user,
    generate_test_keypair, link_is_up, poll_snapshot_until, require_ip_command, require_root,
    unique_id, veth_link_addrs, veth_link_addrs6, write_config,
};

/// Temporary dual-stack `/etc/hosts` entry, removed on drop (same as
/// `veth_dualstack_alternate_failover.rs`'s guard).
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

fn link_remote(snapshot: &mlvpn::ipc::Snapshot, link_name: &str) -> Option<String> {
    snapshot
        .links
        .iter()
        .find(|l| l.name == link_name)
        .and_then(|l| l.remote_addr.clone())
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn link_moves_to_the_other_family_when_its_family_dies_mid_session() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mdrc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mdrs{id}")).expect("create server netns");

    let vc = format!("mdr0c{id}");
    let vs = format!("mdr0s{id}");
    let (addr_c, addr_s) = veth_link_addrs(0);
    let (addr_c6, addr_s6) = veth_link_addrs6(0);
    let _veth = VethPair::create(&vc, &ns_client, &addr_c, &vs, &ns_server, &addr_s)
        .expect("create veth pair");
    ns_client
        .exec("ip", &["addr", "add", &addr_c6, "dev", &vc, "nodad"])
        .expect("add IPv6 address to client veth");
    ns_server
        .exec("ip", &["addr", "add", &addr_s6, "dev", &vs, "nodad"])
        .expect("add IPv6 address to server veth");

    let tmp = create_scratch_dir("dualstackrt", &id).expect("create scratch dir");
    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");
    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_v4 = addr_s.split('/').next().unwrap();
    let server_v6 = addr_s6.split('/').next().unwrap();
    let hostname = format!("mlvpn-dualstack-rt-{id}.invalid");
    let _hosts_guard =
        HostsEntryGuard::add(&hostname, server_v4, server_v6).expect("add /etc/hosts entry");

    let server_cfg = write_config(
        &tmp,
        "server",
        "mdrsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs,
            local_port: 6930,
            local_addr: None,
            dual_stack: true,
            remote_addr: None,
        }],
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
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc,
            local_port: 6930,
            local_addr: None,
            dual_stack: false,
            remote_addr: Some(format!("{hostname}:6930")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let (_server, _server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    let snap = poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never came up at startup");
    let first = link_remote(&snap, "link0").expect("link0 has no remote address");
    let started_on_v6 = first.starts_with('[');
    eprintln!("link0 came up on {first}; breaking that family now");

    // Break the family in use; the other one keeps working.
    let doomed = if started_on_v6 { &addr_s6 } else { &addr_s };
    ns_server
        .exec("ip", &["addr", "del", doomed, "dev", &vs])
        .expect("delete the server's address in the family in use");

    poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        !link_is_up(s, "link0")
    })
    .await
    .expect("link0 never noticed its family died");

    // 30 s fallback delay + up to 5 s watch tick + the probe itself.
    let snap = poll_snapshot_until(&client_ctl, Duration::from_secs(90), |s| {
        link_is_up(s, "link0")
            && link_remote(s, "link0").is_some_and(|r| r.starts_with('[') != started_on_v6)
    })
    .await
    .expect("link0 never came back up on the other address family");
    eprintln!(
        "link0 is back up on {}",
        link_remote(&snap, "link0").unwrap_or_default()
    );

    assert!(
        client_logs
            .wait_for_line_containing("the other one answered; switching", Duration::from_secs(5))
            .await,
        "client never logged the runtime family switch"
    );
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the runtime family switch");
}

//! End-to-end test of IPv6 support on the bonded links themselves
//! (`link::socket_domain`, `link::bind_socket` -- see `ARCHITECTURE.md`
//! §11, "IPv6 on the bonded links themselves," now closed). Distinct
//! from `tunnel.address6` (the TUN interface's own optional IPv6
//! address, already covered elsewhere) -- this is about the *transport*
//! sockets between the two `mlvpnd` instances.
//!
//! Bonds one ordinary IPv4 link (link0, identical to every other test's
//! link0) with one IPv6-only link (link1, addressed from a ULA `/64` --
//! see `veth_link_addrs6`), so this proves a single tunnel can carry
//! both address families across its bonded links at once, not just that
//! an all-IPv6 tunnel happens to work in isolation. The server's link1
//! has no `remote_addr` (learned at runtime, as usual) but does set
//! `local_addr = "::"` so `link::socket_domain` has something to infer
//! IPv6 from on that side -- see that function's doc comment.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_ipv6_link -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    veth_link_addrs6, write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair,
    CLIENT_TUNNEL_ADDR, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn bonded_tunnel_carries_traffic_over_a_mixed_ipv4_ipv6_link_set() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtic{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtis{id}")).expect("create server netns");

    let vc0 = format!("mic0{id}");
    let vs0 = format!("mis0{id}");
    let vc1 = format!("mic1{id}");
    let vs1 = format!("mis1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs6(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0 (IPv4)");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1 (IPv6)");

    let tmp = create_scratch_dir("ipv6link", &id).expect("create scratch dir");

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
        "mipsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6700,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6701,
                // No remote_addr (learned at runtime, as usual) -- this
                // is what tells socket_domain to bind IPv6 for a
                // server-side link that has nothing else to infer it
                // from. "::" (any local IPv6 address), same as
                // link0 implicitly relies on "0.0.0.0" for IPv4.
                local_addr: Some("::"),
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
        "mipcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6700,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6700")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6701,
                local_addr: None,
                // Bracketed, the standard SocketAddr string form for
                // IPv6 -- this alone is enough for socket_domain to
                // infer IPv6 on the client side.
                remote_addr: Some(format!("[{server_addr_1}]:6701")),
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
    .expect("both the IPv4 and IPv6 links never reached 'up'");

    // Traffic should bond across both address families exactly like it
    // bonds across any other pair of links.
    ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the mixed IPv4/IPv6-link tunnel failed");
}

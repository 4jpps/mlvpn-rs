//! End-to-end test of the per-link `tx_send_mode = "sendmmsg"` option.
//!
//! Two links between client and server: `link0` runs `sendmmsg` (or
//! `sendmmsg_gso`, in the second test) on both
//! ends, `link1` keeps the default `sendto` -- so the test also covers the
//! per-link, mixed-mode case. A real tunnel comes up, the TX worker logs
//! which mode it picked, and a burst of full-size pings (which the
//! scheduler spreads over both links) must come back with zero loss.
//!
//! `write_config` has no knob for this option and ~25 other tests call it,
//! so the option is spliced into the written TOML here instead.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_tx_send_mode -- --ignored --nocapture
//! ```

mod support;

use std::path::Path;
use std::process::Command;
use std::time::Duration;
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
    SchedulerOverrides, VethPair, create_scratch_dir, ensure_mlvpn_system_user,
    generate_test_keypair, link_is_up, poll_snapshot_until, require_ip_command, require_root,
    unique_id, veth_link_addrs, write_config,
};

fn enable_mode_on_link0(config_path: &Path, mode: &str) {
    let toml = std::fs::read_to_string(config_path).expect("read config");
    let needle = "name = \"link0\"\n";
    assert_eq!(toml.matches(needle).count(), 1, "link0 block not found");
    let toml = toml.replace(needle, &format!("{needle}tx_send_mode = \"{mode}\"\n"));
    std::fs::write(config_path, toml).expect("rewrite config");
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn sendmmsg_link_carries_traffic_with_no_loss_alongside_a_sendto_link() {
    run_mixed_mode("sendmmsg", "TX send mode: sendmmsg (batched)").await;
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn sendmmsg_gso_link_carries_traffic_with_no_loss_alongside_a_sendto_link() {
    run_mixed_mode("sendmmsg_gso", "TX send mode: sendmmsg_gso").await;
}

async fn run_mixed_mode(mode: &str, expect_log: &str) {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtmc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtms{id}")).expect("create server netns");

    let (vc0, vs0) = (format!("mtm0c{id}"), format!("mtm0s{id}"));
    let (vc1, vs1) = (format!("mtm1c{id}"), format!("mtm1s{id}"));
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir("txsendmode", &id).expect("create scratch dir");
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
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6940,
                local_addr: None,
                dual_stack: false,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6941,
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
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6940,
                local_addr: None,
                dual_stack: false,
                remote_addr: Some(format!("{server_addr_0}:6940")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6941,
                local_addr: None,
                dual_stack: false,
                remote_addr: Some(format!("{server_addr_1}:6941")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    enable_mode_on_link0(&server_cfg, mode);
    enable_mode_on_link0(&client_cfg, mode);

    let (_server, server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    for link in ["link0", "link1"] {
        poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
            link_is_up(s, link)
        })
        .await
        .unwrap_or_else(|_| panic!("{link} never reached 'up'"));
    }

    for (who, logs) in [("client", &client_logs), ("server", &server_logs)] {
        assert!(
            logs.wait_for_line_containing(expect_log, Duration::from_secs(5))
                .await,
            "{who} never logged that link0's TX worker picked {mode}"
        );
    }

    // Full-size pings through the tunnel, fast enough that the TX workers
    // see multi-packet batches. Zero loss is the pass criterion.
    let out = Command::new("ip")
        .args(["netns", "exec", &ns_client.name, "ping"])
        .args(["-c", "500", "-i", "0.003", "-s", "1200", "-W", "2", "-q"])
        .arg(SERVER_TUNNEL_HOST)
        .output()
        .expect("run ping");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(" 0% packet loss"),
        "ping across a {mode}+sendto bonded tunnel lost packets:\n{stdout}"
    );

    for link in ["link0", "link1"] {
        poll_snapshot_until(&client_ctl, Duration::from_secs(5), |s| link_is_up(s, link))
            .await
            .unwrap_or_else(|_| panic!("{link} not 'up' after the ping burst"));
    }
}

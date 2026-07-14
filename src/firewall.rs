//! Firewall integration for `mlvpnd firewall-setup`.
//!
//! Opens (or, with `--remove`, closes) inbound UDP access on every port
//! this config's `[[links]]` bind to, on whichever firewall backend is
//! actually managing this host's packet filtering: `firewalld`, `ufw`,
//! `nftables`, or `iptables` (legacy). Ports are opened regardless of
//! `client`/`server` mode: a client dialing out still benefits from an
//! explicit allow rule on hosts with a strict default-deny inbound
//! policy that doesn't reliably track UDP "return" traffic as
//! established -- most stateful firewalls do this automatically, but an
//! explicit rule makes the tunnel work regardless of that assumption.
//!
//! This is deliberately a separate one-shot CLI subcommand
//! (`mlvpnd firewall-setup`), not something `mlvpnd run` does silently
//! on every startup: mutating system firewall state is a materially
//! different trust boundary than anything else this daemon does (every
//! other privileged action -- opening the TUN device, binding sockets --
//! only touches resources the process itself then owns and uses).
//! Making it an explicit, auditable, `--dry-run`-able admin action keeps
//! that boundary visible instead of hiding it inside a `systemctl start`.
//!
//! Every command below is run as an argv vector (`Command::new(program)
//! .arg(...)`), never through a shell, so there is no command-injection
//! surface even though ports ultimately come from an admin-editable
//! config file.
//!
//! Backend priority when more than one is present: an *active* higher-
//! level manager (`firewalld`, `ufw`) wins over touching `nftables`/
//! `iptables` directly, since rules added straight to the kernel
//! ruleset risk being silently wiped out the next time that manager
//! reloads its own generated configuration.

use crate::config::Config;
use crate::error::{MlvpnError, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Firewalld,
    Ufw,
    Nftables,
    IptablesLegacy,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::Firewalld => "firewalld",
            Backend::Ufw => "ufw",
            Backend::Nftables => "nftables",
            Backend::IptablesLegacy => "iptables (legacy)",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "firewalld" => Some(Backend::Firewalld),
            "ufw" => Some(Backend::Ufw),
            "nftables" | "nft" => Some(Backend::Nftables),
            "iptables" | "iptables-legacy" => Some(Backend::IptablesLegacy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Remove,
}

/// One command this tool would run (or, under `--dry-run`, would have
/// run), kept as a plain argv vector -- never a shell string -- plus a
/// human-readable label for `--dry-run` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCommand {
    pub label: String,
    pub program: String,
    pub args: Vec<String>,
}

impl PlannedCommand {
    fn new(label: impl Into<String>, program: &str, args: Vec<String>) -> Self {
        Self {
            label: label.into(),
            program: program.to_string(),
            args,
        }
    }

    /// Rendered the same way a shell-quoted invocation would read, for
    /// `--dry-run` output only -- never actually parsed back into a
    /// shell.
    pub fn display(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.args {
            s.push(' ');
            if a.is_empty() || a.contains(char::is_whitespace) {
                s.push('\'');
                s.push_str(a);
                s.push('\'');
            } else {
                s.push_str(a);
            }
        }
        s
    }
}

/// Every UDP port this config's links need inbound access for.
pub fn required_ports(cfg: &Config) -> BTreeSet<u16> {
    cfg.links.iter().map(|l| l.local_port).collect()
}

/// Detect the actively-managing firewall backend on this host. Returns
/// `None` if nothing recognized is installed/active.
pub fn detect_backend() -> Option<Backend> {
    if is_firewalld_active() {
        return Some(Backend::Firewalld);
    }
    if is_ufw_active() {
        return Some(Backend::Ufw);
    }
    if command_exists("nft") {
        return Some(Backend::Nftables);
    }
    if command_exists("iptables") {
        return Some(Backend::IptablesLegacy);
    }
    None
}

fn command_exists(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

fn is_firewalld_active() -> bool {
    // `firewall-cmd --state` prints "running" and exits 0 only when the
    // daemon is actually up, not merely installed.
    Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_ufw_active() -> bool {
    Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).starts_with("Status: active")
        })
        .unwrap_or(false)
}

/// Top-level entry point for the `firewalld-setup` CLI subcommand.
pub fn run(
    cfg: &Config,
    dry_run: bool,
    action: Action,
    backend_override: Option<&str>,
) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(MlvpnError::Privilege(
            "firewall-setup must run as root (it inspects and modifies system firewall state); \
             re-run with sudo"
                .into(),
        ));
    }

    let backend = match backend_override {
        Some(s) => Backend::parse(s).ok_or_else(|| {
            MlvpnError::Config(format!(
                "unrecognized --backend '{s}'; expected one of: firewalld, ufw, nftables, iptables"
            ))
        })?,
        None => detect_backend().ok_or_else(|| {
            MlvpnError::Config(
                "no supported firewall backend detected (checked: firewalld, ufw, nft, \
                 iptables). Nothing to do -- open these UDP ports manually if your host \
                 filters inbound traffic by default."
                    .into(),
            )
        })?,
    };

    let ports = required_ports(cfg);
    if ports.is_empty() {
        println!("no [[links]] configured; nothing to open.");
        return Ok(());
    }

    println!(
        "backend: {} | ports: {} | action: {}",
        backend.name(),
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        match action {
            Action::Add => "open",
            Action::Remove => "close",
        }
    );

    let planned = plan_commands(backend, &ports, action)?;
    if planned.is_empty() {
        println!("already up to date; nothing to change.");
        return Ok(());
    }

    for cmd in &planned {
        if dry_run {
            println!("[dry-run] {}  # {}", cmd.display(), cmd.label);
        } else {
            println!("+ {}  # {}", cmd.display(), cmd.label);
            let status = Command::new(&cmd.program)
                .args(&cmd.args)
                .status()
                .map_err(MlvpnError::Io)?;
            if !status.success() {
                return Err(MlvpnError::Config(format!(
                    "command failed ({status}): {}",
                    cmd.label
                )));
            }
        }
    }

    if dry_run {
        println!("dry run only -- nothing was changed. Re-run without --dry-run to apply.");
    } else {
        println!("done.");
    }
    Ok(())
}

/// Build the full command plan for a backend/port-set/action. Backends
/// that need to inspect live state (currently just nftables, to find
/// existing chains and rule handles) do their own I/O inline; the
/// others are pure functions of their inputs.
fn plan_commands(
    backend: Backend,
    ports: &BTreeSet<u16>,
    action: Action,
) -> Result<Vec<PlannedCommand>> {
    match backend {
        Backend::Firewalld => Ok(plan_firewalld(ports, action)),
        Backend::Ufw => Ok(plan_ufw(ports, action)),
        Backend::IptablesLegacy => plan_iptables(ports, action),
        Backend::Nftables => plan_nftables(ports, action),
    }
}

fn plan_firewalld(ports: &BTreeSet<u16>, action: Action) -> Vec<PlannedCommand> {
    let flag = match action {
        Action::Add => "--add-port",
        Action::Remove => "--remove-port",
    };
    let mut cmds: Vec<PlannedCommand> = ports
        .iter()
        .map(|p| {
            PlannedCommand::new(
                format!("{p}/udp via firewalld"),
                "firewall-cmd",
                vec!["--permanent".to_string(), format!("{flag}={p}/udp")],
            )
        })
        .collect();
    cmds.push(PlannedCommand::new(
        "apply permanent changes immediately",
        "firewall-cmd",
        vec!["--reload".to_string()],
    ));
    cmds
}

fn plan_ufw(ports: &BTreeSet<u16>, action: Action) -> Vec<PlannedCommand> {
    ports
        .iter()
        .map(|p| match action {
            Action::Add => PlannedCommand::new(
                format!("{p}/udp via ufw"),
                "ufw",
                vec!["allow".to_string(), format!("{p}/udp")],
            ),
            Action::Remove => PlannedCommand::new(
                format!("{p}/udp via ufw"),
                "ufw",
                vec![
                    "delete".to_string(),
                    "allow".to_string(),
                    format!("{p}/udp"),
                ],
            ),
        })
        .collect()
}

fn plan_iptables(ports: &BTreeSet<u16>, action: Action) -> Result<Vec<PlannedCommand>> {
    let mut out = Vec::new();
    for &p in ports {
        let rule_args = |p: u16| -> Vec<String> {
            vec![
                "INPUT".to_string(),
                "-p".to_string(),
                "udp".to_string(),
                "--dport".to_string(),
                p.to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]
        };
        match action {
            Action::Add => {
                // -C (check) is iptables' own idempotency primitive:
                // exits 0 if the exact rule already exists. Skip
                // planning an insert when it does, so re-running this
                // command doesn't pile up duplicate rules.
                let mut check_args = vec!["-C".to_string()];
                check_args.extend(rule_args(p));
                let already_present = Command::new("iptables")
                    .args(&check_args)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if already_present {
                    continue;
                }
                let mut insert_args = vec!["-I".to_string(), "INPUT".to_string(), "1".to_string()];
                insert_args.extend_from_slice(&rule_args(p)[1..]);
                out.push(PlannedCommand::new(
                    format!("{p}/udp via iptables"),
                    "iptables",
                    insert_args,
                ));
            }
            Action::Remove => {
                let mut delete_args = vec!["-D".to_string()];
                delete_args.extend(rule_args(p));
                out.push(PlannedCommand::new(
                    format!("{p}/udp via iptables"),
                    "iptables",
                    delete_args,
                ));
            }
        }
    }
    Ok(out)
}

/// nftables needs to inspect the live ruleset first: unlike a single
/// linear iptables chain, an nftables host may have any number of base
/// chains hooked at `input`, spread across different tables, and we
/// have no way to know their names in advance. To stay correct without
/// having to reason about cross-chain/cross-priority evaluation order
/// (genuinely ambiguous in general -- see the nftables docs on multiple
/// base chains sharing a hook), this inserts the same accept rule into
/// *every* base chain of type `filter` hooked at `input`, rather than
/// guessing which single one is authoritative. Worst case that's a
/// harmless duplicate rule in an unusual multi-table setup; it never
/// creates a new hook of its own or touches anything but chains that
/// already existed.
fn plan_nftables(ports: &BTreeSet<u16>, action: Action) -> Result<Vec<PlannedCommand>> {
    let output = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(MlvpnError::Io)?;
    if !output.status.success() {
        return Err(MlvpnError::Config(format!(
            "`nft -j list ruleset` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| MlvpnError::Config(format!("parsing `nft -j list ruleset` output: {e}")))?;

    let chains = find_input_filter_chains(&json);
    if chains.is_empty() {
        println!(
            "no active nftables input-filter chain found; the default policy already \
             permits this traffic, so there's nothing to add."
        );
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for (family, table, chain) in &chains {
        for &port in ports {
            match action {
                Action::Add => {
                    if find_rule_handle(&json, family, table, chain, port).is_some() {
                        continue; // already present in this chain
                    }
                    out.push(PlannedCommand::new(
                        format!("{port}/udp via nftables ({family} {table} {chain})"),
                        "nft",
                        vec![
                            "insert".to_string(),
                            "rule".to_string(),
                            family.clone(),
                            table.clone(),
                            chain.clone(),
                            "position".to_string(),
                            "0".to_string(),
                            "udp".to_string(),
                            "dport".to_string(),
                            port.to_string(),
                            "accept".to_string(),
                        ],
                    ));
                }
                Action::Remove => {
                    if let Some(handle) = find_rule_handle(&json, family, table, chain, port) {
                        out.push(PlannedCommand::new(
                            format!("{port}/udp via nftables ({family} {table} {chain})"),
                            "nft",
                            vec![
                                "delete".to_string(),
                                "rule".to_string(),
                                family.clone(),
                                table.clone(),
                                chain.clone(),
                                "handle".to_string(),
                                handle.to_string(),
                            ],
                        ));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Parse `nft -j list ruleset` JSON output for every base chain hooked
/// at `input` with `type filter` -- i.e. every chain that could plausibly
/// be dropping inbound traffic. Returns `(family, table, chain)` tuples.
fn find_input_filter_chains(ruleset: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let Some(items) = ruleset.get("nftables").and_then(Value::as_array) else {
        return out;
    };
    for item in items {
        let Some(chain) = item.get("chain") else {
            continue;
        };
        let is_input_filter = chain.get("hook").and_then(Value::as_str) == Some("input")
            && chain.get("type").and_then(Value::as_str) == Some("filter");
        if !is_input_filter {
            continue;
        }
        let (Some(family), Some(table), Some(name)) = (
            chain.get("family").and_then(Value::as_str),
            chain.get("table").and_then(Value::as_str),
            chain.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        out.push((family.to_string(), table.to_string(), name.to_string()));
    }
    out
}

/// Find an existing `udp dport <port> accept` rule's handle in the given
/// `(family, table, chain)`, if one is already present.
fn find_rule_handle(
    ruleset: &Value,
    family: &str,
    table: &str,
    chain: &str,
    port: u16,
) -> Option<u32> {
    let items = ruleset.get("nftables")?.as_array()?;
    for item in items {
        // Not every array entry is a rule (metainfo/table/chain entries
        // interleave with rule entries in `nft -j list ruleset` output)
        // -- skip those rather than using `?`, which would abort this
        // whole function on the first non-rule entry instead of just
        // moving on to check the next one.
        let Some(rule) = item.get("rule") else {
            continue;
        };
        if rule.get("family").and_then(Value::as_str) != Some(family)
            || rule.get("table").and_then(Value::as_str) != Some(table)
            || rule.get("chain").and_then(Value::as_str) != Some(chain)
        {
            continue;
        }
        let Some(expr) = rule.get("expr").and_then(Value::as_array) else {
            continue;
        };
        let has_udp_dport_match = expr.iter().any(|e| is_udp_dport_match(e, port));
        let has_accept = expr.iter().any(|e| e.get("accept").is_some());
        if has_udp_dport_match && has_accept {
            if let Some(handle) = rule.get("handle").and_then(Value::as_u64) {
                return Some(handle as u32);
            }
        }
    }
    None
}

/// True if `expr` is nftables JSON for `match { udp dport == <port> }`,
/// e.g.:
/// `{"match": {"left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 51000}}`
fn is_udp_dport_match(expr: &Value, port: u16) -> bool {
    let Some(m) = expr.get("match") else {
        return false;
    };
    let is_udp_dport_field = m
        .get("left")
        .and_then(|l| l.get("payload"))
        .map(|p| {
            p.get("protocol").and_then(Value::as_str) == Some("udp")
                && p.get("field").and_then(Value::as_str) == Some("dport")
        })
        .unwrap_or(false);
    let right_is_port = m.get("right").and_then(Value::as_u64) == Some(port as u64);
    is_udp_dport_field && right_is_port
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(vals: &[u16]) -> BTreeSet<u16> {
        vals.iter().copied().collect()
    }

    #[test]
    fn firewalld_add_plan_has_permanent_ports_and_one_reload() {
        let plan = plan_firewalld(&ports(&[51000, 51001]), Action::Add);
        assert_eq!(plan.len(), 3); // 2 ports + 1 reload
        assert_eq!(plan[0].program, "firewall-cmd");
        assert!(plan[0].args.contains(&"--permanent".to_string()));
        assert!(plan[0].args.contains(&"--add-port=51000/udp".to_string()));
        assert!(plan[1].args.contains(&"--add-port=51001/udp".to_string()));
        assert_eq!(plan[2].args, vec!["--reload".to_string()]);
    }

    #[test]
    fn firewalld_remove_plan_uses_remove_port() {
        let plan = plan_firewalld(&ports(&[51000]), Action::Remove);
        assert!(plan[0]
            .args
            .contains(&"--remove-port=51000/udp".to_string()));
    }

    #[test]
    fn ufw_add_plan_one_allow_per_port() {
        let plan = plan_ufw(&ports(&[51000, 51001]), Action::Add);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan[0].args,
            vec!["allow".to_string(), "51000/udp".to_string()]
        );
    }

    #[test]
    fn ufw_remove_plan_uses_delete_allow() {
        let plan = plan_ufw(&ports(&[51000]), Action::Remove);
        assert_eq!(
            plan[0].args,
            vec![
                "delete".to_string(),
                "allow".to_string(),
                "51000/udp".to_string()
            ]
        );
    }

    #[test]
    fn planned_command_display_quotes_only_when_needed() {
        let c = PlannedCommand::new("x", "nft", vec!["insert".to_string(), "51000".to_string()]);
        assert_eq!(c.display(), "nft insert 51000");
    }

    #[test]
    fn backend_parse_accepts_common_aliases() {
        assert_eq!(Backend::parse("nft"), Some(Backend::Nftables));
        assert_eq!(Backend::parse("Nftables"), Some(Backend::Nftables));
        assert_eq!(
            Backend::parse("iptables-legacy"),
            Some(Backend::IptablesLegacy)
        );
        assert_eq!(Backend::parse("bogus"), None);
    }

    fn sample_ruleset(handle: u64, port: u64) -> Value {
        serde_json::json!({
            "nftables": [
                {"metainfo": {"version": "1.0.9"}},
                {"table": {"family": "inet", "name": "filter", "handle": 1}},
                {
                    "chain": {
                        "family": "inet",
                        "table": "filter",
                        "name": "input",
                        "handle": 1,
                        "type": "filter",
                        "hook": "input",
                        "prio": 0,
                        "policy": "drop"
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "filter",
                        "chain": "input",
                        "handle": handle,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": "udp", "field": "dport"}},
                                    "right": port
                                }
                            },
                            {"accept": null}
                        ]
                    }
                }
            ]
        })
    }

    #[test]
    fn finds_input_filter_chain_from_sample_ruleset() {
        let json = sample_ruleset(5, 51000);
        let chains = find_input_filter_chains(&json);
        assert_eq!(
            chains,
            vec![(
                "inet".to_string(),
                "filter".to_string(),
                "input".to_string()
            )]
        );
    }

    #[test]
    fn finds_existing_rule_handle_by_matching_port() {
        let json = sample_ruleset(7, 51000);
        assert_eq!(
            find_rule_handle(&json, "inet", "filter", "input", 51000),
            Some(7)
        );
        // A different port must not match this rule.
        assert_eq!(
            find_rule_handle(&json, "inet", "filter", "input", 51001),
            None
        );
    }

    #[test]
    fn empty_ruleset_yields_no_chains() {
        let json = serde_json::json!({"nftables": [{"metainfo": {"version": "1.0.9"}}]});
        assert!(find_input_filter_chains(&json).is_empty());
    }
}

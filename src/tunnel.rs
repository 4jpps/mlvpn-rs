//! Ties together the TUN device, the bonded links, the scheduler and the
//! crypto session into the running data path.
//!
//! Task layout (all spawned on the shared tokio runtime):
//!
//! - one `tun_reader` task: reads plaintext IP packets from the TUN
//!   device, encrypts them, asks the `Scheduler` which link to use, and
//!   sends the resulting datagram out that link's socket.
//! - one task per link (`link_actor`): owns that link's UDP socket,
//!   demultiplexes incoming frames by `PacketType` (Data goes to the
//!   reorder buffer and then the TUN device; Probe/ProbeReply feed the
//!   latency monitor), and periodically emits its own Probe frames.
//! - one `reorder_flush` task: releases packets from the reorder buffer
//!   that have waited past `reorder_window_ms`, so a permanently missing
//!   packet degrades to out-of-order delivery instead of stalling the
//!   tunnel forever.
//!
//! Locking discipline: `links: Arc<AsyncMutex<Vec<Link>>>` guards
//! *metadata only* (stats, state, the learned remote address). Every task
//! that performs socket I/O first clones the link's `Arc<UdpSocket>` out
//! from under a short-lived lock and then awaits `send_to`/`recv_from` on
//! that owned clone, never across the mutex guard. Holding an async mutex
//! across a network read/write that can block indefinitely would
//! serialize every link behind whichever one is slowest to receive --
//! exactly the kind of head-of-line blocking a multi-link bonding daemon
//! exists to avoid.
//!
//! Known limitations of this first pass (see ARCHITECTURE.md "Roadmap"):
//! the initial handshake is only attempted over the first configured
//! link, with simple retry; opportunistic handshake races over every link
//! and live session migration/rekey scheduling are not yet implemented.

use crate::config::{Mode, SchedulerConfig};
use crate::crypto::{self, Handshake, LocalPrivateKey, Session};
use crate::error::{MlvpnError, Result};
use crate::link::Link;
use crate::monitor::{self, ProbeTracker};
use crate::protocol::{Header, PacketType, ProbePayload, HEADER_LEN};
use crate::scheduler::Scheduler;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::interval;
use tun_rs::AsyncDevice;

const MAX_FRAME: usize = 2048;

pub struct TunnelParams {
    pub mode: Mode,
    pub mtu: u16,
    pub scheduler_cfg: SchedulerConfig,
    pub local_private: LocalPrivateKey,
    pub peer_public: [u8; 32],
    #[allow(dead_code)] // wired up once rekey scheduling lands (roadmap)
    pub rekey_interval: Duration,
}

pub async fn run(tun: AsyncDevice, links: Vec<Link>, params: TunnelParams) -> Result<()> {
    let tun = Arc::new(tun);
    let links = Arc::new(AsyncMutex::new(links));
    let scheduler = Arc::new(std::sync::Mutex::new(Scheduler::new()));
    let session_id = crypto::random_session_id();

    let session = establish_session(&links, &params, session_id).await?;
    let session = Arc::new(AsyncMutex::new(session));

    tracing::info!(session_id, "tunnel session established");

    let reorder = Arc::new(AsyncMutex::new(ReorderBuffer::new(
        params.scheduler_cfg.reorder_window_ms,
    )));

    let n_links = links.lock().await.len();
    let mut handles = Vec::new();

    for idx in 0..n_links {
        let links = links.clone();
        let session = session.clone();
        let scheduler = scheduler.clone();
        let tun = tun.clone();
        let reorder = reorder.clone();
        let cfg = params.scheduler_cfg.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                link_actor(idx, links, session, scheduler, tun, reorder, cfg, session_id).await
            {
                tracing::error!(link_index = idx, error = %e, "link actor exited");
            }
        }));
    }

    {
        let links = links.clone();
        let session = session.clone();
        let scheduler = scheduler.clone();
        let tun = tun.clone();
        let mtu = params.mtu as usize;
        handles.push(tokio::spawn(async move {
            if let Err(e) = tun_reader(tun, links, session, scheduler, mtu, session_id).await {
                tracing::error!(error = %e, "tun reader exited");
            }
        }));
    }

    {
        let reorder = reorder.clone();
        let tun = tun.clone();
        handles.push(tokio::spawn(async move {
            reorder_flush(reorder, tun).await;
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

/// Perform (or wait for) the initial Noise handshake and return the
/// resulting transport session. Client dials out on the first configured
/// link with a bounded number of retries; server waits for an incoming
/// HandshakeInit on any link. This runs before any `link_actor` tasks
/// exist, so it is free to hold the `links` lock across its own recv
/// calls without contending with them.
async fn establish_session(
    links: &Arc<AsyncMutex<Vec<Link>>>,
    params: &TunnelParams,
    session_id: u32,
) -> Result<Session> {
    match params.mode {
        Mode::Client => {
            const RETRIES: u32 = 10;
            let mut last_err = None;
            for attempt in 0..RETRIES {
                let (socket, remote, link_id) = {
                    let links_guard = links.lock().await;
                    let link = links_guard
                        .first()
                        .ok_or_else(|| MlvpnError::Config("no links configured".into()))?;
                    let remote = link
                        .remote
                        .ok_or_else(|| MlvpnError::Config("link has no remote_addr".into()))?;
                    (link.socket.clone(), remote, link.id)
                };

                let mut hs = Handshake::new_initiator(&params.local_private, &params.peer_public)?;
                let msg1 = hs.write_first()?;
                let mut frame = Vec::with_capacity(HEADER_LEN + msg1.len());
                Header {
                    ptype: PacketType::HandshakeInit,
                    link_id,
                    session_id,
                    seq: 0,
                }
                .encode(&mut frame);
                frame.extend_from_slice(&msg1);
                socket.send_to(&frame, remote).await.map_err(MlvpnError::Io)?;

                let mut buf = vec![0u8; MAX_FRAME];
                match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, _from))) => {
                        buf.truncate(n);
                        if let Ok((hdr, payload)) = Header::decode(&buf) {
                            if hdr.ptype == PacketType::HandshakeResp {
                                hs.read_second(payload)?;
                                if let Some(remote_static) = hs.remote_static() {
                                    if remote_static != params.peer_public {
                                        return Err(MlvpnError::AuthFailed);
                                    }
                                }
                                return hs.into_session();
                            }
                        }
                        last_err = Some(MlvpnError::Handshake("unexpected reply frame".into()));
                    }
                    Ok(Err(e)) => last_err = Some(MlvpnError::Io(e)),
                    Err(_) => {
                        tracing::warn!(attempt, "handshake attempt timed out, retrying");
                        last_err = Some(MlvpnError::Handshake("timeout".into()));
                    }
                }
            }
            Err(last_err.unwrap_or(MlvpnError::Handshake("handshake failed".into())))
        }
        Mode::Server => {
            // Race a short-timeout recv across every link in turn. This is
            // a simple sequential poll rather than a true concurrent
            // select over a dynamic set of futures, which is adequate
            // pre-session (no data path running yet) but would be a poor
            // pattern for the hot path -- link_actor uses proper
            // per-socket ownership instead once the session exists.
            let sockets: Vec<(Arc<UdpSocket>, u8)> = {
                let links_guard = links.lock().await;
                links_guard.iter().map(|l| (l.socket.clone(), l.id)).collect()
            };
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                let mut hit = None;
                for (socket, link_id) in &sockets {
                    if let Ok(Ok((n, from))) =
                        tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await
                    {
                        hit = Some((n, from, *link_id, socket.clone()));
                        break;
                    }
                }
                let Some((n, from, link_id, socket)) = hit else {
                    continue;
                };
                buf.truncate(n);
                let Ok((hdr, payload)) = Header::decode(&buf) else {
                    buf.resize(MAX_FRAME, 0);
                    continue;
                };
                if hdr.ptype != PacketType::HandshakeInit {
                    buf.resize(MAX_FRAME, 0);
                    continue;
                }

                // A malformed or malicious handshake attempt from any
                // source must never take the whole server down: log and
                // keep listening rather than propagating the error out of
                // this loop with `?`. Only genuine local resource errors
                // (e.g. the send below failing) are allowed to bubble up.
                let mut hs = match Handshake::new_responder(&params.local_private) {
                    Ok(hs) => hs,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to start responder handshake state");
                        buf.resize(MAX_FRAME, 0);
                        continue;
                    }
                };
                let msg2 = match hs.read_first_and_reply(payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, %from, "rejected malformed/invalid handshake attempt");
                        buf.resize(MAX_FRAME, 0);
                        continue;
                    }
                };
                if let Some(remote_static) = hs.remote_static() {
                    if remote_static != params.peer_public {
                        tracing::warn!(%from, "rejected handshake from unpinned peer key");
                        buf.resize(MAX_FRAME, 0);
                        continue;
                    }
                }
                let mut frame = Vec::with_capacity(HEADER_LEN + msg2.len());
                Header {
                    ptype: PacketType::HandshakeResp,
                    link_id,
                    session_id: hdr.session_id,
                    seq: 0,
                }
                .encode(&mut frame);
                frame.extend_from_slice(&msg2);
                if let Err(e) = socket.send_to(&frame, from).await {
                    tracing::warn!(error = %e, "failed to send handshake response, will retry on next attempt");
                    buf.resize(MAX_FRAME, 0);
                    continue;
                }

                let mut links_guard = links.lock().await;
                if let Some(link) = links_guard.iter_mut().find(|l| l.id == link_id) {
                    link.remote = Some(from);
                }
                drop(links_guard);
                return hs.into_session();
            }
        }
    }
}

async fn tun_reader(
    tun: Arc<AsyncDevice>,
    links: Arc<AsyncMutex<Vec<Link>>>,
    session: Arc<AsyncMutex<Session>>,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    mtu: usize,
    session_id: u32,
) -> Result<()> {
    let mut buf = vec![0u8; mtu + 64];
    loop {
        let n = tun.recv(&mut buf).await.map_err(MlvpnError::Io)?;
        let plaintext = buf[..n].to_vec();

        let (seq, ciphertext) = {
            let s = session.lock().await;
            let seq = s.next_send_seq();
            let ct = s.encrypt(seq, &plaintext)?;
            (seq, ct)
        };

        // Brief, non-awaiting critical section: pick a link and copy out
        // just what we need (a socket handle clone + address) before
        // releasing the lock.
        let chosen: Option<(u8, Arc<UdpSocket>, SocketAddr, String)> = {
            let links_guard = links.lock().await;
            let mut sched = scheduler.lock().unwrap();
            sched.select(&links_guard).and_then(|l| {
                l.remote
                    .map(|r| (l.id, l.socket.clone(), r, l.config.name.clone()))
            })
        };
        let Some((link_id, socket, remote, link_name)) = chosen else {
            tracing::warn!("no link available to send on; dropping packet");
            continue;
        };

        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        Header {
            ptype: PacketType::Data,
            link_id,
            session_id,
            seq,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&ciphertext);

        if let Err(e) = socket.send_to(&frame, remote).await {
            tracing::debug!(link = %link_name, error = %e, "send failed");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn link_actor(
    idx: usize,
    links: Arc<AsyncMutex<Vec<Link>>>,
    session: Arc<AsyncMutex<Session>>,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    tun: Arc<AsyncDevice>,
    reorder: Arc<AsyncMutex<ReorderBuffer>>,
    cfg: SchedulerConfig,
    session_id: u32,
) -> Result<()> {
    let (socket, link_id, probe_interval_ms) = {
        let links_guard = links.lock().await;
        let link = &links_guard[idx];
        (link.socket.clone(), link.id, link.config.probe_interval_ms)
    };

    let mut tracker = ProbeTracker::new(Duration::from_millis(
        probe_interval_ms.saturating_mul(4).max(500),
    ));
    let probe_seq_counter = AtomicU32::new(0);
    let mut probe_tick = interval(Duration::from_millis(probe_interval_ms));
    let mut sweep_tick = interval(Duration::from_millis(probe_interval_ms));

    let mut buf = vec![0u8; MAX_FRAME];

    loop {
        tokio::select! {
            biased;

            recv_result = socket.recv_from(&mut buf) => {
                let (n, from) = recv_result.map_err(MlvpnError::Io)?;
                handle_incoming(
                    idx, link_id, &buf[..n], from, &socket, &links, &session, &scheduler, &tun,
                    &reorder, &cfg, &mut tracker,
                ).await;
            }

            _ = probe_tick.tick() => {
                send_probe(&socket, link_id, &links, idx, &session, &probe_seq_counter, &mut tracker).await;
            }

            _ = sweep_tick.tick() => {
                let misses = tracker.sweep_timeouts();
                if misses > 0 {
                    let mut links_guard = links.lock().await;
                    for _ in 0..misses {
                        links_guard[idx].stats.record_miss();
                    }
                    monitor::update_link_state(&mut links_guard[idx], &cfg);
                    let mut sched = scheduler.lock().unwrap();
                    sched.refresh(&links_guard);
                }
            }
        }
        let _ = session_id; // reserved for future per-frame session validation (roadmap: rekey)
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    idx: usize,
    link_id: u8,
    frame: &[u8],
    from: SocketAddr,
    socket: &Arc<UdpSocket>,
    links: &Arc<AsyncMutex<Vec<Link>>>,
    session: &Arc<AsyncMutex<Session>>,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    tun: &Arc<AsyncDevice>,
    reorder: &Arc<AsyncMutex<ReorderBuffer>>,
    cfg: &SchedulerConfig,
    tracker: &mut ProbeTracker,
) {
    let Ok((hdr, ciphertext)) = Header::decode(frame) else {
        return;
    };

    // Every non-handshake frame type -- Data, Probe, and ProbeReply alike
    // -- is AEAD-protected under the shared Noise transport session, using
    // the header's `seq` as the nonce. This matters as much for Probe
    // traffic as for Data: if probes were sent in the clear, an off-path
    // attacker could inject forged RTT/loss samples and steer the
    // scheduler's link scoring, or trigger bogus Up/Down transitions.
    // Requiring authentication here means only someone holding the
    // session's derived keys (i.e. someone who passed the Noise_IK
    // handshake) can influence link scoring or get a Data payload
    // accepted at all.
    let plaintext = match hdr.ptype {
        PacketType::HandshakeInit | PacketType::HandshakeResp => {
            // Only relevant during establish_session(); once the tunnel is
            // running, a stray handshake frame is either a stale
            // retransmit or a rekey request from a future version. Rekey
            // support is a roadmap item, so we ignore it here rather than
            // risk misinterpreting it.
            return;
        }
        _ => {
            let mut s = session.lock().await;
            match s.decrypt(hdr.seq, ciphertext) {
                Ok(pt) => pt,
                Err(_) => return, // auth failure or replay; silently drop
            }
        }
    };

    // Only now, having verified the frame is authentic, do we trust its
    // source address enough to (re-)learn it as this link's peer address.
    // This is what lets a server-side link start life with no configured
    // `remote_addr` and still become usable the moment the client's first
    // authenticated frame arrives on it, and lets either side recover
    // automatically if a link's source address changes mid-session (e.g.
    // mobile roaming, NAT rebinding) -- without letting an unauthenticated
    // spoofed packet redirect where we send subsequent traffic.
    {
        let mut links_guard = links.lock().await;
        if let Some(link) = links_guard.get_mut(idx) {
            if link.remote != Some(from) {
                tracing::debug!(link = %link.config.name, %from, "learned/updated peer address");
                link.remote = Some(from);
            }
        }
    }

    match hdr.ptype {
        PacketType::Data => {
            {
                let mut links_guard = links.lock().await;
                if let Some(link) = links_guard.get_mut(idx) {
                    link.stats.record_bytes(frame.len() as u64);
                }
            }

            let ready = {
                let mut ro = reorder.lock().await;
                ro.insert(hdr.seq, plaintext);
                ro.drain_ready()
            };
            for pkt in ready {
                let _ = tun.send(&pkt).await;
            }
        }
        PacketType::Probe => {
            // Echo the decrypted probe payload straight back, re-encrypted
            // under our own next sequence number, so the original sender
            // can match it against their outstanding-probe table by
            // `probe_seq` and compute RTT from their own clock.
            let reply_seq = {
                let s = session.lock().await;
                s.next_send_seq()
            };
            let reply_ct = {
                let s = session.lock().await;
                match s.encrypt(reply_seq, &plaintext) {
                    Ok(ct) => ct,
                    Err(_) => return,
                }
            };
            let mut out = Vec::with_capacity(HEADER_LEN + reply_ct.len());
            Header {
                ptype: PacketType::ProbeReply,
                link_id,
                session_id: hdr.session_id,
                seq: reply_seq,
            }
            .encode(&mut out);
            out.extend_from_slice(&reply_ct);
            let _ = socket.send_to(&out, from).await;
        }
        PacketType::ProbeReply => {
            let Ok(probe) = ProbePayload::decode(&plaintext) else {
                return;
            };
            if let Some(rtt_ms) = tracker.record_reply(probe.probe_seq) {
                let mut links_guard = links.lock().await;
                if let Some(link) = links_guard.get_mut(idx) {
                    link.stats.record_rtt(rtt_ms);
                    monitor::update_link_state(link, cfg);
                }
                let mut sched = scheduler.lock().unwrap();
                sched.refresh(&links_guard);
            }
        }
        PacketType::Keepalive | PacketType::Disconnect => {
            // Keepalives need no action beyond having been received (the
            // socket read itself is enough to keep NAT bindings alive);
            // Disconnect handling (graceful session teardown/rekey) is a
            // roadmap item -- see ARCHITECTURE.md.
        }
        PacketType::HandshakeInit | PacketType::HandshakeResp => unreachable!("handled above"),
    }
}

async fn send_probe(
    socket: &Arc<UdpSocket>,
    link_id: u8,
    links: &Arc<AsyncMutex<Vec<Link>>>,
    idx: usize,
    session: &Arc<AsyncMutex<Session>>,
    probe_seq_counter: &AtomicU32,
    tracker: &mut ProbeTracker,
) {
    let remote = {
        let links_guard = links.lock().await;
        links_guard[idx].remote
    };
    let Some(remote) = remote else {
        return;
    };

    let probe_seq = probe_seq_counter.fetch_add(1, Ordering::Relaxed);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let payload = ProbePayload {
        probe_seq,
        send_ts_ns: now_ns,
    }
    .encode();

    let (seq, ciphertext) = {
        let s = session.lock().await;
        let seq = s.next_send_seq();
        match s.encrypt(seq, &payload) {
            Ok(ct) => (seq, ct),
            Err(_) => return,
        }
    };

    let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    Header {
        ptype: PacketType::Probe,
        link_id,
        session_id: 0,
        seq,
    }
    .encode(&mut frame);
    frame.extend_from_slice(&ciphertext);

    if socket.send_to(&frame, remote).await.is_ok() {
        tracker.record_sent(probe_seq);
    }
}

/// Holds decrypted, still-possibly-out-of-order Data payloads keyed by the
/// global session sequence number, and releases them to the TUN device
/// once either the gap in front of them is filled or they've waited
/// longer than `window`. This bounds the extra latency multipath
/// reordering can introduce: we would rather deliver a packet slightly
/// out of order than hold up the whole tunnel waiting for one that may
/// never arrive.
struct ReorderBuffer {
    window: Duration,
    next_expected: u64,
    pending: BTreeMap<u64, (Instant, Vec<u8>)>,
}

impl ReorderBuffer {
    fn new(window_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(window_ms),
            next_expected: 0,
            pending: BTreeMap::new(),
        }
    }

    fn insert(&mut self, seq: u64, payload: Vec<u8>) {
        self.pending.insert(seq, (Instant::now(), payload));
    }

    /// Drain everything that is now safe to deliver: a contiguous run
    /// starting at `next_expected`, plus anything that has aged out of
    /// the reorder window regardless of contiguity.
    fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = Instant::now();

        while let Some((&seq, (sent_at, _))) = self.pending.iter().next() {
            let is_next = seq == self.next_expected;
            let is_stale = now.duration_since(*sent_at) >= self.window;
            if is_next || is_stale {
                let (_sent_at, payload) = self.pending.remove(&seq).unwrap();
                out.push(payload);
                self.next_expected = seq.max(self.next_expected) + 1;
            } else {
                break;
            }
        }
        out
    }
}

async fn reorder_flush(reorder: Arc<AsyncMutex<ReorderBuffer>>, tun: Arc<AsyncDevice>) {
    let mut tick = interval(Duration::from_millis(10));
    loop {
        tick.tick().await;
        let ready = {
            let mut ro = reorder.lock().await;
            ro.drain_ready()
        };
        for pkt in ready {
            let _ = tun.send(&pkt).await;
        }
    }
}

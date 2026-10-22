//! Allocation + CPU microbenchmark for the per-packet WireGuard hot path.
//!
//! Run: `cargo bench --bench wg_path`
//!
//! Mirrors what `tunnel.rs`'s `send_scheduled` / `link_receiver` /
//! `handle_incoming` do around `WgTunnel::{encapsulate,decapsulate}`, minus
//! sockets and locks, and reports wall time plus heap allocations and bytes
//! allocated per packet via a counting global allocator. This is the
//! before/after yardstick for the allocation-cleanup work (Phase 1 of the
//! improvement plan); it does not measure scheduler/lock/queue behaviour,
//! which needs the veth throughput tests instead.

use mlvpn::protocol::{Header, PacketType};
use mlvpn::wireguard::{DecapsulateKind, DecapsulateOutcome, WgTunnel};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
            System.alloc(l)
        }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        unsafe {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
            System.alloc_zeroed(l)
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        unsafe {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(n as u64, Ordering::Relaxed);
            System.realloc(p, l, n)
        }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn pair() -> (WgTunnel, WgTunnel) {
    let c = mlvpn::crypto::StaticKeypair::generate()
        .unwrap()
        .raw_bytes();
    let s = mlvpn::crypto::StaticKeypair::generate()
        .unwrap()
        .raw_bytes();
    let client = WgTunnel::new(c.0, s.1, true).unwrap();
    let server = WgTunnel::new(s.0, c.1, false).unwrap();
    let (init, _) = client.encapsulate(b"x").unwrap();
    let DecapsulateOutcome::SendReply(resp) = server.decapsulate(&init).unwrap() else {
        panic!("expected handshake response")
    };
    let DecapsulateOutcome::SendReply(ka) = client.decapsulate(&resp).unwrap() else {
        panic!("expected keepalive")
    };
    assert!(matches!(
        server.decapsulate(&ka).unwrap(),
        DecapsulateOutcome::Consumed
    ));
    (client, server)
}

fn measure(name: &str, iters: u64, mut f: impl FnMut(u64)) {
    for i in 0..1000 {
        f(i);
    }
    // The timed loop continues the index (not restarts it): the rx case
    // consumes single-use WireGuard counters, so indices must never repeat.
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let b0 = BYTES.load(Ordering::Relaxed);
    let t0 = Instant::now();
    for i in 1000..1000 + iters {
        f(i);
    }
    let dt = t0.elapsed();
    let a = ALLOCS.load(Ordering::Relaxed) - a0;
    let b = BYTES.load(Ordering::Relaxed) - b0;
    println!(
        "{name:<34} {:>8.0} ns/pkt  {:>5.2} allocs/pkt  {:>8.0} B/pkt",
        dt.as_nanos() as f64 / iters as f64,
        a as f64 / iters as f64,
        b as f64 / iters as f64,
    );
}

fn main() {
    let iters = 200_000;
    for payload_len in [100usize, 1400] {
        println!("--- payload {payload_len} B (inner IP packet) ---");
        let payload = vec![0xA5u8; payload_len];

        // TX as send_scheduled does it: tun_reader's to_vec, frame build, encapsulate.
        let (client, server) = pair();
        measure("tx: to_vec+encapsulate_parts", iters, |seq| {
            let plaintext = payload.to_vec();
            let header = Header {
                ptype: PacketType::Data,
                link_id: 0,
                seq,
            }
            .to_bytes();
            let (dg, carried) = client.encapsulate_parts(&[&header, &plaintext]).unwrap();
            black_box((dg, carried));
        });

        // RX as link_receiver/handle_incoming do it: wg_recv's scratch buffer,
        // decapsulate, Header::decode, owned plaintext copy.
        let (client, server2) = pair();
        let _ = server;
        let mut frame = Vec::new();
        Header {
            ptype: PacketType::Data,
            link_id: 0,
            seq: 1,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&payload);
        // Pre-encrypt a batch of datagrams (each WG counter is single-use).
        let n = (iters + 1000) as usize;
        let datagrams: Vec<Vec<u8>> = (0..n)
            .map(|_| client.encapsulate(&frame).unwrap().0)
            .collect();
        let mut buf = vec![0u8; u16::MAX as usize + 64];
        let mut out = Vec::with_capacity(2048);
        measure("rx: decapsulate_into+decode", iters, |i| {
            let dg = &datagrams[i as usize];
            buf[..dg.len()].copy_from_slice(dg); // stands in for recv_from
            let kind = server2
                .decapsulate_into(&buf[..dg.len()], &mut out)
                .unwrap();
            assert!(matches!(kind, DecapsulateKind::Frame));
            let (hdr, pt) = Header::decode(&out).unwrap();
            black_box((hdr.seq, pt.len()));
        });
    }
}

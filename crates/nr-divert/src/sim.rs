//! Simulator transport: a deterministic, reproducible traffic source.
//!
//! Purpose is threefold:
//!
//! 1. **End-to-end tests on Linux.** The production path (WinDivert) only
//!    exists on Windows, so without this there would be no way to run the whole
//!    pipeline in CI.
//! 2. **`nr simulate`** — measure throughput and drops without touching the
//!    network stack, which is how the benchmark numbers in
//!    `docs/BENCHMARKS.md` were produced.
//! 3. **Reproducibility.** A fixed seed produces the same packet sequence, so a
//!    bug found in simulation can be replayed exactly.

use crate::Transport;
use nr_core::frame::{tcp_v4, tcp_v6, udp_v4};
use nr_core::{Direction, ProcKey};

/// A synthetic traffic profile.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Flows to simulate concurrently.
    pub flows: usize,
    /// Frames per flow.
    pub frames_per_flow: usize,
    /// Payload bytes per outbound frame.
    pub payload: usize,
    /// Fraction of frames that are inbound (0..=100, percent).
    pub inbound_percent: u32,
    /// PRNG seed.
    pub seed: u64,
    /// Emit TCP SYN first on each flow (handshake), so a `block` rule that
    /// targets SYNs is exercised.
    pub handshake: bool,
    /// Use IPv6 for every third flow.
    pub mix_v6: bool,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            flows: 8,
            frames_per_flow: 1_000,
            payload: 1_400,
            inbound_percent: 40,
            seed: 0x5EED_1234_ABCD_0001,
            handshake: true,
            mix_v6: true,
        }
    }
}

/// A frame produced by the simulator.
#[derive(Debug, Clone)]
pub struct SimFrame {
    /// The bytes.
    pub data: Vec<u8>,
    /// Direction of travel.
    pub direction: Direction,
}

/// One simulated process.
#[derive(Debug, Clone)]
pub struct SimProcess {
    /// PID reported to the engine.
    pub pid: u32,
    /// Start time reported to the engine.
    pub start_time: u64,
    /// Image name reported to the identity resolver.
    pub name: &'static str,
    /// Outbound destination port.
    pub dport: u16,
}

/// The processes the simulator pretends are running.
#[must_use]
pub fn default_processes() -> Vec<SimProcess> {
    vec![
        SimProcess {
            pid: 1001,
            start_time: 11,
            name: "chrome.exe",
            dport: 443,
        },
        SimProcess {
            pid: 1002,
            start_time: 12,
            name: "steam.exe",
            dport: 27015,
        },
        SimProcess {
            pid: 1003,
            start_time: 13,
            name: "backup.exe",
            dport: 8080,
        },
        SimProcess {
            pid: 1004,
            start_time: 14,
            name: "game.exe",
            dport: 443,
        },
        SimProcess {
            pid: 1005,
            start_time: 15,
            name: "updater.exe",
            dport: 80,
        },
    ]
}

/// Deterministic PRNG (xorshift64*), so runs are reproducible without a
/// dependency.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seed the generator. Zero is remapped (xorshift cannot leave zero).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// Next value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Next value in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// Generate the full frame sequence for `config`.
///
/// The sequence is deliberately hostile to a shaping engine: it offers far more
/// traffic than any test limit allows, in bursts, from several flows at once.
#[must_use]
pub fn generate(config: &SimConfig) -> Vec<(SimFrame, SimProcess)> {
    let procs = default_processes();
    let mut rng = Rng::new(config.seed);
    let mut out = Vec::with_capacity(config.flows * config.frames_per_flow);

    for f in 0..config.flows {
        let proc = procs[f % procs.len()].clone();
        let sport = 49152u16.wrapping_add((f as u16).wrapping_mul(7));
        let v6 = config.mix_v6 && f % 3 == 2;
        let payload = vec![0xABu8; config.payload];

        if config.handshake {
            let syn = if v6 {
                tcp_v6(v6_addr(f as u8), sport, v6_addr(0xEE), proc.dport, &[])
            } else {
                tcp_v4(
                    [10, 0, 0, (f % 250) as u8 + 1],
                    sport,
                    [93, 184, 216, 34],
                    proc.dport,
                    &[],
                )
            };
            out.push((
                SimFrame {
                    data: syn,
                    direction: Direction::Outbound,
                },
                proc.clone(),
            ));
        }

        for _ in 0..config.frames_per_flow {
            let inbound = rng.below(100) < u64::from(config.inbound_percent);
            let len = 1 + (rng.below(config.payload as u64) as usize);
            let data = if v6 {
                if inbound {
                    tcp_v6(
                        v6_addr(0xEE),
                        proc.dport,
                        v6_addr(f as u8),
                        sport,
                        &payload[..len],
                    )
                } else {
                    tcp_v6(
                        v6_addr(f as u8),
                        sport,
                        v6_addr(0xEE),
                        proc.dport,
                        &payload[..len],
                    )
                }
            } else if inbound {
                tcp_v4(
                    [93, 184, 216, 34],
                    proc.dport,
                    [10, 0, 0, (f % 250) as u8 + 1],
                    sport,
                    &payload[..len],
                )
            } else {
                tcp_v4(
                    [10, 0, 0, (f % 250) as u8 + 1],
                    sport,
                    [93, 184, 216, 34],
                    proc.dport,
                    &payload[..len],
                )
            };
            out.push((
                SimFrame {
                    data,
                    direction: if inbound {
                        Direction::Inbound
                    } else {
                        Direction::Outbound
                    },
                },
                proc.clone(),
            ));
        }

        // A UDP flow every fifth process, so `udp dport` rules get exercised.
        if f % 5 == 4 {
            let dns = udp_v4([10, 0, 0, 1], sport, [8, 8, 8, 8], 53, &[0u8; 40]);
            out.push((
                SimFrame {
                    data: dns,
                    direction: Direction::Outbound,
                },
                proc.clone(),
            ));
        }
    }
    out
}

fn v6_addr(tag: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[15] = tag;
    a
}

/// A [`Transport`] backed by a pre-generated frame list.
///
/// This is what makes the benchmark honest: the engine sees exactly the same
/// frames it would see from the driver, with the same directions and the same
/// token round-trip, minus the syscalls.
#[derive(Debug)]
pub struct SimTransport {
    frames: Vec<SimFrame>,
    procs: Vec<SimProcess>,
    cursor: usize,
    /// Frames accepted by `send`.
    pub sent: Vec<usize>,
    /// Frames refused by `send` (after release).
    pub refused: Vec<usize>,
    /// Token -> index of the frame it refers to.
    tokens: Vec<(usize, Direction)>,
}

impl SimTransport {
    /// Build from an explicit sequence.
    #[must_use]
    pub fn new(frames: Vec<(SimFrame, SimProcess)>) -> Self {
        let (frames, procs): (Vec<_>, Vec<_>) = frames.into_iter().unzip();
        Self {
            frames,
            procs,
            cursor: 0,
            sent: Vec::new(),
            refused: Vec::new(),
            tokens: Vec::new(),
        }
    }

    /// Build from a [`SimConfig`].
    #[must_use]
    pub fn from_config(config: &SimConfig) -> Self {
        Self::new(generate(config))
    }

    /// All frames, in order.
    #[must_use]
    pub fn frames(&self) -> &[SimFrame] {
        &self.frames
    }

    /// The process that owns frame `idx`.
    #[must_use]
    pub fn process(&self, idx: usize) -> Option<&SimProcess> {
        self.procs.get(idx)
    }

    /// Identity key for frame `idx`.
    #[must_use]
    pub fn proc_key(&self, idx: usize) -> Option<ProcKey> {
        self.procs
            .get(idx)
            .map(|p| ProcKey::new(p.pid, p.start_time))
    }

    /// Rewind to the beginning.
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.sent.clear();
        self.refused.clear();
        self.tokens.clear();
    }

    /// Was the sequence exhausted?
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.cursor >= self.frames.len()
    }

    /// Peek the next frame without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<&SimFrame> {
        self.frames.get(self.cursor)
    }

    /// Consume the next frame, returning its token (the frame index).
    pub fn next_token(&mut self) -> Option<u64> {
        if self.cursor >= self.frames.len() {
            return None;
        }
        let idx = self.cursor;
        self.cursor += 1;
        let dir = self.frames[idx].direction;
        self.tokens.push((idx, dir));
        Some(idx as u64)
    }
}

impl Transport for SimTransport {
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, Direction, u64)>, crate::DivertError> {
        if self.cursor >= self.frames.len() {
            return Ok(None);
        }
        let idx = self.cursor;
        self.cursor += 1;
        let frame = &self.frames[idx];
        let len = frame.data.len().min(buf.len());
        buf[..len].copy_from_slice(&frame.data[..len]);
        self.tokens.push((idx, frame.direction));
        Ok(Some((len, frame.direction, idx as u64)))
    }

    fn send(&mut self, frame: &[u8], token: u64) -> Result<(), crate::DivertError> {
        let idx = token as usize;
        if idx >= self.frames.len() {
            self.refused.push(idx);
            return Err(crate::DivertError::Other(format!(
                "token {token} out of range"
            )));
        }
        if frame.len() != self.frames[idx].data.len() {
            self.refused.push(idx);
            return Err(crate::DivertError::Other(format!(
                "token {token} sent with wrong length {} != {}",
                frame.len(),
                self.frames[idx].data.len()
            )));
        }
        self.sent.push(idx);
        Ok(())
    }

    fn release(&mut self, _token: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let cfg = SimConfig {
            flows: 3,
            frames_per_flow: 20,
            ..SimConfig::default()
        };
        let a = generate(&cfg);
        let b = generate(&cfg);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.0.data, y.0.data);
        }
    }

    #[test]
    fn transport_round_trips_tokens() {
        let cfg = SimConfig {
            flows: 2,
            frames_per_flow: 5,
            ..SimConfig::default()
        };
        let mut t = SimTransport::from_config(&cfg);
        let mut buf = vec![0u8; 65535];
        let mut n = 0;
        while let Some((len, _dir, token)) = t.recv(&mut buf).unwrap() {
            t.send(&buf[..len], token).unwrap();
            n += 1;
        }
        assert!(n > 0);
        assert_eq!(t.sent.len(), n);
        assert!(t.refused.is_empty());
    }

    #[test]
    fn wrong_length_is_refused() {
        let cfg = SimConfig {
            flows: 1,
            frames_per_flow: 2,
            ..SimConfig::default()
        };
        let mut t = SimTransport::from_config(&cfg);
        let mut buf = vec![0u8; 65535];
        let (len, _d, token) = t.recv(&mut buf).unwrap().unwrap();
        assert!(t.send(&buf[..len - 1], token).is_err());
        assert_eq!(t.refused.len(), 1);
    }

    #[test]
    fn rng_is_stable() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}

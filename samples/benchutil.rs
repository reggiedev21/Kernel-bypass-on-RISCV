// Rapport commun aux deux échos (userecho.rs et bypassecho.rs) : ils
// impriment les mêmes lignes « ECHO … », pour se comparer ligne à ligne.
// Sans allocation et sans flottants.

#![allow(dead_code)]

use core::fmt::Write;

use crate::usys::{self, TrapStats};

/// Une ligne de sortie, écrite d'un seul `write()`.
struct Line {
    buf: [u8; 240],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Imprime une ligne formatée (utilisée par la macro `say!`).
pub fn emit(args: core::fmt::Arguments) {
    let mut l = Line { buf: [0; 240], len: 0 };
    let _ = l.write_fmt(args);
    let _ = l.write_str("\n");
    usys::write(1, &l.buf[..l.len]);
}

macro_rules! say {
    ($($arg:tt)*) => { emit(format_args!($($arg)*)) };
}

pub fn clamp32(v: u64) -> u32 {
    if v > u32::MAX as u64 { u32::MAX } else { v as u32 }
}

/// Étalonnage : une boucle de longueur connue (2 instructions par tour),
/// pour savoir ce que `rdcycle` et `rdinstret` comptent sous l'émulateur.
pub fn calibrate() {
    const ITERS: u64 = 100_000;
    let (c0, i0, t0) = (usys::rdcycle(), usys::rdinstret(), usys::rdtime());
    unsafe {
        core::arch::asm!(
            "2:",
            "addi {n}, {n}, -1",
            "bnez {n}, 2b",
            n = inout(reg) ITERS => _,
            options(nomem, nostack),
        );
    }
    let (c1, i1, t1) = (usys::rdcycle(), usys::rdinstret(), usys::rdtime());
    say!(
        "ECHO calib instr_attendues={} d_cycle={} d_instret={} d_time={}",
        2 * ITERS,
        c1 - c0,
        i1 - i0,
        t1 - t0
    );
}

/// min / p50 / p99 / max d'un échantillon (trié en place), en instructions.
pub fn report(name: &str, v: &mut [u32]) {
    if v.is_empty() {
        return;
    }
    v.sort_unstable();
    let n = v.len();
    let sum: u64 = v.iter().map(|&x| x as u64).sum();
    // Aberrants : au-delà de 10 fois la médiane. Leur nombre distingue un
    // événement rare d'une queue de distribution.
    let p50 = v[n / 2];
    let outliers = v.iter().filter(|&&x| x as u64 > 10 * p50 as u64).count();
    say!(
        "ECHO {} n={} min={} p50={} p99={} max={} moy={} gigue_max_min={} aberrants_10xp50={}",
        name,
        n,
        v[0],
        p50,
        v[(n * 99) / 100],
        v[n - 1],
        sum / n as u64,
        v[n - 1] - v[0],
        outliers
    );
}

/// Différence de compteurs de traps entre `a` et `b`, par paquet, en
/// millièmes. `instr_ecalls` : appels de mesure faits dans la fenêtre,
/// retranchés des `ecall`.
pub fn traps_line(scope: &str, a: &TrapStats, b: &TrapStats, n: u64, instr_ecalls: u64) {
    let pp = |delta: u64| delta * 1000 / n;
    say!(
        "ECHO traps_{} par_paquet_x1000: ecall={} timer={} ext={} ipi={} faute={} ctx={} (ecall hors instrumentation, bruts={})",
        scope,
        pp((b.ecall - a.ecall).saturating_sub(instr_ecalls)),
        pp(b.timer - a.timer),
        pp(b.external - a.external),
        pp(b.software - a.software),
        pp(b.fault - a.fault),
        pp(b.ctx_switch - a.ctx_switch),
        b.ecall - a.ecall
    );
}

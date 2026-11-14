// Écho UDP en kernel bypass.
//
// Après `bypass_open` et l'init du device, la boucle ne fait plus aucun
// syscall : elle lit l'anneau `used`, parse la trame en place, écrit la
// réponse dans un tampon d'émission, rend le tampon de réception et notifie
// une fois par lot. Pas d'allocation : le programme n'a pas d'allocateur.
//
// Même protocole et mêmes lignes de rapport que userecho.rs : ping-pong sur
// le port 5555 de l'invité, "STOP" pour finir. Seul le port hôte change
// (5556 : la seconde carte).
//
// Par paquet, en instructions (`rdinstret` sous QEMU -icount) :
//   service = trame vue par poll_rx → notification d'émission écrite
//   tour    = trame vue → fin de l'itération
// Rien n'horodate l'instant où le device écrit une trame. On mesure donc une
// borne : le trou entre deux sondages consécutifs à vide. Une trame attend au
// plus ce trou : une itération de boucle au repos, ou toute la durée de
// l'interruption si le thread est interrompu ou préempté.
//
// Options de lancement :
//   prio=N   passe le thread en round-robin priorité N
//   pin=H    réserve le hart H au thread et l'y déplace
//   hog      lance un second thread qui calcule sans fin (thread concurrent)

#![no_std]
#![no_main]

#[path = "usys.rs"]
mod usys;
#[path = "benchutil.rs"]
mod benchutil;
#[path = "bypass/virtio.rs"]
mod virtio;
#[path = "bypass/wire.rs"]
mod wire;

use benchutil::{clamp32, report, traps_line};
use usys::TrapStats;
use virtio::{Stats, VirtioNet, QSIZE};
use wire::{build_reply, Endpoint, Reply};

const MY_IP: [u8; 4] = [10, 0, 2, 15];
const PORT: u16 = 5555;
/// Mêmes réglages que userecho.rs.
const WARMUP: usize = 32;
const MAX_SAMPLES: usize = 20_000;
/// Itérations à vide chronométrées avant d'annoncer « prêt ».
const IDLE_ITERS: u64 = 10_000;

static mut SERVICE: [u32; MAX_SAMPLES] = [0; MAX_SAMPLES];
static mut TOUR: [u32; MAX_SAMPLES] = [0; MAX_SAMPLES];

macro_rules! say {
    ($($arg:tt)*) => { benchutil::emit(format_args!($($arg)*)) };
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    usys::print("bypassecho: panic\n");
    usys::exit(0xDEAD);
}

/// Options de lancement (voir l'en-tête).
struct Options {
    prio: Option<u32>,
    pin: Option<usize>,
    hog: bool,
}

fn parse_options() -> Options {
    let mut o = Options { prio: None, pin: None, hog: false };
    usys::for_each_arg(|arg| {
        if let Some(v) = arg.strip_prefix("prio=") {
            o.prio = v.parse().ok();
        } else if let Some(v) = arg.strip_prefix("pin=") {
            o.pin = v.parse().ok();
        } else if arg == "hog" {
            o.hog = true;
        } else {
            say!("ECHO option inconnue: {}", arg);
        }
    });
    o
}

/// Thread concurrent : calcule sans céder ni appeler le noyau.
extern "C" fn hog(_: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Ce qu'une itération de la boucle a fait.
struct Turn {
    /// Datagrammes UDP renvoyés dans ce lot.
    echoed: usize,
    /// Un des datagrammes commençait par "STOP".
    stop: bool,
    /// `rdinstret` à la notification d'émission, puis en fin d'itération.
    t_kick: u64,
    t_end: u64,
}

/// Une itération du chemin chaud, sans syscall. `seen[i]` reçoit l'instant
/// où la i-ième trame UDP du lot a été vue.
#[inline(always)]
fn turn(net: &mut VirtioNet, me: &Endpoint, seen: &mut [u64; QSIZE]) -> Turn {
    let mut t = Turn { echoed: 0, stop: false, t_kick: 0, t_end: 0 };
    let mut tx_pending = false;
    let mut rx_recycled = false;

    // Vider l'anneau de réception avant de notifier.
    while t.echoed < QSIZE {
        let Some(rx) = net.poll_rx() else { break };
        let t_seen = usys::rdinstret();
        if let Some(mut tx) = net.alloc_tx() {
            match build_reply(rx.frame(), tx.buf(), me) {
                Some(reply) => {
                    if let Reply::Udp { payload, payload_len, .. } = reply {
                        seen[t.echoed] = t_seen;
                        t.echoed += 1;
                        if payload_len >= 4 && &tx.buf()[payload..payload + 4] == b"STOP" {
                            t.stop = true;
                        }
                    }
                    net.submit(tx, reply.len());
                    tx_pending = true;
                }
                None => net.release_tx(tx), // trame sans réponse
            }
        }
        // Rendu dans tous les cas : mieux vaut perdre une réponse que tarir
        // la réception.
        net.recycle(rx);
        rx_recycled = true;
    }

    if tx_pending {
        net.kick_tx(); // une notification pour tout le lot
        t.t_kick = usys::rdinstret();
    }
    if rx_recycled {
        net.kick_rx();
    }
    net.reclaim_tx();
    if t.echoed > 0 {
        t.t_end = usys::rdinstret();
    }
    t
}

#[no_mangle]
pub extern "C" fn run() -> ! {
    benchutil::calibrate();

    let info = match usys::bypass_open(usys::BYPASS_ANY, virtio::DMA_PAGES) {
        Ok(i) => i,
        Err(e) => {
            say!("ECHO erreur bypass_open={} (lancer avec --bypass)", e);
            usys::exit(1);
        }
    };
    let mut net = match VirtioNet::init(&info) {
        Ok(n) => n,
        Err(e) => {
            say!("ECHO erreur init={:?}", e);
            usys::exit(1);
        }
    };
    let me = Endpoint { mac: net.mac(), ip: MY_IP, port: PORT };

    // Options : appliquées avant la boucle, ce sont des syscalls.
    let opt = parse_options();
    if let Some(prio) = opt.prio {
        let r = usys::set_rr_priority(prio);
        if r != 0 {
            say!("ECHO erreur set_rr_priority({})={}", prio, r);
            usys::exit(1);
        }
    }
    if let Some(hart) = opt.pin {
        let r = usys::pin_to_hart(hart);
        if r != 0 {
            say!("ECHO erreur pin_to_hart({})={} (hart 0 interdit ; -smp >= 2 requis)", hart, r);
            usys::exit(1);
        }
    }
    if opt.hog {
        // Après bypass_open, qui exige un seul thread.
        let r = usys::thread_spawn(hog, 0);
        if r < 0 {
            say!("ECHO erreur thread_spawn={}", r);
            usys::exit(1);
        }
    }
    let my_hart = usys::trap_stats(usys::TRAPS_THREAD, 0).hart as usize;
    say!(
        "ECHO options prio={} pin={} hog={} hart={}",
        opt.prio.map(|p| p as i64).unwrap_or(-1),
        opt.pin.map(|h| h as i64).unwrap_or(-1),
        opt.hog as u8,
        my_hart
    );

    // SAFETY: programme mono-thread ; seules références à ces tableaux.
    let service = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE) };
    let tour = unsafe { &mut *core::ptr::addr_of_mut!(TOUR) };
    let mut seen_at = [0u64; QSIZE];

    // Coût d'une itération à vide, mesuré avant d'annoncer « prêt », donc
    // sans trafic.
    let i0 = usys::rdinstret();
    for _ in 0..IDLE_ITERS {
        let _ = turn(&mut net, &me, &mut seen_at);
        core::hint::spin_loop();
    }
    let idle = (usys::rdinstret() - i0) / IDLE_ITERS;

    say!("ECHO chemin=bypass");
    say!("ECHO pret port={}", PORT);

    let mut seen = 0usize; // datagrammes UDP reçus, échauffement compris
    let mut n = 0usize; // datagrammes mesurés
    let mut polls = 0u64;
    let mut window_open = false;
    let mut all0 = TrapStats::default();
    let mut thr0 = TrapStats::default();
    let mut hart0 = TrapStats::default();
    let mut net0 = Stats::default();
    let mut polls0 = 0u64;
    // Trous entre sondages à vide. `last_idle` : instant du dernier sondage
    // à vide, 0 si le tour précédent a traité une trame.
    let gap_big_threshold = 10 * idle.max(1);
    let mut last_idle = 0u64;
    let mut gaps = 0u64;
    let mut gap_max = 0u64;
    let mut gap_big = 0u64;
    let mut gap_big_sum = 0u64;

    // Le chemin chaud : plus aucun syscall jusqu'au "STOP".
    loop {
        if !window_open && seen >= WARMUP {
            // Ouverture de la fenêtre de mesure, une seule fois : du relevé
            // le plus large au plus étroit.
            window_open = true;
            all0 = usys::trap_stats(usys::TRAPS_ALL_HARTS, 0);
            hart0 = usys::trap_stats(usys::TRAPS_HART, my_hart);
            thr0 = usys::trap_stats(usys::TRAPS_THREAD, 0);
            net0 = net.stats;
            polls0 = polls;
            last_idle = 0; // ces relevés ne sont pas un trou
        }

        let t_top = usys::rdinstret();
        if window_open && last_idle != 0 {
            let gap = t_top - last_idle;
            gaps += 1;
            if gap > gap_max {
                gap_max = gap;
            }
            if gap > gap_big_threshold {
                gap_big += 1;
                gap_big_sum += gap;
            }
        }
        let t = turn(&mut net, &me, &mut seen_at);
        polls += 1;
        last_idle = if t.echoed == 0 { t_top } else { 0 };

        for &t_seen in &seen_at[..t.echoed] {
            if window_open && n < MAX_SAMPLES {
                service[n] = clamp32(t.t_kick - t_seen);
                tour[n] = clamp32(t.t_end - t_seen);
                n += 1;
            }
            seen += 1;
        }
        if t.stop {
            break;
        }
        core::hint::spin_loop();
    }

    // Fermeture de la fenêtre : ordre inverse.
    let thr1 = usys::trap_stats(usys::TRAPS_THREAD, 0);
    let hart1 = usys::trap_stats(usys::TRAPS_HART, my_hart);
    let all1 = usys::trap_stats(usys::TRAPS_ALL_HARTS, 0);
    let s = net.stats;

    say!("ECHO fin recus={} mesures={} echauffement={}", seen, n, WARMUP);
    if n > 0 {
        let np = n as u64;
        // Le dernier argument retranche les relevés de bord tombés dans
        // chaque fenêtre.
        traps_line("thread", &thr0, &thr1, np, 1);
        traps_line("hart", &hart0, &hart1, np, 3);
        traps_line("systeme", &all0, &all1, np, 5);
        // Tout ce que le hart du thread a subi dans la fenêtre, en valeur
        // absolue.
        say!(
            "ECHO hart{} traps_dans_la_fenetre: ecall={} timer={} ext={} ipi={} faute={} ctx={}",
            my_hart,
            (hart1.ecall - hart0.ecall).saturating_sub(3),
            hart1.timer - hart0.timer,
            hart1.external - hart0.external,
            hart1.software - hart0.software,
            hart1.fault - hart0.fault,
            hart1.ctx_switch - hart0.ctx_switch
        );
        report("service_vu_vers_notify", &mut service[..n]);
        report("tour_complet", &mut tour[..n]);
        say!("ECHO sondage_a_vide instructions_par_iteration={}", idle);
        say!(
            "ECHO trou_entre_sondages n={} max={} au_dela_de_10x_vide={} moy_de_ceux_la={} (borne de la prise en charge)",
            gaps,
            gap_max,
            gap_big,
            if gap_big > 0 { gap_big_sum / gap_big } else { 0 }
        );
        say!(
            "ECHO notify par_paquet_x1000: tx={} rx={} evites={} | sondages_par_paquet={}",
            (s.notify_tx - net0.notify_tx) * 1000 / np,
            (s.notify_rx - net0.notify_rx) * 1000 / np,
            (s.notify_skipped - net0.notify_skipped) * 1000 / np,
            (polls - polls0) / np
        );
        say!(
            "ECHO pilote rx={} rx_bad={} tx={} tx_recuperes={}",
            s.rx_frames, s.rx_bad, s.tx_frames, s.tx_reclaimed
        );
    }
    // exit_group : termine aussi le thread `hog` s'il existe.
    usys::exit_group(0);
}

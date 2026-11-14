// Écho UDP de référence, par le chemin noyau (sockets), instrumenté.
// C'est le chiffre contre lequel le bypass (bypassecho.rs) est comparé.
//
// Protocole (tools/udp_client.py) : ping-pong sur le port 5555, un seul
// datagramme en vol. Un datagramme commençant par "STOP" est renvoyé, puis
// le programme imprime son rapport et sort.
//
// Deux latences par paquet, en instructions (`rdinstret` sous QEMU -icount) :
//   pickup  = IRQ de la carte (horodatée par le noyau) → retour de recvfrom
//   service = durée de sendto
// La lecture de l'horodatage est un syscall de plus par paquet : il est placé
// entre les deux intervalles et retranché des compteurs de traps.

#![no_std]
#![no_main]

#[path = "usys.rs"]
mod usys;
#[path = "benchutil.rs"]
mod benchutil;

use benchutil::{clamp32, report, traps_line};
use usys::{SockAddrIn, TrapStats};

const PORT: u16 = 5555;
/// Paquets ignorés au début (ARP, caches, première faute FPU).
const WARMUP: usize = 32;
const MAX_SAMPLES: usize = 20_000;

static mut PICKUP: [u32; MAX_SAMPLES] = [0; MAX_SAMPLES];
static mut SERVICE: [u32; MAX_SAMPLES] = [0; MAX_SAMPLES];

macro_rules! say {
    ($($arg:tt)*) => { benchutil::emit(format_args!($($arg)*)) };
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    usys::print("userecho: panic\n");
    usys::exit(0xDEAD);
}

#[no_mangle]
pub extern "C" fn run() -> ! {
    benchutil::calibrate();

    let s = usys::socket_udp();
    if s < 0 {
        say!("ECHO erreur socket={}", s);
        usys::exit(1);
    }
    let s = s as usize;
    let r = usys::bind(s, &SockAddrIn::new([0, 0, 0, 0], PORT));
    if r != 0 {
        say!("ECHO erreur bind={}", r);
        usys::exit(1);
    }
    say!("ECHO chemin=noyau");
    say!("ECHO pret port={}", PORT);

    // SAFETY: programme mono-thread ; seules références à ces tableaux.
    let pickup = unsafe { &mut *core::ptr::addr_of_mut!(PICKUP) };
    let service = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE) };

    let mut buf = [0u8; 1472];
    let mut peer = SockAddrIn::new([0; 4], 0);
    let mut seen = 0usize; // datagrammes reçus, échauffement compris
    let mut n = 0usize; // datagrammes mesurés
    let mut all0 = TrapStats::default();
    let mut thr0 = TrapStats::default();

    loop {
        if seen == WARMUP {
            // Début de fenêtre : tous les harts, puis le thread.
            all0 = usys::trap_stats(usys::TRAPS_ALL_HARTS, 0);
            thr0 = usys::trap_stats(usys::TRAPS_THREAD, 0);
        }

        let mut peer_len = 16u32;
        let got = usys::recvfrom(s, &mut buf, 0, &mut peer, &mut peer_len);
        let t_ret = usys::rdinstret();
        if got < 0 {
            say!("ECHO erreur recvfrom={}", got);
            usys::exit(1);
        }
        let got = got as usize;

        // Mesure : 1 ecall par paquet, hors des deux intervalles.
        let irq = usys::trap_stats(usys::TRAPS_THREAD, 0).nic_irq_instret;

        let t1 = usys::rdinstret();
        let sent = usys::sendto(s, &buf[..got], &peer);
        let t2 = usys::rdinstret();
        if sent != got as isize {
            say!("ECHO erreur sendto={}", sent);
            usys::exit(1);
        }

        if seen >= WARMUP && n < MAX_SAMPLES {
            pickup[n] = clamp32(t_ret.saturating_sub(irq));
            service[n] = clamp32(t2 - t1);
            n += 1;
        }
        seen += 1;

        if got >= 4 && &buf[..4] == b"STOP" {
            break;
        }
    }

    // Fin de fenêtre : ordre inverse.
    let thr1 = usys::trap_stats(usys::TRAPS_THREAD, 0);
    let all1 = usys::trap_stats(usys::TRAPS_ALL_HARTS, 0);

    say!("ECHO fin recus={} mesures={} echauffement={}", seen, n, WARMUP);
    if n > 0 {
        let np = n as u64;
        // Appels de mesure à retrancher : n horodatages, plus les relevés de
        // début et de fin tombés dans chaque fenêtre.
        traps_line("thread", &thr0, &thr1, np, np + 1);
        traps_line("systeme", &all0, &all1, np, np + 2);
        report("pickup_irq_vers_recvfrom", &mut pickup[..n]);
        report("service_sendto", &mut service[..n]);
    }
    usys::exit(0);
}

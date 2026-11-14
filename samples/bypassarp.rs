// Preuve du pilote : une trame brute émise, une trame reçue.
//
// L'échange est un ARP : « qui a 10.0.2.2 ? ». La passerelle du réseau user
// de QEMU répond elle-même, donc aucun client n'est nécessaire sur l'hôte.
// Une réponse bien formée prouve l'émission, la réception, et que l'adresse
// physique rendue par bypass_open est bien celle que voit le device.
//
// Verdict par SYS_TEST : 0xB1A6 si conforme, 0xE00+n en cas d'échec à
// l'étape n.

#![no_std]
#![no_main]

#[path = "usys.rs"]
mod usys;
#[path = "bypass/virtio.rs"]
mod virtio;

use core::fmt::Write;
use virtio::VirtioNet;

const MY_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// 10 MHz : 2 s d'attente au plus pour la réponse.
const TIMEOUT_TICKS: u64 = 20_000_000;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    usys::print("BYPASS2 panic\n");
    usys::exit(0xDEAD);
}

struct Line {
    buf: [u8; 200],
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

macro_rules! say {
    ($($arg:tt)*) => {{
        let mut l = Line { buf: [0; 200], len: 0 };
        let _ = write!(l, $($arg)*);
        let _ = l.write_str("\n");
        usys::write(1, &l.buf[..l.len]);
    }};
}

fn fail(step: usize) -> ! {
    say!("BYPASS2 echec etape {}", step);
    usys::test(0xE00 + step);
    usys::exit(1);
}

/// Hexdump, 16 octets par ligne.
fn hexdump(tag: &str, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut l = Line { buf: [0; 200], len: 0 };
        let _ = write!(l, "BYPASS2 {} {:04x} ", tag, i * 16);
        for b in chunk {
            let _ = write!(l, " {:02x}", b);
        }
        let _ = l.write_str("\n");
        usys::write(1, &l.buf[..l.len]);
    }
}

/// Requête ARP « qui a `target` ? » dans `buf`. Rend la longueur (60 octets,
/// trame Ethernet minimale, bourrage à zéro).
fn build_arp_request(buf: &mut [u8], mac: &[u8; 6], me: &[u8; 4], target: &[u8; 4]) -> usize {
    let f = &mut buf[..60];
    f.fill(0);
    f[0..6].fill(0xff); // destination : diffusion
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType ARP
    f[14..16].copy_from_slice(&[0x00, 0x01]); // matériel : Ethernet
    f[16..18].copy_from_slice(&[0x08, 0x00]); // protocole : IPv4
    f[18] = 6; // longueur d'adresse matérielle
    f[19] = 4; // longueur d'adresse protocole
    f[20..22].copy_from_slice(&[0x00, 0x01]); // opération : requête
    f[22..28].copy_from_slice(mac); // émetteur : notre MAC
    f[28..32].copy_from_slice(me); // émetteur : notre IP
    // f[32..38] : MAC cible inconnue, à zéro
    f[38..42].copy_from_slice(target);
    60
}

/// Est-ce la réponse ARP attendue ? Rend la MAC de la passerelle.
fn parse_arp_reply(f: &[u8], mac: &[u8; 6]) -> Option<[u8; 6]> {
    if f.len() < 42 || f[12..14] != [0x08, 0x06] || f[20..22] != [0x00, 0x02] {
        return None;
    }
    if f[28..32] != GATEWAY_IP || f[32..38] != *mac || f[38..42] != MY_IP {
        return None;
    }
    let mut gw = [0u8; 6];
    gw.copy_from_slice(&f[22..28]);
    Some(gw)
}

#[no_mangle]
pub extern "C" fn run() -> ! {
    // 1. Le seul syscall de mise en place, puis l'init du device.
    let info = match usys::bypass_open(usys::BYPASS_ANY, virtio::DMA_PAGES) {
        Ok(i) => i,
        Err(e) => {
            say!("BYPASS2 bypass_open = {}", e);
            fail(1);
        }
    };
    let t0 = usys::trap_stats(usys::TRAPS_THREAD, 0);
    let mut net = match VirtioNet::init(&info) {
        Ok(n) => n,
        Err(e) => {
            say!("BYPASS2 init = {:?}", e);
            fail(2);
        }
    };
    let mac = net.mac();

    // 2. Émission : une requête ARP.
    let Some(mut tx) = net.alloc_tx() else { fail(3) };
    let len = build_arp_request(tx.buf(), &mac, &MY_IP, &GATEWAY_IP);
    let mut sent = [0u8; 60];
    sent.copy_from_slice(&tx.buf()[..len]);
    net.submit(tx, len);
    net.kick_tx();

    // 3. Réception : polling jusqu'à la réponse.
    let deadline = usys::rdtime() + TIMEOUT_TICKS;
    let mut polls = 0u64;
    let mut others = 0u32;
    let mut reply = [0u8; 64];
    let mut reply_len = 0usize;
    let gw_mac = loop {
        polls += 1;
        if let Some(rx) = net.poll_rx() {
            let found = parse_arp_reply(rx.frame(), &mac);
            if found.is_some() {
                reply_len = rx.frame().len().min(reply.len());
                reply[..reply_len].copy_from_slice(&rx.frame()[..reply_len]);
            } else {
                others += 1;
            }
            net.recycle(rx);
            net.kick_rx();
            if let Some(gw) = found {
                break gw;
            }
        } else if polls % 1024 == 0 && usys::rdtime() > deadline {
            say!("BYPASS2 aucune reponse ARP apres {} sondages", polls);
            fail(4);
        } else {
            core::hint::spin_loop();
        }
    };
    net.reclaim_tx();
    let t1 = usys::trap_stats(usys::TRAPS_THREAD, 0);

    // 4. Rapport, après la fenêtre : imprimer, c'est des syscalls.
    say!(
        "BYPASS2 mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} dma_phys={:#x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], info.dma_phys
    );
    hexdump("tx", &sent[..42]);
    hexdump("rx", &reply[..reply_len.min(42)]);
    say!(
        "BYPASS2 passerelle {}.{}.{}.{} est a {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        GATEWAY_IP[0], GATEWAY_IP[1], GATEWAY_IP[2], GATEWAY_IP[3],
        gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]
    );
    let s = net.stats;
    say!(
        "BYPASS2 sondages={} autres_trames={} rx={} rx_bad={} tx={} tx_recuperes={} notify_rx={} notify_tx={} notify_evites={}",
        polls, others, s.rx_frames, s.rx_bad, s.tx_frames, s.tx_reclaimed,
        s.notify_rx, s.notify_tx, s.notify_skipped
    );
    // De l'init du device à la réponse reçue, le seul ecall est le second
    // relevé de compteurs.
    let ecalls = t1.ecall - t0.ecall;
    say!(
        "BYPASS2 traps init+tx+rx : ecall={} (dont 1 pour le releve) fautes={} timer={} ctx={}",
        ecalls,
        t1.fault - t0.fault,
        t1.timer - t0.timer,
        t1.ctx_switch - t0.ctx_switch
    );

    if s.rx_bad != 0 {
        fail(5);
    }
    if s.tx_reclaimed != 1 {
        fail(6); // le device doit avoir rendu le tampon d'émission
    }
    if ecalls != 1 || t1.fault != t0.fault {
        fail(7);
    }
    say!("BYPASS2 ok");
    usys::test(0xB1A6);
    usys::exit(0);
}

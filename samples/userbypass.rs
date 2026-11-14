// Preuve de `bypass_open` : après ce seul syscall, le processus lit les
// registres du virtio-net et écrit dans sa région DMA depuis le mode
// utilisateur, sans trap.
//
// Verdict par SYS_TEST :
//   0xB1A5    conforme
//   0x0DE1ED  bypass_open a rendu EPERM (lancé sans le droit bypass)
//   0xE00+n   échec à l'étape n

#![no_std]
#![no_main]

#[path = "usys.rs"]
mod usys;

use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};

const DMA_PAGES: usize = 18; // 2 pages d'anneaux + 16 pages de tampons
const PAGE: usize = 4096;

// Registres virtio-mmio (virtio 1.x §4.2.2).
const R_MAGIC: usize = 0x000;
const R_VERSION: usize = 0x004;
const R_DEVICE_ID: usize = 0x008;
const R_STATUS: usize = 0x070;
const R_CONFIG: usize = 0x100;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    usys::exit(0xDEAD);
}

struct Line {
    buf: [u8; 160],
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
        let mut l = Line { buf: [0; 160], len: 0 };
        let _ = write!(l, $($arg)*);
        let _ = l.write_str("\n");
        usys::write(1, &l.buf[..l.len]);
    }};
}

fn fail(step: usize) -> ! {
    say!("BYPASS echec etape {}", step);
    usys::test(0xE00 + step);
    usys::exit(1);
}

#[inline(always)]
fn reg(mmio: *mut u8, off: usize) -> u32 {
    // SAFETY: page de registres mappée par bypass_open, registres 32 bits.
    unsafe { read_volatile(mmio.add(off) as *const u32) }
}

#[no_mangle]
pub extern "C" fn run() -> ! {
    // 1. L'unique syscall de mise en place.
    let info = match usys::bypass_open(usys::BYPASS_ANY, DMA_PAGES) {
        Ok(i) => i,
        Err(e) if e == -usys::EPERM => {
            say!("BYPASS refuse : EPERM (lancer avec --bypass)");
            usys::test(0x0D_E1ED);
            usys::exit(0);
        }
        Err(e) => {
            say!("BYPASS bypass_open = {}", e);
            fail(1);
        }
    };
    say!(
        "BYPASS mmio={:#x} dma={:#x} dma_len={:#x} dma_phys={:#x}",
        info.mmio as usize,
        info.dma as usize,
        info.dma_len,
        info.dma_phys
    );
    if info.dma_len != DMA_PAGES * PAGE || info.dma_phys == 0 || info.dma_phys % PAGE as u64 != 0 {
        fail(2);
    }

    // 2. Registres lus depuis le mode utilisateur, entre deux relevés de
    //    compteurs. Le second relevé est un ecall : on attend exactement
    //    1 ecall et 0 faute.
    let before = usys::trap_stats(usys::TRAPS_THREAD, 0);
    let magic = reg(info.mmio, R_MAGIC);
    let version = reg(info.mmio, R_VERSION);
    let device = reg(info.mmio, R_DEVICE_ID);
    let status = reg(info.mmio, R_STATUS);
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        // SAFETY: espace de configuration du device, accès octet.
        *b = unsafe { read_volatile(info.mmio.add(R_CONFIG + i)) };
    }
    let after = usys::trap_stats(usys::TRAPS_THREAD, 0);

    say!(
        "BYPASS magic={:#x} version={} device_id={} status={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        magic, version, device, status, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    if magic != 0x7472_6976 {
        fail(3);
    }
    if version != 2 {
        fail(4); // transport legacy
    }
    if device != 1 {
        fail(5);
    }
    if status != 0 {
        fail(6); // le noyau doit rendre un device remis à zéro
    }
    let ecalls = after.ecall - before.ecall;
    let faults = after.fault - before.fault;
    say!("BYPASS traps pendant les lectures : ecall={} (dont 1 pour le releve) fautes={}", ecalls, faults);
    if ecalls != 1 || faults != 0 {
        fail(7);
    }

    // 3. Région DMA : à zéro, inscriptible d'un bout à l'autre.
    let words = info.dma_len / 8;
    let dma = info.dma as *mut u64;
    for i in 0..words {
        // SAFETY: région de `dma_len` octets, alignée sur la page.
        if unsafe { read_volatile(dma.add(i)) } != 0 {
            fail(8);
        }
    }
    for i in [0, 1, words / 2, words - 1] {
        let v = 0xA5A5_0000_0000_0000u64 | i as u64;
        // SAFETY: idem ; `i < words`.
        unsafe { write_volatile(dma.add(i), v) };
        if unsafe { read_volatile(dma.add(i)) } != v {
            fail(9);
        }
    }

    // 4. Un processus ne tient qu'un device.
    match usys::bypass_open(usys::BYPASS_ANY, 1) {
        Err(e) if e == -usys::EBUSY => {}
        _ => fail(10),
    }

    say!("BYPASS ok");
    usys::test(0xB1A5);
    usys::exit(0);
}

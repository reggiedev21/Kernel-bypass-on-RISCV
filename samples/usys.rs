// samples/usys.rs
//
// API d'appels système CÔTÉ UTILISATEUR — la « libc » minimale des
// programmes user. Incluse par les programmes via `#[path = "usys.rs"] mod
// usys;`. Préfigure le futur SDK Rust.
//
// Les NUMÉROS doivent rester synchronisés avec src/syscall.rs (module `nr`).
// Convention : a7 = numéro, a0..a2 = args, a0 = retour ( >=0 succès,
// <0 = -errno, façon POSIX).

#![allow(dead_code)]

pub const SYS_DUP: usize = 23;
pub const SYS_OPENAT: usize = 56;
pub const SYS_CLOSE: usize = 57;
pub const SYS_READ: usize = 63;
pub const SYS_WRITE: usize = 64;
pub const SYS_EXIT: usize = 93;
pub const SYS_EXIT_GROUP: usize = 94;
pub const SYS_FUTEX: usize = 98;
pub const SYS_SET_ROBUST_LIST: usize = 99;
pub const SYS_GET_ROBUST_LIST: usize = 100;
pub const SYS_CLOCK_GETTIME: usize = 113;
pub const SYS_SOCKET: usize = 198;
pub const SYS_BIND: usize = 200;
pub const SYS_CONNECT: usize = 203;
pub const SYS_GETSOCKNAME: usize = 204;
pub const SYS_SENDTO: usize = 206;
pub const SYS_RECVFROM: usize = 207;
pub const SYS_SETSOCKOPT: usize = 208;
pub const SYS_SCHED_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CLONE: usize = 220;
pub const SYS_BRK: usize = 214;
pub const SYS_GETRANDOM: usize = 278;
pub const SYS_TEST: usize = 0x1000;
pub const SYS_GET_THREAD_INDEX: usize = 0x1001;
pub const SYS_THREAD_SPAWN: usize = 0x1002;
pub const SYS_THREAD_JOIN: usize = 0x1003;
pub const SYS_THREAD_DETACH: usize = 0x1004;
pub const SYS_GET_TRAP_STATS: usize = 0x100A;
pub const SYS_BYPASS_OPEN: usize = 0x100B;
pub const SYS_PIN_TO_HART: usize = 0x100C;
pub const SYS_GET_ARGS: usize = 0x1005;
pub const SYS_SET_SCHED_PARAM: usize = 0x1006;

/// Appel système générique (3 arguments). Renvoie a0 (isize : -errno si < 0).
#[inline(always)]
unsafe fn syscall3(num: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    // SAFETY: `ecall` bascule en S-mode ; le noyau sauvegarde/restaure les
    // registres via la trapframe.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") num,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall5(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") num,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall6(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> isize {
    let ret: isize;
    // SAFETY: cf. syscall3.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") num,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// Sockets UDP/IPv4 — la « libsocket » minimale (cf. src/net, src/syscall.rs)
// ---------------------------------------------------------------------------

pub const AF_INET: usize = 2;
pub const SOCK_DGRAM: usize = 2;
pub const MSG_DONTWAIT: usize = 0x40;
pub const EAGAIN: isize = 11;
pub const EDESTADDRREQ: isize = 89;
pub const EMSGSIZE: isize = 90;
pub const EADDRINUSE: isize = 98;

/// `struct sockaddr_in` (Linux) : 16 octets, port et adresse en ordre réseau.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub family: u16,
    pub port_be: u16,
    pub addr: [u8; 4],
    pub zero: [u8; 8],
}

impl SockAddrIn {
    pub const fn new(addr: [u8; 4], port: u16) -> Self {
        Self { family: AF_INET as u16, port_be: port.to_be(), addr, zero: [0; 8] }
    }
    pub const fn port(&self) -> u16 {
        u16::from_be(self.port_be)
    }
}

pub fn socket_udp() -> isize {
    unsafe { syscall3(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) }
}

pub fn bind(fd: usize, addr: &SockAddrIn) -> isize {
    unsafe { syscall3(SYS_BIND, fd, addr as *const SockAddrIn as usize, 16) }
}

pub fn connect(fd: usize, addr: &SockAddrIn) -> isize {
    unsafe { syscall3(SYS_CONNECT, fd, addr as *const SockAddrIn as usize, 16) }
}

pub fn getsockname(fd: usize, addr: &mut SockAddrIn, len: &mut u32) -> isize {
    unsafe {
        syscall3(SYS_GETSOCKNAME, fd, addr as *mut SockAddrIn as usize, len as *mut u32 as usize)
    }
}

pub fn sendto(fd: usize, buf: &[u8], dst: &SockAddrIn) -> isize {
    unsafe {
        syscall6(
            SYS_SENDTO,
            fd,
            buf.as_ptr() as usize,
            buf.len(),
            0,
            dst as *const SockAddrIn as usize,
            16,
        )
    }
}

/// recvfrom avec adresse d'origine.
pub fn recvfrom(
    fd: usize,
    buf: &mut [u8],
    flags: usize,
    from: &mut SockAddrIn,
    from_len: &mut u32,
) -> isize {
    unsafe {
        syscall6(
            SYS_RECVFROM,
            fd,
            buf.as_mut_ptr() as usize,
            buf.len(),
            flags,
            from as *mut SockAddrIn as usize,
            from_len as *mut u32 as usize,
        )
    }
}

/// recv() : recvfrom avec adresse NULL (le cas qui plantait dans libsocket).
pub fn recv(fd: usize, buf: &mut [u8], flags: usize) -> isize {
    unsafe { syscall6(SYS_RECVFROM, fd, buf.as_mut_ptr() as usize, buf.len(), flags, 0, 0) }
}

/// SO_RCVTIMEO en millisecondes (0 = bloquant sans limite).
pub fn set_recv_timeout_ms(fd: usize, ms: u64) -> isize {
    let tv: [i64; 2] = [(ms / 1000) as i64, ((ms % 1000) * 1000) as i64];
    unsafe { syscall5(SYS_SETSOCKOPT, fd, 1, 20, tv.as_ptr() as usize, 16) }
}

pub const CLONE_VM: usize = 0x0000_0100;
pub const CLONE_FS: usize = 0x0000_0200;
pub const CLONE_FILES: usize = 0x0000_0400;
pub const CLONE_THREAD: usize = 0x0001_0000;
pub const THREAD_CLONE_FLAGS: usize = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD;

/// clone minimal : reprend après l'ecall dans l'enfant (retour 0).
pub fn clone(stack: usize, tls: usize) -> isize {
    unsafe { syscall5(SYS_CLONE, THREAD_CLONE_FLAGS, stack, 0, tls, 0) }
}

/// write(fd, buf) — écrit `buf` sur `fd`. Renvoie le nombre d'octets ou -errno.
pub fn write(fd: usize, buf: &[u8]) -> isize {
    unsafe { syscall3(SYS_WRITE, fd, buf.as_ptr() as usize, buf.len()) }
}

/// write brut (pointeur + longueur arbitraires) — sert à ÉPROUVER la
/// validation des pointeurs (un pointeur noyau doit renvoyer -EFAULT).
pub fn write_raw(fd: usize, ptr: usize, len: usize) -> isize {
    unsafe { syscall3(SYS_WRITE, fd, ptr, len) }
}

/// Raccourci : écrit une chaîne sur stdout (fd 1).
pub fn print(s: &str) -> isize {
    write(1, s.as_bytes())
}

/// read(fd, buf) — lit dans `buf`. Bloquant. Renvoie le nombre d'octets lus.
pub fn read(fd: usize, buf: &mut [u8]) -> isize {
    unsafe { syscall3(SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len()) }
}

/// getpid() — identifiant du processus courant.
pub fn getpid() -> usize {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) as usize }
}

/// open(path) — ouvre un chemin en lecture seule (AT_FDCWD). Renvoie le fd.
/// Copie le chemin dans un tampon NUL-terminé (l'ABI attend une chaîne C).
pub fn open(path: &str) -> isize {
    const AT_FDCWD: isize = -100;
    let mut buf = [0u8; 256];
    let n = path.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&path.as_bytes()[..n]);
    buf[n] = 0;
    unsafe { syscall3(SYS_OPENAT, AT_FDCWD as usize, buf.as_ptr() as usize, 0) }
}

/// dup(fd) — duplique un descripteur ; renvoie le nouveau fd (ou -errno).
pub fn dup(fd: usize) -> isize {
    unsafe { syscall3(SYS_DUP, fd, 0, 0) }
}

/// close(fd) — ferme un descripteur.
pub fn close(fd: usize) -> isize {
    unsafe { syscall3(SYS_CLOSE, fd, 0, 0) }
}

/// sched_yield() — cède le CPU.
pub fn sched_yield() {
    unsafe {
        syscall3(SYS_SCHED_YIELD, 0, 0, 0);
    }
}

/// get_thread_index() — index dense du thread courant (0 = principal).
pub fn thread_index() -> usize {
    unsafe { syscall3(SYS_GET_THREAD_INDEX, 0, 0, 0) as usize }
}

/// thread_spawn(entry, arg) — crée un thread démarrant à `entry(arg)` (mode
/// utilisateur, pile fournie par le noyau). `entry` ne doit jamais revenir :
/// il termine par `exit`. Renvoie le tid (ou < 0).
pub fn thread_spawn(entry: extern "C" fn(usize) -> !, arg: usize) -> isize {
    unsafe { syscall3(SYS_THREAD_SPAWN, entry as usize, arg, 0) }
}

pub fn thread_join(tid: usize, ret: &mut usize) -> isize {
    unsafe { syscall3(SYS_THREAD_JOIN, tid, ret as *mut usize as usize, 0) }
}

pub fn thread_detach(tid: usize) -> isize {
    unsafe { syscall3(SYS_THREAD_DETACH, tid, 0, 0) }
}

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

pub fn futex_wait(word: *const u32, expected: u32, timeout: Option<&Timespec>) -> isize {
    unsafe {
        syscall5(
            SYS_FUTEX,
            word as usize,
            0 | 128,
            expected as usize,
            timeout.map_or(0, |t| t as *const Timespec as usize),
            0,
        )
    }
}

pub fn futex_wake(word: *const u32, count: usize) -> isize {
    unsafe { syscall5(SYS_FUTEX, word as usize, 1 | 128, count, 0, 0) }
}

pub fn set_robust_list(head: usize, len: usize) -> isize {
    unsafe { syscall3(SYS_SET_ROBUST_LIST, head, len, 0) }
}

pub fn get_robust_list(head: &mut usize, len: &mut usize) -> isize {
    unsafe {
        syscall3(
            SYS_GET_ROBUST_LIST,
            0,
            head as *mut usize as usize,
            len as *mut usize as usize,
        )
    }
}

// ---------------------------------------------------------------------------
// Instruments de mesure
// ---------------------------------------------------------------------------

/// Compteurs de traps rendus par le noyau (8 × u64).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrapStats {
    pub ecall: u64,
    pub timer: u64,
    pub external: u64,
    pub software: u64,
    pub fault: u64,
    pub ctx_switch: u64,
    /// Hart sur lequel l'appel a été servi.
    pub hart: u64,
    /// `rdinstret` de la dernière IRQ du NIC noyau.
    pub nic_irq_instret: u64,
}

pub const TRAPS_THREAD: usize = 0;
pub const TRAPS_HART: usize = 1;
pub const TRAPS_ALL_HARTS: usize = 2;

/// Lit les compteurs. C'est un `ecall`, donc un trap de plus dans ce qu'il
/// lit : à retrancher des différences.
pub fn trap_stats(scope: usize, hart: usize) -> TrapStats {
    let mut s = TrapStats::default();
    unsafe {
        syscall3(SYS_GET_TRAP_STATS, scope, hart, &mut s as *mut TrapStats as usize);
    }
    s
}

/// Compteur `cycle`. Sous QEMU -icount il compte des nanosecondes virtuelles
/// (4 par instruction avec shift=2), pas des cycles.
#[inline(always)]
pub fn rdcycle() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("rdcycle {}", out(reg) v, options(nomem, nostack)) };
    v
}

/// Instructions exécutées : l'unité des latences sous QEMU -icount. Compteur
/// global à la machine (tous harts). Sans -icount, il suit l'horloge de l'hôte.
#[inline(always)]
pub fn rdinstret() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("rdinstret {}", out(reg) v, options(nomem, nostack)) };
    v
}

/// CSR `time` (10 MHz sur QEMU virt : 100 ns par unité).
#[inline(always)]
pub fn rdtime() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) v, options(nomem, nostack)) };
    v
}

// ---------------------------------------------------------------------------
// Kernel bypass
// ---------------------------------------------------------------------------

/// Ce que le noyau cède au processus. Après cet appel, plus aucun syscall
/// n'est nécessaire pour émettre ou recevoir.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BypassInfo {
    /// Registres virtio-mmio du device (4 Kio, R|W).
    pub mmio: *mut u8,
    /// Région DMA : anneaux et tampons (R|W, à zéro).
    pub dma: *mut u8,
    pub dma_len: usize,
    /// Adresse physique du début de `dma`. Le device ne connaît que des
    /// adresses physiques : `phys = dma_phys + (va - dma)`.
    pub dma_phys: u64,
}

/// `slot` : le premier virtio-net que le noyau n'utilise pas.
pub const BYPASS_ANY: usize = usize::MAX;
pub const EPERM: isize = 1;
pub const EBUSY: isize = 16;
pub const ENODEV: isize = 19;

/// Ouvre un device en bypass. Exige d'avoir été lancé avec `--bypass`.
pub fn bypass_open(slot: usize, dma_pages: usize) -> Result<BypassInfo, isize> {
    let mut info = BypassInfo {
        mmio: core::ptr::null_mut(),
        dma: core::ptr::null_mut(),
        dma_len: 0,
        dma_phys: 0,
    };
    let r = unsafe {
        syscall3(SYS_BYPASS_OPEN, slot, dma_pages, &mut info as *mut BypassInfo as usize)
    };
    if r == 0 { Ok(info) } else { Err(r) }
}

// ---------------------------------------------------------------------------
// Ordonnancement et arguments
// ---------------------------------------------------------------------------

/// Passe le thread courant en round-robin à la priorité `prio` (0..=31,
/// 31 = la plus haute, 16 par défaut).
pub fn set_rr_priority(prio: u32) -> isize {
    // [policy u32 = 0 (round-robin), priority u32, puis trois u64 inutilisés]
    let mut param = [0u8; 32];
    param[4..8].copy_from_slice(&prio.to_ne_bytes());
    unsafe { syscall3(SYS_SET_SCHED_PARAM, 0, param.as_ptr() as usize, 0) }
}

/// Réserve le hart `hart` (≠ 0) au thread courant et l'y déplace. Ce hart
/// n'exécute alors plus que lui, sans interruption timer ni IPI.
pub fn pin_to_hart(hart: usize) -> isize {
    unsafe { syscall3(SYS_PIN_TO_HART, hart, 0, 0) }
}

/// Appelle `f` pour chaque argument de lancement, nom du programme exclu.
pub fn for_each_arg(mut f: impl FnMut(&str)) {
    let mut buf = [0u8; 260];
    let n = unsafe { syscall3(SYS_GET_ARGS, buf.as_mut_ptr() as usize, buf.len(), 0) };
    if n < 4 || n as usize > buf.len() {
        return;
    }
    // [argc : u32][argv séparés par des NUL]
    let blob = &buf[4..n as usize];
    for (i, arg) in blob.split(|&b| b == 0).enumerate() {
        if i == 0 || arg.is_empty() {
            continue;
        }
        if let Ok(s) = core::str::from_utf8(arg) {
            f(s);
        }
    }
}

/// test(val) — extension noyau (point d'observation des tests).
pub fn test(val: usize) -> isize {
    unsafe { syscall3(SYS_TEST, val, 0, 0) }
}

/// exit(code) — termine le processus. Ne revient jamais.
pub fn exit(code: usize) -> ! {
    unsafe {
        syscall3(SYS_EXIT, code, 0, 0);
    }
    loop {}
}

pub fn exit_group(code: usize) -> ! {
    unsafe {
        syscall3(SYS_EXIT_GROUP, code, 0, 0);
    }
    loop {}
}

/// brk(addr) — ajuste la rupture du tas ; renvoie la rupture (courante si
/// `addr==0` ou en cas d'échec). Socle de l'allocateur ci-dessous.
pub fn brk(addr: usize) -> usize {
    unsafe { syscall3(SYS_BRK, addr, 0, 0) as usize }
}

/// Nanosecondes depuis le boot (CLOCK_MONOTONIC).
pub fn now_ns() -> u64 {
    let mut ts = [0i64; 2]; // { tv_sec, tv_nsec }
    unsafe {
        syscall3(SYS_CLOCK_GETTIME, 1, ts.as_mut_ptr() as usize, 0);
    }
    (ts[0] as u64) * 1_000_000_000 + (ts[1] as u64)
}

/// Remplit `buf` d'octets aléatoires. Renvoie le nombre d'octets.
pub fn getrandom(buf: &mut [u8]) -> isize {
    unsafe { syscall3(SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), 0) }
}

// ===========================================================================
// Allocateur global minimal (bump) adossé à brk — débloque `alloc`
// (Vec/String/format!…). N'utilise que `core` (pas la crate `alloc`), pour
// rester incluable même par des programmes qui n'allouent pas.
//
// Simplifications assumées : `dealloc` est un no-op (pas de récupération) ;
// un vrai allocateur (free-list) le remplacera. Suffisant pour prouver que
// le tas fonctionne de bout en bout. Le processus utilisateur étant
// mono-thread, l'`UnsafeCell` est sûr.
// ===========================================================================

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

struct HeapState {
    cur: usize, // pointeur de bump
    end: usize, // rupture actuelle (brk)
}

pub struct BumpAlloc(UnsafeCell<HeapState>);

// SAFETY: un processus utilisateur est mono-thread ici ; aucun accès concurrent.
unsafe impl Sync for BumpAlloc {}

impl BumpAlloc {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(HeapState { cur: 0, end: 0 }))
    }
}

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: mono-thread ; référence unique le temps de l'appel.
        let h = unsafe { &mut *self.0.get() };
        if h.end == 0 {
            let b = brk(0);
            h.cur = b;
            h.end = b;
        }
        let align = layout.align().max(8);
        let start = (h.cur + align - 1) & !(align - 1);
        let new_cur = match start.checked_add(layout.size()) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        if new_cur > h.end {
            // Croît par blocs de 64 KiB pour limiter les syscalls.
            let grow = (new_cur + 0xFFFF) & !0xFFFF;
            let got = brk(grow);
            if got < grow {
                return core::ptr::null_mut(); // OOM
            }
            h.end = got;
        }
        h.cur = new_cur;
        start as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // bump : pas de libération individuelle.
    }
}

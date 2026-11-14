// Pilote virtio-net en espace utilisateur.
//
// Après `bypass_open`, tout ce fichier n'est que des lectures et des écritures
// en mémoire : registres du device (page MMIO) et anneaux/tampons (région
// DMA). Aucun syscall, aucune interruption, aucune allocation.
//
// Périmètre : transport MMIO moderne (version 2), virtqueues scindées, une
// file RX et une file TX, aucune offload. Une trame = un tampon = un
// descripteur, précédée de l'en-tête virtio-net de 12 octets.

#![allow(dead_code)]

use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{fence, AtomicU16, Ordering};

use crate::usys::BypassInfo;

// --- Géométrie -------------------------------------------------------------

/// Descripteurs par file. Puissance de 2, <= 16 (masques `u16`).
pub const QSIZE: usize = 16;
pub const BUF_SIZE: usize = 2048;
/// En-tête virtio-net : 12 octets avec VERSION_1.
pub const HDR_LEN: usize = 12;
/// Trame Ethernet maximale, sans FCS.
pub const MAX_FRAME: usize = 1514;

const PAGE: usize = 4096;

// Découpage de la région DMA : une page d'anneaux par file, puis les tampons.
// Alignements exigés par la spec : desc 16, avail 2, used 4.
const OFF_RX_RING: usize = 0x0000;
const OFF_TX_RING: usize = 0x1000;
const OFF_DESC: usize = 0x000; // 16 descripteurs de 16 octets
const OFF_AVAIL: usize = 0x400; // flags, idx, ring[QSIZE], used_event (u16)
const OFF_USED: usize = 0x800; // flags, idx (u16), ring[QSIZE] {id, len} (u32)
const OFF_RX_BUFS: usize = 0x2000;
const OFF_TX_BUFS: usize = OFF_RX_BUFS + QSIZE * BUF_SIZE;
const DMA_NEEDED: usize = OFF_TX_BUFS + QSIZE * BUF_SIZE;

/// Pages à demander à `bypass_open` (18).
pub const DMA_PAGES: usize = DMA_NEEDED / PAGE;

const _: () = assert!(QSIZE.is_power_of_two() && QSIZE <= 16);
const _: () = assert!(HDR_LEN + MAX_FRAME <= BUF_SIZE);
const _: () = assert!(DMA_NEEDED % PAGE == 0);
const _: () = assert!(OFF_USED + 4 + 8 * QSIZE + 2 <= PAGE);

// --- Registres virtio-mmio (virtio 1.x §4.2.2) -----------------------------

const R_MAGIC: usize = 0x000;
const R_VERSION: usize = 0x004;
const R_DEVICE_ID: usize = 0x008;
const R_DEV_FEATURES: usize = 0x010;
const R_DEV_FEATURES_SEL: usize = 0x014;
const R_DRV_FEATURES: usize = 0x020;
const R_DRV_FEATURES_SEL: usize = 0x024;
const R_QUEUE_SEL: usize = 0x030;
const R_QUEUE_NUM_MAX: usize = 0x034;
const R_QUEUE_NUM: usize = 0x038;
const R_QUEUE_READY: usize = 0x044;
const R_QUEUE_NOTIFY: usize = 0x050;
const R_STATUS: usize = 0x070;
const R_QUEUE_DESC_LO: usize = 0x080;
const R_QUEUE_DESC_HI: usize = 0x084;
const R_QUEUE_AVAIL_LO: usize = 0x090;
const R_QUEUE_AVAIL_HI: usize = 0x094;
const R_QUEUE_USED_LO: usize = 0x0A0;
const R_QUEUE_USED_HI: usize = 0x0A4;
const R_CONFIG: usize = 0x100;

const MAGIC: u32 = 0x7472_6976; // "virt"
const DEVICE_ID_NET: u32 = 1;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

/// Bit 5 du mot bas : MAC lisible dans l'espace de configuration.
const F_NET_MAC: u32 = 1 << 5;
/// Bit 32 (bit 0 du mot haut) : VIRTIO_F_VERSION_1.
const F_VERSION_1_HI: u32 = 1 << 0;

const Q_RX: u32 = 0;
const Q_TX: u32 = 1;

/// Le device peut écrire dans ce tampon (file RX).
const DESC_F_WRITE: u16 = 2;
/// Pilote → device : pas d'interruption quand un tampon est consommé.
const AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Device → pilote : inutile de notifier.
const USED_F_NO_NOTIFY: u16 = 1;

// --- Une virtqueue scindée -------------------------------------------------
//
// Les trois zones sont partagées avec le device, qui les lit et les écrit
// quand il veut. Elles ne sont jamais vues à travers une référence Rust (le
// compilateur pourrait sortir la lecture de `used.idx` de la boucle) : accès
// volatils sur pointeurs bruts, et `AtomicU16` pour les deux index.

struct Queue {
    index: u32,
    /// Adresses virtuelles des trois zones et du premier tampon.
    desc: usize,
    avail: usize,
    used: usize,
    bufs: usize,
    /// Copie locale de `avail.idx` : le pilote en est le seul écrivain.
    avail_idx: u16,
    /// Prochain élément de `used` à consommer.
    last_used: u16,
}

impl Queue {
    fn new(index: u32, ring: usize, bufs: usize) -> Self {
        Self {
            index,
            desc: ring + OFF_DESC,
            avail: ring + OFF_AVAIL,
            used: ring + OFF_USED,
            bufs,
            avail_idx: 0,
            last_used: 0,
        }
    }

    fn buf(&self, id: usize) -> usize {
        self.bufs + id * BUF_SIZE
    }

    /// Écrit le descripteur `id` : { addr u64, len u32, flags u16, next u16 }.
    fn write_desc(&self, id: usize, addr_phys: u64, len: u32, flags: u16) {
        let d = self.desc + id * 16;
        // SAFETY: `id < QSIZE` ; le descripteur n'est pas dans `avail`, le
        // device ne le lit pas.
        unsafe {
            write_volatile(d as *mut u64, addr_phys);
            write_volatile((d + 8) as *mut u32, len);
            write_volatile((d + 12) as *mut u16, flags);
            write_volatile((d + 14) as *mut u16, 0);
        }
    }

    fn write_desc_len(&self, id: usize, len: u32) {
        // SAFETY: idem `write_desc`.
        unsafe { write_volatile((self.desc + id * 16 + 8) as *mut u32, len) };
    }

    fn set_avail_flags(&self, flags: u16) {
        // SAFETY: premier mot de la zone avail.
        unsafe { write_volatile(self.avail as *mut u16, flags) };
    }

    /// Offre le descripteur `id` au device, sans notifier (voir `kick_*`).
    ///
    /// L'ordre compte : descripteur déjà écrit, puis entrée d'anneau, puis
    /// index avec `Release`. RISC-V a un ordre mémoire faible : le device qui
    /// voit le nouvel index doit voir aussi l'entrée et le descripteur.
    fn publish(&mut self, id: u16) {
        let slot = self.avail_idx as usize & (QSIZE - 1);
        // SAFETY: `slot < QSIZE` ; zone avail, alignée sur 2.
        unsafe { write_volatile((self.avail + 4 + 2 * slot) as *mut u16, id) };
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: `avail.idx`, u16 aligné, vu comme atomique.
        let idx = unsafe { &*((self.avail + 2) as *const AtomicU16) };
        idx.store(self.avail_idx, Ordering::Release);
    }

    /// Dépile un élément de `used` : (id du descripteur, octets écrits).
    /// C'est la lecture du polling : un `load` de `used.idx`.
    #[inline]
    fn pop_used(&mut self) -> Option<(u32, u32)> {
        // SAFETY: `used.idx`, u16 aligné, écrit par le device.
        let idx = unsafe { &*((self.used + 2) as *const AtomicU16) };
        if idx.load(Ordering::Acquire) == self.last_used {
            return None;
        }
        let slot = self.last_used as usize & (QSIZE - 1);
        let elem = self.used + 4 + 8 * slot;
        // SAFETY: `slot < QSIZE` ; élément publié avant l'index lu ci-dessus.
        let (id, len) =
            unsafe { (read_volatile(elem as *const u32), read_volatile((elem + 4) as *const u32)) };
        self.last_used = self.last_used.wrapping_add(1);
        Some((id, len))
    }

    /// Le device veut-il être notifié ? La barrière sépare notre écriture de
    /// `avail.idx` de la lecture de `used.flags` : sans elle, chaque côté peut
    /// lire l'ancienne valeur de l'autre et la notification se perd.
    fn wants_notify(&self) -> bool {
        fence(Ordering::SeqCst);
        // SAFETY: premier mot de la zone used, écrit par le device.
        unsafe { read_volatile(self.used as *const u16) & USED_F_NO_NOTIFY == 0 }
    }
}

// --- Jetons ----------------------------------------------------------------
//
// Un jeton possède un tampon, sans emprunter le pilote : on peut tenir une
// trame reçue et une trame en cours d'écriture en même temps. Ni `Copy` ni
// `Clone`, consommé par valeur : rendre deux fois le même tampon ne compile
// pas.

/// Une trame reçue. À rendre par `VirtioNet::recycle`.
#[must_use = "un tampon RX non rendu est perdu pour le device"]
pub struct RxToken {
    id: u16,
    ptr: *const u8,
    len: usize,
}

impl RxToken {
    /// La trame Ethernet, sans l'en-tête virtio.
    pub fn frame(&self) -> &[u8] {
        // SAFETY: tampon rendu par le device et pas encore republié ; `len`
        // borné par `poll_rx`.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// Un tampon d'émission. À consommer par `submit` ou `release_tx`.
#[must_use = "un tampon TX non soumis ni relâché est perdu"]
pub struct TxToken {
    id: u16,
    ptr: *mut u8,
}

impl TxToken {
    /// Où écrire la trame Ethernet (MAX_FRAME octets).
    pub fn buf(&mut self) -> &mut [u8] {
        // SAFETY: tampon libre, absent de l'anneau avail.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, MAX_FRAME) }
    }
}

// --- Le device -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// Région DMA trop petite (DMA_PAGES pages requises).
    DmaTooSmall,
    /// Pas un virtio-net en transport moderne.
    NotVirtioNet,
    /// Le device refuse VERSION_1, ou FEATURES_OK ne tient pas.
    Negotiation,
    /// File déjà active, ou trop petite.
    Queue,
}

/// Compteurs du pilote.
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub rx_frames: u64,
    /// Éléments `used` incohérents (id ou longueur).
    pub rx_bad: u64,
    pub tx_frames: u64,
    pub tx_reclaimed: u64,
    /// Écritures de QueueNotify : chacune est une sortie vers QEMU.
    pub notify_rx: u64,
    pub notify_tx: u64,
    /// Notifications évitées (le device a posé NO_NOTIFY).
    pub notify_skipped: u64,
}

pub struct VirtioNet {
    mmio: usize,
    dma: usize,
    dma_len: usize,
    dma_phys: u64,
    mac: [u8; 6],
    rx: Queue,
    tx: Queue,
    /// Bit i à 1 : tampon TX i libre.
    tx_free: u16,
    /// Bit i à 1 : tampon RX i tenu par un `RxToken`.
    rx_held: u16,
    pub stats: Stats,
}

impl VirtioNet {
    #[inline(always)]
    fn r(&self, off: usize) -> u32 {
        // SAFETY: page de registres mappée par bypass_open, registres 32 bits.
        unsafe { read_volatile((self.mmio + off) as *const u32) }
    }

    #[inline(always)]
    fn w(&self, off: usize, val: u32) {
        // SAFETY: idem `r`.
        unsafe { write_volatile((self.mmio + off) as *mut u32, val) }
    }

    /// Traduction adresse virtuelle → physique, la seule du pilote. Une
    /// adresse virtuelle écrite par erreur dans un descripteur ne déclenche
    /// aucune faute : le device écrit à cette adresse physique.
    fn phys(&self, va: usize) -> u64 {
        assert!(va >= self.dma && va < self.dma + self.dma_len, "adresse hors de la région DMA");
        self.dma_phys + (va - self.dma) as u64
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Initialise le device (virtio 1.x §3.1.1). `info` vient de
    /// `bypass_open(_, DMA_PAGES)` ; la région DMA doit être à zéro.
    pub fn init(info: &BypassInfo) -> Result<Self, InitError> {
        if info.dma_len < DMA_NEEDED {
            return Err(InitError::DmaTooSmall);
        }
        let dma = info.dma as usize;
        let mut dev = Self {
            mmio: info.mmio as usize,
            dma,
            dma_len: info.dma_len,
            dma_phys: info.dma_phys,
            mac: [0; 6],
            rx: Queue::new(Q_RX, dma + OFF_RX_RING, dma + OFF_RX_BUFS),
            tx: Queue::new(Q_TX, dma + OFF_TX_RING, dma + OFF_TX_BUFS),
            tx_free: u16::MAX >> (16 - QSIZE),
            rx_held: 0,
            stats: Stats::default(),
        };

        if dev.r(R_MAGIC) != MAGIC || dev.r(R_VERSION) != 2 || dev.r(R_DEVICE_ID) != DEVICE_ID_NET {
            return Err(InitError::NotVirtioNet);
        }

        // 1. Reset, puis ACKNOWLEDGE, puis DRIVER.
        dev.w(R_STATUS, 0);
        while dev.r(R_STATUS) != 0 {
            core::hint::spin_loop();
        }
        dev.w(R_STATUS, STATUS_ACKNOWLEDGE);
        dev.w(R_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // 2. Négociation : VERSION_1 exigée, MAC si proposée, rien d'autre.
        dev.w(R_DEV_FEATURES_SEL, 0);
        let dev_lo = dev.r(R_DEV_FEATURES);
        dev.w(R_DEV_FEATURES_SEL, 1);
        let dev_hi = dev.r(R_DEV_FEATURES);
        if dev_hi & F_VERSION_1_HI == 0 {
            dev.w(R_STATUS, STATUS_FAILED);
            return Err(InitError::Negotiation);
        }
        dev.w(R_DRV_FEATURES_SEL, 0);
        dev.w(R_DRV_FEATURES, dev_lo & F_NET_MAC);
        dev.w(R_DRV_FEATURES_SEL, 1);
        dev.w(R_DRV_FEATURES, F_VERSION_1_HI);

        // 3. FEATURES_OK, à relire : le device l'efface s'il refuse.
        let status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
        dev.w(R_STATUS, status);
        if dev.r(R_STATUS) & STATUS_FEATURES_OK == 0 {
            dev.w(R_STATUS, STATUS_FAILED);
            return Err(InitError::Negotiation);
        }

        // 4. Les deux files : taille, adresses physiques, activation.
        dev.setup_queue(Q_RX)?;
        dev.setup_queue(Q_TX)?;

        // 5. Polling : aucune interruption demandée.
        dev.rx.set_avail_flags(AVAIL_F_NO_INTERRUPT);
        dev.tx.set_avail_flags(AVAIL_F_NO_INTERRUPT);

        // 6. Descripteurs : desc[i] désigne toujours le tampon i. En RX le
        //    device écrit ; en TX la longueur est réécrite à chaque émission.
        for i in 0..QSIZE {
            let rx_pa = dev.phys(dev.rx.buf(i));
            dev.rx.write_desc(i, rx_pa, BUF_SIZE as u32, DESC_F_WRITE);
            let tx_pa = dev.phys(dev.tx.buf(i));
            dev.tx.write_desc(i, tx_pa, 0, 0);
        }

        // 7. Le device peut consommer.
        dev.w(R_STATUS, status | STATUS_DRIVER_OK);

        // 8. Tous les tampons RX offerts, une seule notification.
        for i in 0..QSIZE {
            dev.rx.publish(i as u16);
        }
        dev.w(R_QUEUE_NOTIFY, Q_RX);
        dev.stats.notify_rx += 1;

        // 9. Adresse MAC, au début de l'espace de configuration.
        if dev_lo & F_NET_MAC != 0 {
            for i in 0..6 {
                // SAFETY: espace de configuration du device, accès octet.
                dev.mac[i] = unsafe { read_volatile((dev.mmio + R_CONFIG + i) as *const u8) };
            }
        } else {
            dev.mac = [0x02, 0x00, 0x00, 0x52, 0x54, 0x01]; // administrée localement
        }
        Ok(dev)
    }

    fn setup_queue(&mut self, index: u32) -> Result<(), InitError> {
        self.w(R_QUEUE_SEL, index);
        if self.r(R_QUEUE_READY) != 0 || (self.r(R_QUEUE_NUM_MAX) as usize) < QSIZE {
            return Err(InitError::Queue);
        }
        let (desc, avail, used) = {
            let q = if index == Q_RX { &self.rx } else { &self.tx };
            (self.phys(q.desc), self.phys(q.avail), self.phys(q.used))
        };
        self.w(R_QUEUE_NUM, QSIZE as u32);
        self.w(R_QUEUE_DESC_LO, desc as u32);
        self.w(R_QUEUE_DESC_HI, (desc >> 32) as u32);
        self.w(R_QUEUE_AVAIL_LO, avail as u32);
        self.w(R_QUEUE_AVAIL_HI, (avail >> 32) as u32);
        self.w(R_QUEUE_USED_LO, used as u32);
        self.w(R_QUEUE_USED_HI, (used >> 32) as u32);
        self.w(R_QUEUE_READY, 1);
        Ok(())
    }

    // --- Réception ---

    /// Une trame est-elle arrivée ? Une lecture de `used.idx`, pas de syscall.
    #[inline]
    pub fn poll_rx(&mut self) -> Option<RxToken> {
        loop {
            let (id, total) = self.rx.pop_used()?;
            let (id, total) = (id as usize, total as usize);
            // On ne fait pas confiance au device : id hors bornes ou déjà
            // tenu, longueur impossible.
            if id >= QSIZE || self.rx_held & (1 << id) != 0 {
                self.stats.rx_bad += 1;
                continue;
            }
            if total <= HDR_LEN || total > BUF_SIZE {
                self.stats.rx_bad += 1;
                self.rx.publish(id as u16); // tampon rendu tel quel
                continue;
            }
            self.rx_held |= 1 << id;
            self.stats.rx_frames += 1;
            return Some(RxToken {
                id: id as u16,
                ptr: (self.rx.buf(id) + HDR_LEN) as *const u8,
                len: total - HDR_LEN,
            });
        }
    }

    /// Rend le tampon au device. Sinon la file RX se vide et le device jette
    /// les trames sans rien signaler.
    #[inline]
    pub fn recycle(&mut self, t: RxToken) {
        self.rx_held &= !(1 << t.id);
        self.rx.publish(t.id);
    }

    /// Notifie la file RX, une fois par lot de `recycle`. Si la file s'est
    /// vidée, le device ne reprend qu'à cette notification.
    #[inline]
    pub fn kick_rx(&mut self) {
        if self.rx.wants_notify() {
            self.w(R_QUEUE_NOTIFY, Q_RX);
            self.stats.notify_rx += 1;
        } else {
            self.stats.notify_skipped += 1;
        }
    }

    // --- Émission ---

    /// Un tampon d'émission libre, en-tête virtio à zéro.
    #[inline]
    pub fn alloc_tx(&mut self) -> Option<TxToken> {
        if self.tx_free == 0 {
            self.reclaim_tx();
            if self.tx_free == 0 {
                return None;
            }
        }
        let id = self.tx_free.trailing_zeros() as usize;
        self.tx_free &= !(1 << id);
        let base = self.tx.buf(id);
        // SAFETY: tampon libre. En-tête à zéro = aucune offload demandée.
        unsafe { write_bytes(base as *mut u8, 0, HDR_LEN) };
        Some(TxToken { id: id as u16, ptr: (base + HDR_LEN) as *mut u8 })
    }

    /// Soumet `len` octets de trame, sans notifier : `kick_tx` après le lot.
    #[inline]
    pub fn submit(&mut self, t: TxToken, len: usize) {
        let len = len.min(MAX_FRAME);
        self.tx.write_desc_len(t.id as usize, (HDR_LEN + len) as u32);
        self.tx.publish(t.id);
        self.stats.tx_frames += 1;
    }

    /// Tampon finalement inutilisé.
    #[inline]
    pub fn release_tx(&mut self, t: TxToken) {
        self.tx_free |= 1 << t.id;
    }

    /// Notifie la file TX.
    #[inline]
    pub fn kick_tx(&mut self) {
        if self.tx.wants_notify() {
            self.w(R_QUEUE_NOTIFY, Q_TX);
            self.stats.notify_tx += 1;
        } else {
            self.stats.notify_skipped += 1;
        }
    }

    /// Récupère les tampons dont l'émission est terminée.
    #[inline]
    pub fn reclaim_tx(&mut self) {
        while let Some((id, _)) = self.tx.pop_used() {
            if (id as usize) < QSIZE {
                self.tx_free |= 1 << id;
                self.stats.tx_reclaimed += 1;
            }
        }
    }
}

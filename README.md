# Kernel bypass on a hobby RTOS: a user-space virtio-net driver in Rust on RISC-V

Nov 14, 2026 · @Yassine

*This article was drafted with Claude Fable from the code and the measurement log, then reviewed and corrected by me.*

High-frequency trading firms take the kernel out of the network path to gain speed and, above all, predictability. I wanted to understand how that works at the lowest level, so I built it on the RTOS I am writing in Rust for RISC-V: a UDP echo whose data path never enters the kernel, compared against the same echo going through sockets.

The short version: the bypass path is about 16 times shorter, but removing syscalls was the easy part. Most of the work, and most of what I learned, was about the jitter the scheduler still imposes on a thread that never asks the kernel for anything.

| UDP echo, 64-byte datagrams, idle system, one hart | Kernel path | Bypass path |
| --- | --- | --- |
| Traps per packet | 3 | 0 |
| Instructions from arrival to reply | 5,275 + 3,821 = 9,096 (sum of two medians) | 544, plus at most 68 of waiting |
| Spread between best and worst case | about 5,300 and 4,800 | 20, plus at most 68 |

This table is the final state, after the scheduler changes of section 7, with the bypass thread at high priority. Section 6 shows the first comparison, taken before those changes, which is why its figures differ slightly (8,517 and 529).

The kernel is closed source for now, so this article describes its side in prose only. All the user-space bypass code is in this repository.

The article has two parts. First, a short tour of how kernel bypass works on Linux, so the vocabulary and the trade-offs are clear. Then the experiment on my own RTOS, which follows the same idea: one control-plane call into the kernel, and a data plane that lives entirely in user space.

## Kernel bypass on Linux

### The problem

On 10 GbE with 64-byte frames, the line rate is 14.88 million packets per second. At 3 GHz that leaves about 200 cycles per packet. A conventional network stack handles on the order of 1 Mpps per core, which is about 3,000 cycles per packet (rough orders of magnitude, not measurements of mine).

The cost comes from many small things: interrupts, syscalls, allocating a `sk_buff`, crossing the stack (netfilter, routing, socket layer), copying from kernel to user space, wake-ups and context switches, cache misses and locks.

### What bypass removes

The principle: the data plane leaves the kernel, the control plane stays in it (configuration, initialisation, permissions).

| Step | Classic path | With bypass |
| --- | --- | --- |
| DMA from the NIC into the RX ring | NIC | NIC (unchanged) |
| Notification | IRQ, then NAPI (softirq) | The application **polls** in a busy loop |
| Network stack | Kernel (`sk_buff`, IP, UDP, TCP) | The application, or a library, redoes it or skips it |
| Queueing and wake-up | Socket buffer, scheduler | None: the application reads the ring directly |
| Copy to user space | `recv()` copies | **Zero-copy**: the application reads the DMA buffer |

### The building blocks

- **Polling.** One core runs at 100% on the RX descriptors. No interrupt, so no interrupt jitter, but a core burns permanently.
- **Lock-free rings** (SPSC or MPMC) of descriptors `{address, length, flags}`, with producer and consumer indices.
- **Batching.** Handling 32 to 64 packets per iteration amortises fixed costs (cache, MMIO doorbell).
- **DMA memory.** Hugepages (fewer TLB misses, pinned and physically contiguous memory), an **IOMMU with VFIO** to give a user process isolated DMA access to a device without exposing all of RAM, and NUMA placement so the NIC, the memory and the thread sit on the same node.
- **CPU isolation.** `isolcpus=`, `nohz_full=`, `rcu_nocbs=`, IRQ affinity moved elsewhere, pinned threads, the `performance` governor.
- **Multi-queue and RSS.** The NIC spreads flows over N RX queues, one per core, with nothing shared.
- **Cache discipline.** 64-byte alignment, no false sharing, prefetching descriptors and headers.

### The Linux toolbox

| Technology | How it works | What it costs you | Typical use |
| --- | --- | --- | --- |
| **DPDK** | The NIC is unbound from the kernel and bound to `vfio-pci`; a user-space poll-mode driver runs it. Pieces: EAL, `mempool`/`mbuf`, `rte_ring`, `rte_eth_rx_burst()` / `rte_eth_tx_burst()`. | The NIC disappears for the kernel (no `tcpdump`, no `ip`); you bring your own stack; heavy deployment. | Software routers and firewalls, vSwitches, 5G user plane, load balancers, trading |
| **XDP / eBPF** | An eBPF program runs in the driver, before the `sk_buff` exists. Verdicts: `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT`, `XDP_ABORTED`. | The kernel stays in charge; you are limited to what eBPF allows. | Anti-DDoS, L4 load balancing, filtering |
| **AF\_XDP** | An `AF_XDP` socket receives the frames XDP redirects, straight into a shared memory area (UMEM), through four rings: Fill, RX, Completion, TX. Zero-copy when the driver supports it. | Close to DPDK in speed, but the NIC stays under the kernel and unredirected traffic follows the normal path. | High throughput in user space without giving up the kernel |
| **io\_uring** | Two shared rings (submission and completion), batched submission, optional `SQPOLL`, registered buffers. | Not a network bypass: it removes syscall overhead, not the stack. | Application networking, above all storage |
| **RDMA** | The NIC reads and writes remote memory directly (verbs, queue pairs, memory regions): full bypass plus offload. | Specific hardware and fabric. | HPC, distributed storage, AI training |

There are others (Onload and `ef_vi` for transparent socket bypass, netmap, PF\_RING ZC, and SPDK, the DPDK equivalent for NVMe), but I don't think I am good enough to go over them correctly.

### When not to do it

Bypass has real costs: cores at 100% all the time, complexity, loss of kernel tooling (firewall, `tcpdump`, routing), a stack to maintain, and dependence on the NIC. If the network is not your bottleneck, or you are below roughly 1 to 2 Mpps per core (a rule of thumb, not a measured threshold), try the cheaper options first: `SO_REUSEPORT`, `recvmmsg`/`sendmmsg`.

Security is the other cost. Without an IOMMU, a user-space process that programs a DMA-capable device can make it overwrite any memory. With VFIO and an IOMMU the device is confined, but the process still controls the NIC, and a bug in your own user-space stack is no longer caught by the kernel.

One measurement trap deserves a mention: reporting throughput and ignoring tail latency. What matters is p99 and p99.9, not the average.

### Where my design sits

My design is closest to the DPDK and VFIO model: a single control-plane call hands a device and a DMA region to a process, and everything after that is memory reads and writes, with a polling loop and a lock-free split virtqueue. The main difference is that my RTOS has no IOMMU, so the bypass process is simply trusted. The rest of the article is about what that looks like on a small RTOS, and what it still cannot remove.

## 1. What is measured, and what QEMU allows

Everything runs on QEMU's `virt` machine with two virtio-net devices: one owned by the kernel, one handed to the bypass process. Both paths therefore coexist in the same boot and are driven by the same host client, a ping-pong with a single datagram in flight.

Jitter in a software path has two origins. Structural jitter is the variation in the number of instructions executed between a frame's arrival and the reply: traps, context switches, locks, preemptions. Micro-architectural jitter comes from caches, TLBs, branch prediction and interrupt latency. QEMU does not model the second kind, so I only claim results about the first.

With `-icount shift=2`, virtual time advances by 4 ns per instruction, and a latency measured in the guest becomes a path length in instructions. The measurements are reproducible: two runs of the same benchmark give the same min, median and p99 to the instruction, and only the maximum moves by a few tens of instructions. Every benchmark first prints a calibration line, because the counters do not mean what their names suggest under emulation:

- A loop of 200,000 instructions gives a `rdinstret` delta of 200,004 and a `rdcycle` delta of 800,020. `rdcycle` counts virtual nanoseconds, so all latencies use `rdinstret`.
- The counter is global to the machine. With two harts the same loop reads 370,419, because the other hart's instructions are counted too. Path lengths are therefore measured with a single hart.
- The kernel must be built in release mode. In debug the kernel path is 20 to 40 times longer, depending on the interval.

For each latency I report min, median, p99 and max, plus the number of samples above ten times the median. That last figure tells a rare event apart from a long tail, and it turned out to matter (section 8).

## 2. The reference: an echo through the kernel

The reference program is a plain `recvfrom` / `sendto` loop on a UDP socket. Per packet, the kernel does this:

```
echo calls recvfrom and blocks                         -> trap 1 (ecall)
device raises an IRQ                                   -> trap 2
  network service thread wakes, runs the IP stack,
  fills the socket buffer, wakes the reader            -> context switch 1
reader is scheduled, its recvfrom copies the
  payload out and returns                              -> context switch 2
echo calls sendto                                      -> trap 3 (ecall)
  payload copied in, IP stack, descriptor published,
  device notified
```

Two latencies are recorded: pickup, from the device IRQ to the return of `recvfrom`, and service, the duration of `sendto`.

The client sends 10,000 datagrams plus a final stop datagram. The first 32 are warm-up and are excluded, which leaves 9,969 measured packets in every table of this article.

| Kernel path, 9,969 packets, instructions | min | p50 | p99 | max |
| --- | --- | --- | --- | --- |
| Pickup (IRQ to `recvfrom` return) | 2,434 | 4,701 | 6,539 | 7,771 |
| Service (`sendto`) | 3,543 | 3,816 | 7,758 | 7,795 |

Per packet the system takes 2.000 ecalls, 1.000 external interrupt and 2.08 context switches. On an idle system the kernel path is not very jittery: a factor of three between best and worst. That is the fair baseline. The bypass will not win an order of magnitude of jitter at rest; it wins on path length, and under disturbance.

## 3. One syscall, then the kernel steps aside

The whole kernel interface of the bypass is one call:

```rust
/// What the kernel hands over: after this call, no syscall is needed
/// to send or receive.
#[repr(C)]
pub struct BypassInfo {
    /// virtio-mmio registers of the device (4 KiB, R|W).
    pub mmio: *mut u8,
    /// DMA region: rings and buffers (R|W, zeroed).
    pub dma: *mut u8,
    pub dma_len: usize,
    /// PHYSICAL address of the start of `dma`. The device only knows
    /// physical addresses: `phys = dma_phys + (va - dma)`.
    pub dma_phys: u64,
}

pub fn bypass_open(slot: usize, dma_pages: usize) -> Result<BypassInfo, isize>;
```

On the kernel side, the call does the following, in this order:

1. Checks a right granted at launch. Without an IOMMU, a process that programs a DMA-capable device can make it write anywhere in RAM, so this right is equivalent to kernel privilege.
2. Finds a modern virtio-net device the kernel does not use, and resets it.
3. Masks the device's interrupt at the interrupt controller.
4. Allocates physically contiguous, zeroed pages that the kernel will never move or reclaim.
5. Maps the register page and the DMA region into the process, readable and writable from user mode, not executable.
6. Returns the virtual addresses and the physical base of the DMA region.

The part that is easy to get wrong is teardown. When the process dies, the device must be reset before its pages are returned to the allocator, otherwise it keeps writing by DMA into memory that now belongs to someone else. And the two mappings must be removed before the page table is freed, otherwise the DMA pages would be freed twice and the register page would be released as if it were RAM. A kernel test runs a program that opens the device and exits, twice in a row, and checks that the free page count returns exactly to its initial value; the second run also proves the first one gave the device back. I validated the test by mutation: removing the unmapping of the DMA region makes it fail on a double free. The register-page case follows from the same code path but has no mutation of its own.

## 4. The user-space driver

The driver (`samples/bypass/virtio.rs`) targets the modern MMIO transport with split virtqueues, one RX queue and one TX queue, and negotiates nothing beyond `VIRTIO_F_VERSION_1` and the MAC address. One frame is one buffer is one descriptor, preceded by the 12-byte virtio-net header. After initialisation the file contains nothing but memory reads and writes.

### Physical addresses, in one place

In the process, virtual and physical addresses differ, and the device only understands physical ones. A virtual address written into a descriptor raises no fault: the device simply writes at that physical address. A single function translates, and it is the only place where an address bound for the device is produced:

```rust
fn phys(&self, va: usize) -> u64 {
    assert!(va >= self.dma && va < self.dma + self.dma_len, "address outside the DMA region");
    self.dma_phys + (va - self.dma) as u64
}
```

It is only called during initialisation. Descriptor addresses are fixed once, so the hot path never translates.

### Memory ordering

The rings are shared with a device that reads and writes them whenever it wants. They are never seen through a Rust reference: an ordinary read of `used.idx` in the polling loop could legally be hoisted out of the loop. Everything goes through volatile accesses on raw pointers, or an `AtomicU16` for the two indices.

RISC-V has a weak memory model (RVWMO), so the publication order is a contract, not a habit. The descriptor is written first, then the ring entry, then the index with `Release`:

```rust
/// Offers descriptor `id` to the device. DOES NOT NOTIFY (see `kick`).
fn publish(&mut self, id: u16) {
    let slot = self.avail_idx as usize & (QSIZE - 1);
    // SAFETY: `slot < QSIZE`; avail area, 2-byte aligned.
    unsafe { write_volatile((self.avail + 4 + 2 * slot) as *mut u16, id) };
    self.avail_idx = self.avail_idx.wrapping_add(1);
    // SAFETY: `avail.idx`, aligned u16, viewed as atomic.
    let idx = unsafe { &*((self.avail + 2) as *const AtomicU16) };
    idx.store(self.avail_idx, Ordering::Release);
}
```

Polling is the mirror image: one load of `used.idx`. An idle iteration of the echo does it twice, once on the RX queue for new frames and once on the TX queue to reclaim sent buffers, and costs 22 instructions in total.

```rust
fn pop_used(&mut self) -> Option<(u32, u32)> {
    // SAFETY: `used.idx`, aligned u16, written by the device.
    let idx = unsafe { &*((self.used + 2) as *const AtomicU16) };
    if idx.load(Ordering::Acquire) == self.last_used {
        return None;
    }
    let slot = self.last_used as usize & (QSIZE - 1);
    let elem = self.used + 4 + 8 * slot;
    // SAFETY: `slot < QSIZE`; element { id u32, len u32 }, 4-byte aligned,
    // published by the device before the index read above.
    let (id, len) =
        unsafe { (read_volatile(elem as *const u32), read_volatile((elem + 4) as *const u32)) };
    self.last_used = self.last_used.wrapping_add(1);
    Some((id, len))
}
```

Notification needs a full barrier. The driver writes `avail.idx` then reads the device's "no notify" flag; the device does the opposite. Without a barrier between the write and the read, each side can read the other's old value and the notification is lost:

```rust
fn wants_notify(&self) -> bool {
    fence(Ordering::SeqCst);
    // SAFETY: first word of the used area, written by the device.
    unsafe { read_volatile(self.used as *const u16) & USED_F_NO_NOTIFY == 0 }
}
```

I never saw a notification lost under QEMU, but I never ran without the barriers either, and emulation would be a poor test of a weak memory model anyway. The barriers are there because the protocol requires them, not because a run failed without them.

### Tokens that own their buffer

A received frame and a frame being written must be alive at the same time, so neither can borrow the driver. Each is a token that owns one buffer:

```rust
#[must_use = "an RX buffer that is not returned is lost to the device"]
pub struct RxToken { id: u16, ptr: *const u8, len: usize }

#[must_use = "a TX buffer neither submitted nor released is lost"]
pub struct TxToken { id: u16, ptr: *mut u8 }
```

The tokens are neither `Copy` nor `Clone`, and `recycle` and `submit` take them by value. Returning the same buffer twice does not compile. Forgetting to return one still does: `#[must_use]` only warns when a token is dropped on the spot, so a leaked buffer remains possible.

## 5. The hot loop

One iteration drains the RX ring, replies, hands the buffers back and notifies once per batch. This is the loop of `samples/bypassecho.rs`, simplified: the instrumentation is removed, and so is the cap of one ring's worth of frames per iteration.

```rust
loop {
    let mut tx_pending = false;
    let mut rx_recycled = false;

    // Drain the RX ring BEFORE notifying anything.
    while let Some(rx) = net.poll_rx() {
        if let Some(mut tx) = net.alloc_tx() {
            match build_reply(rx.frame(), tx.buf(), &me) {
                Some(reply) => { net.submit(tx, reply.len()); tx_pending = true; }
                None => net.release_tx(tx), // frame that calls for no reply
            }
        }
        // Returned in every case, even when no TX buffer was free:
        // better to lose a reply than to starve reception.
        net.recycle(rx);
        rx_recycled = true;
    }

    if tx_pending { net.kick_tx(); } // one notification for the whole batch
    if rx_recycled { net.kick_rx(); }
    net.reclaim_tx();
    core::hint::spin_loop();
}
```

No syscall, no interrupt, and no allocation. The last point holds by construction: the program has no global allocator, so any allocation would be a link error.

`build_reply` (`samples/bypass/wire.rs`) is a minimal Ethernet, ARP, IPv4 and UDP stack working on byte views. It answers ARP requests for its address, without which the peer never learns the MAC and no datagram arrives. For UDP it copies the frame once, from the device's RX buffer to its TX buffer, then swaps source and destination at each layer:

```rust
tx[0..6].copy_from_slice(&rx[6..12]); // destination MAC = the sender
tx[6..12].copy_from_slice(&me.mac);
tx[IP + 12..IP + 16].copy_from_slice(&rx[IP + 16..IP + 20]); // source IP = the old destination
tx[IP + 16..IP + 20].copy_from_slice(&rx[IP + 12..IP + 16]);
tx[udp..udp + 2].copy_from_slice(&rx[udp + 2..udp + 4]); // ports
tx[udp + 2..udp + 4].copy_from_slice(&rx[udp..udp + 2]);
```

The IPv4 and UDP checksums stay valid as they are. Both are one's-complement sums of 16-bit words, which are commutative, and swapping source and destination does not change the set of words summed.

## 6. First comparison

Same client, same 10,000 datagrams, no loss on either side. These runs predate the scheduler changes of section 7.

| Per packet | Kernel | Bypass |
| --- | --- | --- |
| `ecall` | 2.000 | 0 |
| External interrupts | 1.000 | 0 |
| Timer interrupts | 0.019 | 0.018 |
| Context switches | 2.08 | 0.018 |
| Payload copies (counted by reading the code) | 2, plus the IP stack | 1 |

| Latency, instructions | min | p50 | p99 | max |
| --- | --- | --- | --- | --- |
| Kernel, pickup | 2,434 | 4,701 | 6,539 | 7,771 |
| Kernel, service | 3,543 | 3,816 | 7,758 | 7,795 |
| Bypass, service (frame seen to notification written) | 529 | 529 | 529 | 2,899 |

The bypass handles a frame in 529 instructions, against 8,517 for the kernel path (the sum of its two medians, 4,701 and 3,816): about 16 times fewer. With 1,400-byte datagrams the ratio is the same. The service time is constant up to the 99th percentile.

Two caveats belong next to that ratio. The kernel's IP stack verifies the IPv4 and UDP checksums on receive and computes them on send, while my echo reuses them, so part of the gap is less work, not a shorter path. I have not measured how large that part is. And every notification is a VM exit whose cost does not appear in guest instructions.

### What service latency hides

The bypass has no observable instant at which the device wrote a frame, so there is no direct equivalent of the kernel's pickup latency. I measure a bound instead: the gap between two consecutive idle polls. A frame written just after a poll waits at most that long. At rest the gap is one loop iteration, 22 instructions. If the thread is interrupted or preempted, it is the whole duration of the interruption.

That metric shows the bypass still takes a trap: 0.018 timer interrupt per packet. Out of 763,076 idle polls, 106 gaps exceed ten times the idle iteration, 3,324 instructions at worst. This is the scheduler's 1 ms round-robin quantum, which fires even when the thread is alone on its hart.

It gets worse under preemption. A deadline-class thread running 3 ms jobs opens a gap of about 750,000 instructions on both paths: 755,952 for the kernel, 753,526 for the bypass. Service latency does not show it at all, because it starts when the frame is seen. Kernel bypass removes the traps of the path. It does not remove the ones the scheduler imposes on the thread.

## 7. Removing the remaining jitter, one source at a time

Each step removes one source and the measurement is repeated. There are three changes, applied cumulatively:

1. **Quantum on demand**: no round-robin time slice when no thread of equal priority is ready.
2. **High priority**: the echo runs above the kernel's network thread.
3. **Reserved hart**: the echo is pinned to a hart that runs nothing else.

"Traps" is what the thread's hart took during the 10,000-packet window, in absolute numbers.

| Configuration | Scenario | Traps (timer / context switch) | Service spread | Largest gap |
| --- | --- | --- | --- | --- |
| Baseline (round-robin, default priority) | idle | about 180 / 180 (the thread's own count) | 2,370 | 3,324 |
| Quantum on demand | idle | 2 / 2 | 4,528 | 68 |
| Quantum on demand + high priority | idle | 0 / 0 | 20 | 68 |
| Quantum on demand | competing thread | 764 / 382 | 255,362 | 255,429 |
| Quantum on demand + high priority | competing thread | 0 / 0 | 20 | 68 |
| Quantum on demand + high priority | deadline thread | 1 / 2 | 20 | 754,059 |
| Reserved hart (2 harts) | idle, competing thread, deadline thread | 0 / 0 | not measurable | not measurable |

Every row has zero ecalls, zero external interrupts, zero inter-processor interrupts and zero faults.

**Quantum on demand.** A round-robin thread with nobody to yield to no longer gets a timer tick. The counterpart is what makes it correct: when a thread of equal priority becomes ready, the hart running its peer must be told to re-arm its quantum, otherwise the newcomer starves. Two kernel tests cover this, both validated by mutation. Forcing the quantum always on fails the first, forcing it always off fails the second.

**High priority.** Two timer traps remained, each with a context switch. They are most likely wake-ups of the kernel's network thread preempting the echo: I did not trace them, but they disappear once the echo runs above that thread's priority. The hart then takes no trap at all over 10,000 packets, and the service time stays within 20 instructions. The price, on a single hart, is that the echo starves everything below it, including the kernel's own network stack, for as long as it runs.

**Reserved hart.** Priority does not protect against a deadline-class thread, which always wins over round-robin. Pinning does: the pinned thread leaves the global ready queue, its hart runs nothing else, receives no inter-processor interrupt for other threads' wake-ups, and disarms its timer. It is the only step with zero traps in all three scenarios.

The kernel path pays for these scheduler changes: its median pickup grows by about 570 instructions (4,701 to 5,275), in exchange for three times fewer timer interrupts per packet.

This is the Linux recipe in miniature. `nohz_full` plays the role of quantum on demand, a `SCHED_FIFO` priority that of the high priority, and `isolcpus` with IRQ affinity that of the reserved hart: together they keep the tick, other threads and their wake-ups away from the core that runs the hot loop.

### What QEMU cannot tell me

The latency columns are empty for the reserved hart on purpose. With two harts under `-icount`, QEMU runs the harts in turn inside one host thread and `rdinstret` is global, so a "gap" measures the time slice QEMU gives the other hart, not an interruption of my thread. Without `-icount` the harts are truly parallel but the counters follow the host clock. Under emulation, hart isolation is proven by trap counts. Its latency needs hardware.

## 8. Things that bit me

**A 755,000-instruction outlier.** Early runs showed a maximum 158 times the median, landing in a different measurement from one run to the next. The cause was a demonstration thread started at boot: deadline class, 3 ms jobs, which at 4 ns per instruction is exactly 750,000 instructions. It affected 4 packets out of 2,000. A lone maximum says nothing without the number of outliers, which is why the report prints it. That accident became my preemption scenario.

**An interrupt that was never enabled.** With one hart, the counters showed zero external interrupts and yet every echo came back. Reception was being carried by a periodic wake-up of the network thread, which `-icount sleep=off` makes instantaneous. The interrupt controller's enable register was being computed with a per-hart formula fed a context number, so the source was enabled for the next hart. The trap counters built for this project are what exposed it.

**Counters that count something else.** Without the calibration line, I would have reported `rdcycle` values as cycles.

## 9. Limitations and next steps

- The figures are instructions, not nanoseconds. Micro-architectural jitter and real interrupt latency need a board, and a user-space driver for that board's network controller. `bypass_open` and the method carry over.
- I did not measure Linux's own bypass paths (DPDK, AF\_XDP). The Linux section is background; the numbers in this article come from my RTOS only.
- The pickup comparison is asymmetric: a measured distribution on the kernel side, a measured bound on the bypass side.
- The benchmark is a ping-pong with one datagram in flight. Batches of several frames, an exhausted RX queue and a full TX queue are not exercised yet. A burst client is the next test.
- The checksum work differs between the two paths. A run with checksums disabled in the kernel's stack would isolate the cost of the path itself.
- Without an IOMMU the bypass process is trusted. The driver validates what the device returns on the RX path, and does not yet do the same on the TX completion path.
- The reserved hart is not covered by the automated test suite, which runs on a single hart by design. It is covered by the benchmarks and by a manual sequence: pin, run the kernel echo, pin the same hart again, pin another one.
- Two disturbance scenarios I planned are not measured: a second process talking on another socket, and a flood of UART input.
- At high priority on a single hart, the echo starves the kernel's network stack while it runs. That is the cost of priority without a dedicated hart.
- Polling occupies a hart at 100%. A hybrid mode that re-enables the interrupt when idle would reintroduce a trap, and with it some jitter.
- One queue, no TCP, no offloads.

## Reproduce

The kernel is closed, so you cannot rerun these numbers as they are: the user programs need the `bypass_open` call and the trap counters of my kernel. What you can do is read the driver, port it to a kernel that offers the same three things (a mapped register page, a DMA region with its physical address, a masked interrupt), and reuse the measurement method below.

**Versions.** QEMU 10.1.91 (v10.2.0-rc1), rustc 1.96.0-nightly (2026-03-28), target `riscv64gc-unknown-none-elf`, host Windows 11. The kernel is built in release mode; the user programs with `-O` and `panic=abort`.

**QEMU.** One hart, deterministic virtual time, two virtio-net devices on the modern MMIO transport, each on its own user-mode network with a forwarded UDP port:

```
qemu-system-riscv64 -machine virt,aclint=on -m 128M -smp 1 -nographic \
  -bios <firmware> -kernel <kernel> -initrd <ramdisk> \
  -global virtio-mmio.force-legacy=false \
  -netdev user,id=net0,hostfwd=udp:127.0.0.1:5555-:5555 \
  -device virtio-net-device,netdev=net0,bus=virtio-mmio-bus.0 \
  -netdev user,id=net1,hostfwd=udp:127.0.0.1:5556-:5555 \
  -device virtio-net-device,netdev=net1,bus=virtio-mmio-bus.1 \
  -icount shift=2,sleep=off
```

The kernel takes the first device (host port 5555) and the bypass process the second (host port 5556). Without `force-legacy=false` the devices come up in legacy mode and the driver refuses them. The reserved-hart runs use `-smp 2`.

**Client.** `tools/udp_client.py` on the host sends numbered 64-byte datagrams to `127.0.0.1`, waits for each echo before sending the next, checks the content, then sends a stop datagram that makes the echo print its report and exit. The same client drives both paths; only the port changes:

```
python tools/udp_client.py 5555 -n 10000   # kernel path
python tools/udp_client.py 5556 -n 10000   # bypass path
```

`tools/bench.py` wraps the whole sequence: it starts QEMU, waits for the boot-time demonstration threads to finish (section 8), launches the echo from the RTOS shell, runs the client and prints the report.

**Counters.** Latencies are `rdinstret` deltas read in user mode, which requires the kernel to open the counters to user mode (`scounteren`). Trap counts come from per-thread and per-hart counters incremented at every trap entry and at every dispatch, read through a syscall before and after the measurement window; the reads themselves are subtracted. On the kernel path, the IRQ handler stamps `rdinstret` and the echo reads that stamp after `recvfrom` returns, which is exact because only one datagram is in flight.

## Code

| File | Role |
| --- | --- |
| `samples/bypass/virtio.rs` | User-space virtio-net driver |
| `samples/bypass/wire.rs` | Minimal Ethernet, ARP, IPv4 and UDP |
| `samples/bypassecho.rs` | The polling echo, instrumented |
| `samples/userecho.rs` | The reference echo through sockets |
| `samples/bypassarp.rs` | Driver proof: one frame sent, one received |
| `samples/userbypass.rs` | `bypass_open` proof: device registers read from user mode without a trap |
| `samples/benchutil.rs` | Report shared by both echoes |
| `samples/usys.rs` | Syscall wrappers, including `bypass_open` and `BypassInfo`, which the driver depends on |
| `tools/udp_client.py` | Host ping-pong client |
| `tools/bench.py` | Runs QEMU, the echo and the client, prints the report |
| `tools/pcap_dump.py` | Decodes a capture (Ethernet, ARP, UDP) without Wireshark |

The comments in these files are in French. The excerpts in this article are the same code, with comments translated and sometimes reworded.

## License

Copyright (c) 2026 Yassine @reggiedev21. All rights reserved. The code and the article are published for reading and study only; no license to copy, modify or reuse them is granted. See [LICENSE](LICENSE).

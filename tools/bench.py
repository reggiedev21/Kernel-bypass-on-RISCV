#!/usr/bin/env python3
"""Banc de mesure d'un écho UDP sous QEMU.

Démarre QEMU avec deux cartes virtio-net (slot 0 : noyau, port hôte 5555 ;
slot 1 : bypass, port hôte 5556), lance PROGRAMME depuis le shell de Rustos
(`runraw`), fait tourner le client ping-pong, puis affiche les lignes "ECHO"
du rapport imprimé par le programme.

    python tools/bench.py                                # écho de référence
    python tools/bench.py --bypass -p 5556 bypassecho    # écho en kernel bypass
    python tools/bench.py --bypass --no-client bypassarp # programme autonome
    python tools/bench.py -n 10000 --smp 1
    python tools/bench.py --no-icount           # temps hôte (compteurs non fiables)

PROGRAMME est un nom de /bin (« bypassecho ») ou un chemin absolu de l'invité.
Préférer le nom : sous Git Bash, un argument commençant par « / » est réécrit
en chemin Windows avant d'arriver ici.

Sous -icount (défaut), `rdinstret` compte des instructions : les latences
affichées sont des longueurs de chemin, reproductibles.
"""

import argparse
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import udp_client  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KERNEL = "target/riscv64gc-unknown-none-elf/debug/xv6-rust"
RAMDISK = "target/ramdisk.img"
BIOS = os.environ.get(
    "RUSTOS_BIOS", "osboot/target/riscv64imac-unknown-none-elf/release/osboot"
)


def qemu_cmd(smp, icount, pcap, kernel):
    cmd = [
        "qemu-system-riscv64", "-machine", "virt,aclint=on", "-bios", BIOS,
        "-kernel", kernel, "-initrd", RAMDISK, "-m", "128M", "-smp", str(smp),
        "-nographic",
        "-global", "virtio-mmio.force-legacy=false",
        "-netdev", "user,id=net0,hostfwd=udp:127.0.0.1:5555-:5555",
        "-device", "virtio-net-device,netdev=net0,bus=virtio-mmio-bus.0",
        "-netdev", "user,id=net1,hostfwd=udp:127.0.0.1:5556-:5555",
        "-device", "virtio-net-device,netdev=net1,bus=virtio-mmio-bus.1",
    ]
    if pcap:
        cmd += [
            "-object", "filter-dump,id=d0,netdev=net0,file=target/ref.pcap",
            "-object", "filter-dump,id=d1,netdev=net1,file=target/bypass.pcap",
        ]
    if icount:
        cmd += ["-icount", "shift=2,sleep=off"]
    return cmd


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("program", nargs="?", default="userecho",
                   help="nom dans /bin de l'invité, ou chemin absolu")
    p.add_argument("-p", "--port", type=int, default=5555)
    p.add_argument("-n", "--count", type=int, default=2000)
    p.add_argument("-s", "--size", type=int, default=64)
    p.add_argument("--smp", type=int, default=1)
    p.add_argument("--no-icount", action="store_true")
    p.add_argument("--release", action="store_true", help="noyau de `cargo build --release`")
    p.add_argument("--pcap", action="store_true", help="capture target/{ref,bypass}.pcap")
    p.add_argument("--ready", default="ECHO pret", help="marqueur série : programme prêt")
    p.add_argument("--bypass", action="store_true",
                   help="lance le programme avec le droit kernel bypass (runraw --bypass)")
    p.add_argument("-a", "--args", default="",
                   help='arguments du programme, ex. "prio=30 pin=1"')
    p.add_argument("--no-client", action="store_true",
                   help="programme autonome : pas de client UDP, on attend sa sortie")
    p.add_argument("--no-settle", action="store_true",
                   help="ne pas attendre la fin des threads de démonstration du boot")
    p.add_argument("-v", "--verbose", action="store_true", help="toute la sortie série")
    a = p.parse_args()

    os.chdir(ROOT)
    proc = subprocess.Popen(
        qemu_cmd(a.smp, not a.no_icount, a.pcap,
                 KERNEL.replace("/debug/", "/release/") if a.release else KERNEL),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )

    lines, ready, done = [], threading.Event(), threading.Event()
    # Threads de démonstration lancés au boot : l'un d'eux, de classe
    # deadline, préempte tout le reste. On attend qu'ils aient fini pour
    # qu'ils ne tombent pas dans la fenêtre de mesure.
    settle_marks = ["[RT] done", "[S] done"]
    settled = threading.Event()
    pending = set(settle_marks)
    # Bannière du shell de l'invité : rien de ce qu'on écrit avant n'est lu.
    shell_up = threading.Event()

    def reader():
        for line in proc.stdout:
            lines.append(line.rstrip("\r\n"))
            if a.ready in line:
                ready.set()
            for m in settle_marks:
                if m in line:
                    pending.discard(m)
            if not pending:
                settled.set()
            if "=== shell" in line:
                shell_up.set()
            if "[shell] exit code" in line:
                done.set()
        done.set()
        ready.set()
        settled.set()
        shell_up.set()

    threading.Thread(target=reader, daemon=True).start()

    ok = False
    try:
        # La commande commence par une ligne vide : le premier octet peut
        # être avalé pendant l'init de l'UART.
        if not shell_up.wait(60):
            print("[bench] le shell de Rustos n'est jamais apparu", file=sys.stderr)
        if not a.no_settle and not settled.wait(60):
            print("[bench] les threads de démonstration n'ont pas terminé", file=sys.stderr)
        flags = "--bypass " if a.bypass else ""
        program = a.program if a.program.startswith("/") else "/bin/" + a.program
        command = "\nrunraw " + flags + program + (" " + a.args if a.args else "") + "\n"
        # Par petits paquets espacés : l'UART émulé n'a que 16 octets de FIFO
        # de réception, une ligne longue envoyée d'un bloc est tronquée.
        for i in range(0, len(command), 8):
            proc.stdin.write(command[i:i + 8])
            proc.stdin.flush()
            time.sleep(0.05)
        if a.no_client:
            ok = done.wait(120) and any("exit code = 0" in l for l in lines)
        elif not ready.wait(60) or proc.poll() is not None:
            print("[bench] le programme n'a jamais signalé qu'il était prêt", file=sys.stderr)
        else:
            t0 = time.perf_counter()
            ok = udp_client.run(a.port, a.count, a.size, timeout=2.0, retries=20)
            print(f"[bench] durée hôte du lot : {time.perf_counter() - t0:.1f} s")
            done.wait(120)
    finally:
        proc.kill()
        proc.wait()

    shown = lines if a.verbose or not ok else [l for l in lines if "ECHO" in l or "BYPASS" in l]
    for l in shown:
        print(l)
    if not ok and not a.verbose:
        print("[bench] ÉCHEC — relancer avec -v pour la sortie série complète", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

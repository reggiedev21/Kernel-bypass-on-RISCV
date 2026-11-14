#!/usr/bin/env python3
"""Client de test UDP en ping-pong.

Envoie COUNT datagrammes numérotés vers 127.0.0.1:PORT, attend chaque écho
avant d'envoyer le suivant (un seul paquet en vol), vérifie le contenu, puis
envoie un datagramme "STOP" qui fait imprimer son rapport à l'écho.

Le même client sert au chemin noyau (port 5555) et au chemin bypass (5556).

Le RTT affiché est mesuré avec l'horloge de l'HÔTE : il contient le bruit de
QEMU et de l'ordonnanceur de l'hôte. C'est un contrôle de bon fonctionnement,
pas une mesure de gigue — celle-ci est faite dans l'invité.
"""

import argparse
import socket
import struct
import sys
import time


def exchange(sock, addr, payload, timeout, retries):
    """Envoie `payload`, rend (rtt_s, tentatives) ou None après `retries` échecs."""
    for attempt in range(1, retries + 1):
        t0 = time.perf_counter()
        sock.sendto(payload, addr)
        deadline = t0 + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(2048)
            except (socket.timeout, ConnectionResetError):
                # ConnectionResetError : sous Windows, tant que l'invité
                # n'écoute pas encore.
                break
            if data == payload:
                return time.perf_counter() - t0, attempt
            # Écho en retard d'une tentative précédente : on l'ignore.
    return None


def run(port, count, size, timeout, retries, quiet=False):
    """Rend True si tous les échos sont revenus identiques."""
    addr = ("127.0.0.1", port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pad = bytes((i * 7 + 3) & 0xFF for i in range(max(0, size - 8)))
    rtts, lost, retried = [], 0, 0

    for seq in range(count):
        payload = b"PING" + struct.pack("!I", seq) + pad
        result = exchange(sock, addr, payload, timeout, retries)
        if result is None:
            lost += 1
            continue
        rtt, attempts = result
        rtts.append(rtt)
        retried += attempts - 1

    stop = exchange(sock, addr, b"STOP" + struct.pack("!I", count), timeout, retries)

    if not quiet:
        print(f"[client] port={port} envoyés={count} reçus={len(rtts)} "
              f"perdus={lost} retransmissions={retried} stop={'ok' if stop else 'PERDU'}")
        if rtts:
            rtts.sort()
            us = [r * 1e6 for r in rtts]
            print(f"[client] RTT hôte (µs, indicatif) : min={us[0]:.0f} "
                  f"p50={us[len(us) // 2]:.0f} p99={us[len(us) * 99 // 100]:.0f} max={us[-1]:.0f}")
    return lost == 0 and stop is not None


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("port", type=int, nargs="?", default=5555)
    p.add_argument("-n", "--count", type=int, default=1000)
    p.add_argument("-s", "--size", type=int, default=64, help="taille du datagramme (octets)")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-r", "--retries", type=int, default=20)
    a = p.parse_args()
    return 0 if run(a.port, a.count, a.size, a.timeout, a.retries) else 1


if __name__ == "__main__":
    sys.exit(main())

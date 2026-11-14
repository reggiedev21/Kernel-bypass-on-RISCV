#!/usr/bin/env python3
"""Liste les trames d'une capture pcap.

    python tools/pcap_dump.py target/bypass.pcap

Sans dépendance : lit le format pcap classique écrit par `-object filter-dump`
de QEMU, et décode Ethernet, ARP et IPv4/UDP — juste assez pour vérifier sans
Wireshark qu'une trame émise par le pilote en espace utilisateur est bien
sortie, et bien formée.
"""

import struct
import sys


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def ip(b):
    return ".".join(str(x) for x in b)


def describe(f):
    if len(f) < 14:
        return "trame tronquée"
    dst, src, etype = f[0:6], f[6:12], struct.unpack("!H", f[12:14])[0]
    head = f"{mac(src)} > {mac(dst)}"
    if etype == 0x0806 and len(f) >= 42:
        op = struct.unpack("!H", f[20:22])[0]
        if op == 1:
            return f"{head} ARP requête : qui a {ip(f[38:42])} ? dites-le à {ip(f[28:32])}"
        if op == 2:
            return f"{head} ARP réponse : {ip(f[28:32])} est à {mac(f[22:28])}"
        return f"{head} ARP op={op}"
    if etype == 0x0800 and len(f) >= 34:
        ihl = (f[14] & 0x0F) * 4
        proto = f[23]
        s, d = ip(f[26:30]), ip(f[30:34])
        if proto == 17 and len(f) >= 14 + ihl + 8:
            sp, dp, ulen = struct.unpack("!HHH", f[14 + ihl:14 + ihl + 6])
            return f"{head} UDP {s}:{sp} > {d}:{dp} ({ulen - 8} octets)"
        return f"{head} IPv4 {s} > {d} proto={proto}"
    return f"{head} ethertype={etype:#06x}"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    data = open(sys.argv[1], "rb").read()
    if len(data) < 24:
        print("capture vide")
        return 1
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4:
        end = "<"
    elif magic == 0xD4C3B2A1:
        end = ">"
    else:
        print(f"format inconnu (magic {magic:#x})")
        return 1
    off, n = 24, 0
    while off + 16 <= len(data):
        _, _, incl, orig = struct.unpack(end + "IIII", data[off:off + 16])
        frame = data[off + 16:off + 16 + incl]
        off += 16 + incl
        n += 1
        print(f"{n:4d}  {orig:5d} o  {describe(frame)}")
    print(f"{n} trame(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

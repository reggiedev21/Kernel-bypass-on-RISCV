// Mini-pile Ethernet / ARP / IPv4 / UDP : de quoi répondre à l'ARP et faire
// un écho UDP.
//
// La trame reçue est lue en place dans le tampon RX du device, la réponse
// écrite directement dans un tampon TX. Pas d'allocation ; le payload est
// copié une seule fois, de RX vers TX.
//
// Ignorés : fragments, ICMP, tout autre protocole ou port. Les sommes de
// contrôle reçues ne sont pas vérifiées.

#![allow(dead_code)]

const ETH_HDR: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const IPPROTO_UDP: u8 = 17;
/// Trame Ethernet minimale, sans FCS.
const MIN_FRAME: usize = 60;

/// Notre identité sur le réseau.
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub port: u16,
}

/// Ce que `build_reply` a écrit dans le tampon d'émission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Réponse ARP de `len` octets.
    Arp { len: usize },
    /// Écho UDP de `len` octets ; payload à `tx[payload..payload + payload_len]`.
    Udp { len: usize, payload: usize, payload_len: usize },
}

impl Reply {
    pub fn len(&self) -> usize {
        match *self {
            Reply::Arp { len } | Reply::Udp { len, .. } => len,
        }
    }
}

/// Lit la trame `rx` et, si elle appelle une réponse, l'écrit dans `tx`.
/// `None` : trame à ignorer.
#[inline]
pub fn build_reply(rx: &[u8], tx: &mut [u8], me: &Endpoint) -> Option<Reply> {
    if rx.len() < ETH_HDR {
        return None;
    }
    if rx[12..14] == ETHERTYPE_IPV4 {
        udp_echo(rx, tx, me)
    } else if rx[12..14] == ETHERTYPE_ARP {
        arp_reply(rx, tx, me)
    } else {
        None
    }
}

/// Requête ARP visant notre IP → réponse. Sans elle, le pair ne trouve pas
/// notre MAC et aucun datagramme n'arrive.
///
/// Paquet ARP, après les 14 octets Ethernet (28 octets) :
///   0 htype(2)  2 ptype(2)  4 hlen  5 plen  6 oper(2)
///   8 sha(6)  14 spa(4)  18 tha(6)  24 tpa(4)
fn arp_reply(rx: &[u8], tx: &mut [u8], me: &Endpoint) -> Option<Reply> {
    const ARP: usize = ETH_HDR;
    if rx.len() < ARP + 28 {
        return None;
    }
    let a = &rx[ARP..ARP + 28];
    // Ethernet/IPv4, requête, pour notre adresse.
    if a[0..8] != [0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01] || a[24..28] != me.ip {
        return None;
    }
    let out = &mut tx[..MIN_FRAME];
    out.fill(0);
    out[0..6].copy_from_slice(&a[8..14]); // destination : le demandeur
    out[6..12].copy_from_slice(&me.mac);
    out[12..14].copy_from_slice(&ETHERTYPE_ARP);
    let o = &mut out[ARP..ARP + 28];
    o[0..8].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]); // réponse
    o[8..14].copy_from_slice(&me.mac);
    o[14..18].copy_from_slice(&me.ip);
    o[18..24].copy_from_slice(&a[8..14]);
    o[24..28].copy_from_slice(&a[14..18]);
    Some(Reply::Arp { len: MIN_FRAME })
}

/// Datagramme UDP pour notre IP et notre port → le même, renvoyé.
///
/// En-tête IPv4 : 0 version|IHL  2 longueur totale(2)  6 drapeaux|offset(2)
///   9 protocole  10 somme(2)  12 source(4)  16 destination(4)
/// En-tête UDP : 0 port source(2)  2 port destination(2)  4 longueur(2)  6 somme(2)
fn udp_echo(rx: &[u8], tx: &mut [u8], me: &Endpoint) -> Option<Reply> {
    const IP: usize = ETH_HDR;
    if rx.len() < IP + 20 {
        return None;
    }
    let vihl = rx[IP];
    let ihl = (vihl & 0x0f) as usize * 4;
    if vihl >> 4 != 4 || ihl < 20 {
        return None;
    }
    let total = u16::from_be_bytes([rx[IP + 2], rx[IP + 3]]) as usize;
    // Pas de fragment, de l'UDP, pour notre adresse.
    let frag = u16::from_be_bytes([rx[IP + 6], rx[IP + 7]]);
    if frag & 0x3fff != 0 || rx[IP + 9] != IPPROTO_UDP || rx[IP + 16..IP + 20] != me.ip {
        return None;
    }
    let udp = IP + ihl;
    if total < ihl + 8 || rx.len() < IP + total || IP + total > tx.len() {
        return None;
    }
    if u16::from_be_bytes([rx[udp + 2], rx[udp + 3]]) != me.port {
        return None;
    }
    let udp_len = u16::from_be_bytes([rx[udp + 4], rx[udp + 5]]) as usize;
    if udp_len < 8 || udp_len > total - ihl {
        return None;
    }

    // L'unique copie du payload : tampon RX → tampon TX.
    let len = IP + total;
    tx[..len].copy_from_slice(&rx[..len]);

    // Échange source/destination à chaque couche.
    tx[0..6].copy_from_slice(&rx[6..12]); // MAC destination = l'émetteur
    tx[6..12].copy_from_slice(&me.mac);
    tx[IP + 12..IP + 16].copy_from_slice(&rx[IP + 16..IP + 20]); // IP source = l'ancienne destination
    tx[IP + 16..IP + 20].copy_from_slice(&rx[IP + 12..IP + 16]);
    tx[udp..udp + 2].copy_from_slice(&rx[udp + 2..udp + 4]); // ports
    tx[udp + 2..udp + 4].copy_from_slice(&rx[udp..udp + 2]);
    // Les sommes IPv4 et UDP restent valides : ce sont des sommes de mots de
    // 16 bits, commutatives, et l'échange ne change pas les mots sommés.
    // Si le payload change, il faut les recalculer.

    let padded = if len < MIN_FRAME {
        tx[len..MIN_FRAME].fill(0);
        MIN_FRAME
    } else {
        len
    };
    Some(Reply::Udp { len: padded, payload: udp + 8, payload_len: udp_len - 8 })
}

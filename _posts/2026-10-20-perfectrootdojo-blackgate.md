---
title: "Blackgate — DNS Tunneling PCAP"
date: 2026-10-20 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, pcap, dns-tunneling, network]
pin: false
---

# Blackgate — Writeup

**Artifact:** `dns_tunnel.pcap` (393,182 bytes, 3,686 frames, ~99 s of traffic)
**Flag:** `r00t{dns_tunn3ls_c4rry_m0r3_th4n_qu3r13s}`

## TL;DR

The capture is 3,686 frames of deliberately boring, realistic-looking
enterprise traffic: DNS lookups for Google, Microsoft, Slack, Zoom, GitHub,
AWS, etc. from 41 internal hosts, plus ARP noise. Buried in it is a single
host, `10.20.7.44`, that appears in exactly **6 packets, total** — three DNS
queries and their three responses, to the internal resolver, for a domain
that doesn't fit the pattern of any other host:
`relay.blackgate-watch.net`. The query labels are hex, numbered in sequence,
and concatenate to the flag.

## Method

No `tshark`/`dpkt`/`scapy` available in the sandbox, so the pcap was parsed
by hand with Python's `struct` module (global pcap header → per-frame
header → Ethernet → IPv4 → UDP/TCP), then DNS messages were parsed from the
UDP payloads on port 53 (header, question section with name decompression,
and answer records).

## 1. Triage

```
packets: 3686
link type: 1 (Ethernet)
duration: 2026-09-21 08:12:51 -> 08:14:30 (~99 s)
```

Breaking down by protocol:

- 240 ARP frames (`ethertype 0x0806`) — ordinary LAN broadcast noise.
- The rest is IPv4: a long tail of TCP/443 (TLS) flows between 41 distinct
  `10.20.0.0/24` hosts and real-looking public IPs (AWS `52.x.x.x` ranges,
  etc.), and 1,306 UDP/53 packets, almost all between internal hosts and
  `10.20.0.53` (the internal DNS resolver — 653 of the 1,306 DNS packets
  touch it directly, the rest are other hosts' ordinary lookups).

Every one of the 1,306 DNS messages is a plain `A` record query
(`qtype=1`) — no TXT/NULL/CNAME records anywhere, which rules out the
"obviously weird record type" tell and means the tunnel has to be hiding in
the query *names* themselves.

## 2. Separating signal from the noise

Tallying the last two labels (the "domain suffix") of every query name:

```
google.com        240
googleapis.com     200
microsoft.com      172
github.com         116
jsdelivr.net       106
slack.com          104
amazonaws.com      100
office365.com       96
windows.com         84
zoom.us             82
```

All plausible, all high-volume, all noise. Sorting instead by **query name
length** immediately isolates the odd one out:

```
62  000.723030747b646e735f74756e6e336c73.relay.blackgate-watch.net
62  000.723030747b646e735f74756e6e336c73.relay.blackgate-watch.net
62  001.5f63347272795f6d3072335f7468346e.relay.blackgate-watch.net
62  001.5f63347272795f6d3072335f7468346e.relay.blackgate-watch.net
48  002.5f717533723133737d.relay.blackgate-watch.net
48  002.5f717533723133737d.relay.blackgate-watch.net
```
(next longest query, at 21 characters, is `outlook.office365.com` — a huge
gap below these.)

`blackgate-watch.net` isn't one of the normal corporate SaaS suffixes seen
anywhere else in the capture, the first label is a 3-digit zero-padded
counter (`000`, `001`, `002`), and the second label is all lowercase hex.
That's the DNS-tunneling signature: data smuggled one query at a time as a
subdomain, with a sequence number so the receiving side can reassemble
chunks that may arrive out of order.

## 3. Confirming the source

Pulling every packet that mentions `10.20.7.44` (the source of these
queries) shows it is responsible for **only these 6 packets in the entire
capture** — nothing else, no TLS, no other DNS:

```
2841  10.20.7.44:60386 -> 10.20.0.53:53   query   000.723030747b646e735f74756e6e336c73.relay.blackgate-watch.net
2842  10.20.0.53:53 -> 10.20.7.44:60386   NXDOMAIN (rcode=3)
2843  10.20.7.44:32243 -> 10.20.0.53:53   query   001.5f63347272795f6d3072335f7468346e.relay.blackgate-watch.net
2844  10.20.0.53:53 -> 10.20.7.44:32243   NXDOMAIN (rcode=3)
2845  10.20.7.44:43458 -> 10.20.0.53:53   query   002.5f717533723133737d.relay.blackgate-watch.net
2846  10.20.0.53:53 -> 10.20.7.44:43458   NXDOMAIN (rcode=3)
```

Every other internal host in the capture sends 30–100+ packets of ordinary
update/collaboration-app traffic over the ~99 s window; `10.20.7.44` sends
three queries about 1.1–1.3 seconds apart and nothing else. The resolver
answers NXDOMAIN each time (it has no route to resolve
`blackgate-watch.net` upstream in this capture), but that's irrelevant to
the exfil — the data already left the network the moment the query was
sent; the response isn't part of the channel here.

## 4. Decoding

Stripping the `NNN.` sequence prefix and the `.relay.blackgate-watch.net`
suffix from each of the three queries, in sequence order, and concatenating
the hex:

```
000 -> 723030747b646e735f74756e6e336c73
001 -> 5f63347272795f6d3072335f7468346e
002 -> 5f717533723133737d
```

```python
labels = [
    "723030747b646e735f74756e6e336c73",
    "5f63347272795f6d3072335f7468346e",
    "5f717533723133737d",
]
data = bytes.fromhex("".join(labels))
print(data)
```

```
b'r00t{dns_tunn3ls_c4rry_m0r3_th4n_qu3r13s}'
```

Flag, directly:

```
r00t{dns_tunn3ls_c4rry_m0r3_th4n_qu3r13s}
```

## 5. Why this works as DNS exfiltration

- DNS is almost always allowed outbound through firewalls/proxies even when
  everything else is locked down, so it's an attractive covert channel.
- A query to a domain the attacker controls (`blackgate-watch.net` here)
  routes through the local resolver, which — if it doesn't already have the
  answer cached — forwards it toward the authoritative server, carrying the
  encoded subdomain the whole way; no response is ever needed for data to
  leave.
- DNS labels are limited to 63 bytes and full names to 255, so large data
  is chunked (here: hex-encoded, numbered, split across three queries) and
  reassembled by sequence number on the receiving end — mirrored here by
  just sorting on the `NNN` prefix before concatenating.
- Burying three odd queries inside 1,306 look-alike corporate DNS lookups
  from 41 hosts is exactly how this kind of exfil tries to hide in
  plain sight; the giveaway was an anomaly in query *length* and
  *domain reputation*, not record type or volume.

## Indicators of compromise

| Type | Value |
|---|---|
| Internal source host | `10.20.7.44` |
| Tunnel domain | `blackgate-watch.net` (specifically `relay.blackgate-watch.net`) |
| Internal resolver used | `10.20.0.53` |
| Pattern | `<3-digit sequence>.<hex payload chunk>.relay.blackgate-watch.net`, A-record queries only |
| Timing | 3 queries, 08:14:06–08:14:08 UTC, ~1.2 s apart |

## Lessons

- A domain's query volume being low is not itself suspicious — look at
  what's *unusual* relative to its own host, not just low-frequency vs.
  high-frequency domains in aggregate.
- Sorting/filtering on simple derived fields (name length, suffix
  reputation, per-host packet count) cracks a haystack search far faster
  than reading packets in order.
- A sequence prefix in subdomain labels is a strong DNS-tunneling tell;
  check for it before assuming TXT/NULL records are required for this kind
  of exfil.

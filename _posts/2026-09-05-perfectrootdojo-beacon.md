---
title: "Beacon — XOR C2 Traffic Analysis"
date: 2026-09-05 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, pcap, xor, c2, network]
pin: false
---

# BEACON.TXT - beacon.pcap solve notes

## FLAG
    r00t{x0r_k3ys_h4t3_kn0wn_pl41nt3xt}

INFECTED HOST:  10.60.4.112
C2 SERVER:      91.242.87.19, TCP port 4444 (reached by raw IP, no DNS lookup)
CIPHER:         repeating-key XOR, 6-byte key  37 a2 54 e3 c7 02


## 1. The Capture
No tshark, scapy or dpkt was available, so I wrote a small pcap/Ethernet/
IP/TCP/UDP parser in Python.

  - 3,696 packets over about 108 seconds, Ethernet, classic pcap.
  - 2,096 TCP, 1,360 UDP, 240 ARP.
  - 42 internal hosts in 10.60.0.0/16, all noisy in the normal way.


## 2. Separating Normal From Abnormal
Normal background traffic:
  - UDP/53 DNS to the resolver 10.60.0.53. Only 14 distinct names were
    asked for, all ordinary: graph.microsoft.com, api.slack.com,
    fonts.googleapis.com, cdn.jsdelivr.net, zoom.us, update.googleapis.com,
    github.com, outlook.office365.com, teams.microsoft.com,
    clients2.google.com, time.windows.com, drive.google.com,
    docs.google.com, s3.amazonaws.com.
  - 520 TCP SYNs to port 443 (TLS to cloud/SaaS addresses, mostly 52.x).
  - NTP-looking UDP to 132.163.97.1.

Anything that is not one of those stands out. There is exactly one:

  - The ONLY TCP SYN to a port other than 443 in the whole file is to
    port 4444 (a well-known default listener port for reverse shells/C2
    frameworks).
  - Its destination 91.242.87.19 was never resolved via DNS. (Every SYN in
    the file goes to a different external address, 521 in total, so the
    destination alone is not what marks it out; the port and the missing
    DNS lookup are.)
  - The source is 10.60.4.112. That host's entire traffic in the capture
    (16 packets) is this one connection.

Flow (times relative to start of capture):

   71.1 s  10.60.4.112:39281 -> 91.242.87.19:4444  SYN
   72.3 s  C2 -> host                              SYN/ACK
   75.3 s  host -> C2   33 bytes                   check-in #1
   77.1 s  host -> C2   33 bytes                   check-in #2
   79.4 s  host -> C2   33 bytes                   check-in #3
   81.6 s  host -> C2   35 bytes                   check-in #4
   83.1 s  C2 -> host   44 bytes                   reply
   84.5 s  FIN exchange


## 3. The Payloads
Not readable as sent. Hex of the four host->C2 messages:

   #1 74ea11a08c4b79983c8cb4761a9563d0f338069563d3f732079264d3fd6b53ce31
   #2 same as #1 except one byte (0x64 -> 0x62 at offset 26)
   #3 same as #1 except offsets 25-26 (0x92 0x64 -> 0x93 0x66)
   #4 same as #3 prefix, then longer (35 bytes)

Three things stood out:
  - Messages #1-#4 are identical except at a few positions, and the changes
    do not spread. A block cipher would change the whole block. This is a
    byte-wise XOR with a fixed keystream: the same key for every message.
  - Similar byte patterns repeat every 6 bytes (offsets 13-14 and 19-20 are
    "95 63" both times), which points to a key of length 6.
  - Several messages share bytes with the 44-byte reply at the same
    offsets, so the reply uses the same key.


## 4. Recovering The Key
Known-plaintext attacks, using what the differences imply:

  a) The differing bytes in #1..#4 behave like decimal digits being
     incremented. Assuming a plaintext digit '0' at offsets 25 and 26 gives
     the key bytes at positions 25 % 6 = 1 and 26 % 6 = 2:
         0x92 ^ 0x30 = 0xa2
         0x64 ^ 0x30 = 0x54
  b) The reply is likely to carry the flag, so assume it contains the
     start r00t{ . With the key repeating every 6 bytes and offset 13 using
     key byte 1 (0xa2): 0xd9 ^ 0xa2 = 0x7b = '{'. That fits independently,
     which confirms the period of 6 and key byte 1.
  c) Then "r00t" must sit at offsets 9-12, which fixes the remaining
     key bytes:
         k3 = 0x91 ^ 'r' = 0xe3
         k4 = 0xf7 ^ '0' = 0xc7
         k5 = 0x32 ^ '0' = 0x02
         k0 = 0x43 ^ 't' = 0x37

  Key:  37 a2 54 e3 c7 02

The key is not ASCII, so it is not a word I could have guessed. It came
purely from the cribs.


## 5. Decryption
XORing every message with the repeating key gives clean text, with no
leftover garbage anywhere in any of the five messages:

  host -> C2:
     CHECKIN:host-7734:1770000000:idle
     CHECKIN:host-7734:1770000060:idle
     CHECKIN:host-7734:1770000120:idle
     CHECKIN:host-7734:1770000180:active

  C2 -> host:
     TASK:ack:r00t{x0r_k3ys_h4t3_kn0wn_pl41nt3xt}

So the bot identifies itself as "host-7734", reports a timestamp that moves
in 60-second steps and a state (idle, then active), and the server answers
with a task acknowledgement that carries the flag.

The fact that all five messages decrypt completely with one 6-byte key,
including parts I did not use to derive it (for example the words CHECKIN,
idle, active and TASK, and the numeric timestamps), is the confirmation.


## 6. Indicators
  Infected host:       10.60.4.112 (bot id "host-7734")
  C2 IP / port:        91.242.87.19 : 4444/tcp
  Source port seen:    39281
  Protocol:            custom, repeating-XOR over raw TCP, text messages
                       of the form CHECKIN:<id>:<unix time>:<state> and
                       TASK:<verb>:<data>
  XOR key:             37a254e3c702
  Behaviour:           direct-to-IP connection with no DNS lookup, an
                       unusual port, and short periodic check-ins.


## 7. Caveats
  - The embedded timestamps step by 60 s, but the check-ins in the capture
    are only about 2 seconds apart. I did not resolve this. It does not
    affect the decryption.
  - Only one bot is visible; no other internal host talks to the C2.
  - "Nothing else is suspicious" is based on destination ports, DNS names
    and flow counts. I did not decode the TLS flows, which are opaque.

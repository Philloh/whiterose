---
title: "The Hunt — Modbus ICS Intrusion Analysis"
date: 2026-11-01 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, ics, modbus, pcap, network]
pin: false
---

# The Hunt — Industrial Pipeline Intrusion Analysis

**Artifact analyzed:** `the_hunt.pcap`
**Protocol in scope:** Modbus/TCP (port 502)
**Objective:** Identify anomalous activity on an industrial control network, attribute it to a host, and recover the embedded flag.

---

## 1. Scenario

Engineers flagged unusual behavior on a pipeline control network. The only artifact provided was a packet capture (`the_hunt.pcap`, ~337 KB, 3,703 packets). The task was to determine what happened, who was responsible, and extract proof (a flag) left behind by the intrusion.

## 2. Environment & Tooling

The analysis sandbox had no internet access and no `tshark`/`scapy` available, so the capture was parsed from scratch in Python:

- A minimal **pcap global/record header parser** (`struct`-based) was written to pull raw Ethernet frames out of the classic (non-pcapng) `.pcap` file.
- A second pass decoded **Ethernet → IPv4 → TCP** headers to identify hosts, ports, and protocols in play.
- A third pass implemented a **Modbus/TCP** parser (MBAP header: Transaction ID, Protocol ID, Length, Unit ID, followed by the PDU: function code + data) to decode every request/response on the wire.

No commercial or pre-built dissectors were used — everything was hand-rolled from the Modbus and pcap specifications, which also made it trivial to pivot the analysis as hypotheses changed.

## 3. Initial Recon

### 3.1 Link & transport layer

```
Link type: Ethernet
Total packets: 3,703
Protocols: 100% TCP
```

Every single packet in the capture was TCP — no ARP, ICMP, DNS, or anything else. That immediately narrowed the hunt.

### 3.2 Conversations

| Src IP | Dst IP | Packets |
|---|---|---|
| 172.28.0.20 | 172.28.0.10 | 2218 |
| 172.28.0.10 | 172.28.0.20 | 1110 |
| 172.28.0.21 | 172.28.0.10 | 224 |
| 172.28.0.10 | 172.28.0.21 | 113 |
| 172.28.0.66 | 172.28.0.10 | 18 |
| 172.28.0.10 | 172.28.0.66 | 10 |
| 172.28.0.30 | 172.28.0.10 | 6 |
| 172.28.0.10 | 172.28.0.30 | 4 |

Every conversation involves **172.28.0.10**, and every TCP session runs over **port 502** — the standard Modbus/TCP port. This confirmed `172.28.0.10` as the PLC/field device, with four distinct clients talking to it.

## 4. Protocol-Level Analysis (Modbus/TCP)

Decoding the MBAP headers and PDUs across all 3,703 packets produced **2,458 Modbus transactions**, broken down by function code:

| FC | Name | Count |
|---|---|---|
| 3 | Read Holding Registers | 1,334 |
| 1 | Read Coils | 1,110 |
| 6 | Write Single Register | 8 |
| 5 | Write Single Coil | 4 |
| 16 | Write Multiple Registers | 2 |

The overwhelming majority of traffic is **read-only polling** — normal SCADA/HMI behavior. The 14 **write** transactions are what mattered.

### 4.1 Profiling each client

Grouping transactions by client IP and looking at *which function codes each host used* and *session duration* separated the normal operators from the odd one out:

| Client IP | Function codes used | First seen | Last seen | Session span |
|---|---|---|---|---|
| 172.28.0.20 | FC1, FC3 (read only) | T+0s | T+553s | Entire capture |
| 172.28.0.21 | FC3 (read only) | T+0s | T+550s | Entire capture |
| **172.28.0.30** | FC3 (1x), **FC6 (1x)** | T+90.4s | T+90.4s | **<1 ms** |
| **172.28.0.66** | FC1, FC3, **FC5 (2x), FC6 (3x), FC16 (1x)** | T+150s | T+450s | 300s, writes only |

- **172.28.0.20** and **172.28.0.21** poll continuously for the full duration of the capture, using only read function codes — classic HMI / historian behavior.
- **172.28.0.30** opens a connection for under a millisecond, issues exactly one read and one write, then disappears. This is the signature of an **engineering workstation**: connect briefly with engineering software, check a setpoint, push an update, disconnect.
- **172.28.0.66** never behaves like a monitoring station. It shows up mid-capture and, aside from one incidental read, does nothing but **write** to coils and registers — including the only `Write Multiple Registers` (FC16) transaction in the entire capture.

### 4.2 The engineer's session (172.28.0.30)

```
T+0.000000  172.28.0.30 -> 172.28.0.10  FC3 Read Holding Register[addr=10, qty=1]
T+0.000620  172.28.0.10 -> 172.28.0.30  Response: value = 0x0258 (600)
T+0.000847  172.28.0.30 -> 172.28.0.10  FC6 Write Single Register[addr=10, value=0x026c (620)]
T+0.000936  172.28.0.10 -> 172.28.0.30  Echo/ACK
```

A textbook configuration change: read the current setpoint (600), write a slightly adjusted value (620), done. Nothing malicious — this is the legitimate engineer.

### 4.3 The attacker's session (172.28.0.66)

```
T+0s     Write Single Coil   addr=2   -> OFF   (0x0000)
T+15s    Write Single Register addr=4 -> 70
T+75s    Write Single Register addr=4 -> 40
T+75s    Write Single Coil   addr=2   -> ON    (0xFF00)
T+150s   Write Multiple Registers addr=20..47 (28 registers)  <-- payload below
T+270s   Write Single Register addr=20 -> 650   (overwrites first word of payload)
```

This host:
1. Toggled a coil (likely a valve or pump actuator) off, then back on 75 seconds later.
2. Twice rewrote a process register (address 4) to different values — tampering with a setpoint.
3. Pushed a 28-register block starting at address 20 — far larger than any legitimate write in the capture, and the only use of FC16 observed.
4. Returned two minutes later and overwrote just the *first* register of that block, as if trying to cover its tracks.

None of this matches read-poll behavior from an HMI, nor the single-shot read/write pattern of the engineer. **172.28.0.66 is the intruder.**

## 5. Extracting the Payload

The FC16 write's data field (56 bytes = 28 × 16-bit registers) was decoded big-endian, register by register:

```
Raw hex: 0384 0072 0030 0030 0074 007b 0031 005f 006c 0030 0076
         0033 005f 006d 0033 005f 0073 0030 006d 0033 005f 006d
         0030 0064 0062 0075 0073 007d
```

Every register after the first follows the pattern `0x00XX`, where `XX` is a printable ASCII byte sitting in the **low byte** of each 16-bit register — a simple "one character per Modbus register" encoding. Reading the low byte of registers 1–27 in order:

```
r 0 0 t { 1 _ l 0 v 3 _ m 3 _ s 0 m 3 _ m 0 d b u s }
```

(Register 0, value `0x0384`, doesn't fit the pattern and was left out of the decoded string — plausibly padding or a deliberate decoy, consistent with the later "cleanup" write that overwrote exactly that register.)

### Decoded flag

```
r00t{1_l0v3_m3_s0m3_m0dbus}
```

## 6. Findings Summary

| Question | Answer | Evidence |
|---|---|---|
| Protocol in use | Modbus/TCP (port 502) | 100% of traffic on TCP/502, valid MBAP headers |
| PLC / target device | 172.28.0.10 | Common endpoint of every conversation |
| HMI / monitoring stations | 172.28.0.20, 172.28.0.21 | Continuous read-only polling, full capture duration |
| **Engineer IP** | **172.28.0.30** | Single sub-millisecond read-then-write session (legitimate setpoint change) |
| **Attacker IP** | **172.28.0.66** | Only client issuing unsolicited writes (coil toggling, register tampering, FC16 payload injection, cleanup overwrite) |
| Flag | `r00t{1_l0v3_m3_s0m3_m0dbus}` | Decoded from the FC16 Write Multiple Registers payload, low byte of registers 1–27 |

## 7. Methodology Recap (how the lab was solved)

1. **Triaged the capture** — confirmed it was pure TCP, found a single server (`172.28.0.10`) and four clients.
2. **Parsed Modbus/TCP manually** (no network access for tooling), decoding MBAP headers and PDUs for all 2,458 transactions.
3. **Tallied function codes** to separate benign polling (FC1/FC3) from state-changing operations (FC5/FC6/FC16).
4. **Profiled each client** by function-code mix and session duration/timing, which cleanly separated:
   - continuous read-only pollers (HMI/historian),
   - a single legitimate read-then-write engineer session,
   - a write-only, multi-stage attacker session.
5. **Reconstructed the attacker's write-command timeline** to characterize the intrusion (actuator toggling, setpoint tampering, bulk register write, cleanup write).
6. **Decoded the FC16 payload** register-by-register, isolating the low (ASCII) byte of each word to recover the planted flag.

## 8. Recommendations

- Modbus/TCP has no built-in authentication — any host that can route to `172.28.0.10:502` can issue writes. Network segmentation/ACLs should restrict write-capable function codes to known engineering workstations only.
- Deploy ICS-aware monitoring that alerts on FC5/FC6/FC16 from unexpected source IPs, and on any write immediately followed by a write to the same address from a different session (the "cleanup" pattern seen here).
- Consider Modbus proxy/firewall enforcement of a function-code allowlist per source IP.

---
*End of write-up.*

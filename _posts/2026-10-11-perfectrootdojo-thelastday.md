---
title: "The Last Day — Windows Event Log Analysis"
date: 2026-10-11 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, windows, evtx, insider-threat, incident-response]
pin: false
---


## Scenario
HR flagged a departure as routine offboarding, but an analyst found file access
to folders the employee had no reason to touch, after hours. Two host log
exports were provided:

  - Security.evtx                              (Windows Security log)
  - Microsoft-Windows-Sysmon4Operational.evtx  (Sysmon Operational log)

Flag format: r00t{....}


## 1. Tooling and parsing
- Installed the python-evtx library (pip install python-evtx) and parsed each
  .evtx file record by record, converting every record to XML text.
- Extracted EventID, TimeCreated/@SystemTime and every <Data Name="...">
  field, then printed one compact line per event for review.
- Counted event IDs first to see what the logs contained:
    Security: 4624 logon, 4672 special privileges, 4688 process creation,
              4663 object access, 4776 NTLM auth, 4725 account disabled,
              5145 network share access, 1102 log cleared
    Sysmon:   1 process create, 3 network connection, 7 image load,
              10 process access, 11 file create, 18 pipe connect
- As a cross-check, dumped UTF-16 strings from both files (strings -el),
  sorted by frequency. Fabricated/injected values appear exactly once, while
  background noise repeats many times, which helps separate the two.


## 2. Separating signal from noise
The files are padded with unrelated records from other public datasets
(2019 sshd/MSI events, 2020 HR-ADMIN01 activity, Chrome BITS downloads for
user "bouss", Meterpreter-style named pipe/nc.exe test data, etc.). The
relevant events share these traits:
  - Computer = WKSTN-14.p3rfcorp.local
  - TimeCreated in the 2026-09-13 23:30 -> 2026-09-14 00:07 UTC window
  - Involve user n.wanjiru in domain P3RFCORP
Note: Sysmon events carry a stale internal <UtcTime> field (2020/2021) copied
from the source dataset. The reliable time is the event header
TimeCreated/@SystemTime, which is consistent across both logs.


## 3. Findings per question
Q1  Account that logged on after business hours
    Security 4624, LogonType 10 (RemoteInteractive / RDP), 2026-09-13 23:47:12
    UTC, TargetUserName = n.wanjiru, TargetDomainName = P3RFCORP, via seclogo
    / NTLM.
    Answer: r00t{n.wanjiru}

Q2  Source IP of that logon
    Same 4624 event, IpAddress field = 203.0.113.77 (external address).
    Answer: r00t{203.0.113.77}

Q3  Where the sensitive files were staged
    Security 4663 shows n.wanjiru reading C:\Shares\Finance\Client_Master_List.xlsx
    and Q3_Client_Contracts.xlsx (plus Chrome "Login Data" and Firefox
    logins.json - credential stores). Sysmon 11 (23:52:30) shows explorer.exe
    creating F:\Staging\ClientExports_Raw.xlsx, and the later 7-Zip command
    archives F:\Staging\*.
    Answer: r00t{F:\Staging}

Q4  Archive filename
    Sysmon 1 (00:03:45), user P3RFCORP\n.wanjiru, parent cmd.exe:
      7z.exe a -p client_exports_final.7z F:\Staging\*
    (password-protected 7z archive of the staging folder)
    Answer: r00t{client_exports_final.7z}

Q5  Domain that received the upload
    Sysmon 3 network connection, Image C:\Program Files\7-Zip\7z.exe, user
    P3RFCORP\n.wanjiru, DestinationHostname vault-personal-sync.io,
    port 443 (https).
    Answer: r00t{vault-personal-sync.io}

Q6  Time of the exfiltration upload (to the second)
    The Sysmon 3 event above has header TimeCreated SystemTime
    2026-09-14 00:07:22 UTC. The embedded UtcTime (2020-08-02 16:24:59) is
    leftover dataset noise and was rejected. Sequence check:
      23:47:12 logon -> 23:52:30 staging -> 00:03:45 archive -> 00:07:22 upload
    Answer: r00t{2026-09-14 00:07:22}
    (Note: the bare time r00t{00:07:22} was not accepted - the full date and
    time format is required.)

Q7  What the paperwork left behind
    On HR-ADMIN01, six account deactivations (Security 4725) were issued in
    the same batch at 2020-09-17 10:57:44, after an NTLM logon (4624/4776)
    from 172.16.66.37 and IPC$ (samr/lsarpc) share access (5145). Five of
    the six events have SubjectUserName = it.admin. The one disabling
    n.wanjiru (EventRecordID 769796) has SubjectUserName =
    r00t{th3_l4st_d4y_1ns1d3r_thr34t} - the actor field was tampered with /
    contains the flag. Found by comparing the SubjectUserName across all
    4725 events, and confirmed by a string search for "r00t".
    Answer: r00t{th3_l4st_d4y_1ns1d3r_thr34t}


## 4. Other observations (not needed for the answers)
- Security 1102 (audit log cleared) on WKSTN-14 at 2026-09-13 23:30:00 UTC,
  attributed to user01 - possible anti-forensics.
- 4672 with SeSecurityPrivilege for the new logon session at 23:30:00.
- Logon was initiated by "user01" (seclogo / secondary logon) targeting
  n.wanjiru, which suggests credential reuse/impersonation.
- Suspicious lookalike binaries in noise records: C:\ProgramData\Intel\CV.exe
  side-loading wwlib.dll, C:\Users\Defau1t\wsus.exe, cmdkey/lync.zip activity.


## 5. Attack timeline (UTC)
2026-09-13 23:30:00  Security log cleared (1102), special privileges assigned
2026-09-13 23:47:12  RDP logon n.wanjiru from 203.0.113.77
2026-09-13 23:52:30  ClientExports_Raw.xlsx written to F:\Staging
2026-09-13 23:56:00  Reads of Finance share files and browser credential stores
2026-09-14 00:03:45  7z archive client_exports_final.7z created from F:\Staging\*
2026-09-14 00:07:22  Upload over HTTPS to vault-personal-sync.io


## 6. Final answers
Q1  r00t{n.wanjiru}
Q2  r00t{203.0.113.77}
Q3  r00t{F:\Staging}
Q4  r00t{client_exports_final.7z}
Q5  r00t{vault-personal-sync.io}
Q6  r00t{2026-09-14 00:07:22}
Q7  r00t{th3_l4st_d4y_1ns1d3r_thr34t}

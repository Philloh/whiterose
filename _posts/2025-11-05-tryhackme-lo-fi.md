---
title: "TryHackMe Lo-Fi — Walkthrough"
date: 2025-11-05 10:00:00 +0300
categories: [TryHackMe, Web]
tags: [lfi, log-poisoning, rce, beginner]
pin: false
---

Lo-Fi is a beginner-friendly room centered on **Local File Inclusion (LFI)**. The intended solve reads `/flag.txt` through the `?page=` parameter. The writeup below also covers optional **log poisoning** to turn the LFI into **RCE**.

## The Flag

The objective is to visit the web application and retrieve the flag at the filesystem root.

Browsing to `http://<TARGET_IP>/` shows links to YouTube videos. Other pages load content through the **`/?page=`** query parameter.

A direct request such as `http://<TARGET_IP>/?page=/flag.txt` triggers an error. Testing shows the failure occurs only when the `page` value **begins with `/`**.

Instead of an absolute path, use directory traversal:

```text
http://<TARGET_IP>/?page=../../../flag.txt
```

That request displays the flag and completes the room.

![Lo-Fi homepage and LFI flag read](/assets/img/posts/lo-fi/flag-lfi.png)

## Extra — RCE

Reading the flag finishes the room, but the LFI can be pushed further toward **remote code execution**.

### Log poisoning approach

A common technique poisons a log file by injecting a **PHP** payload, then includes that log through the LFI to execute code.

Direct inclusion of `access.log` failed in testing. Checking open file descriptors for the current process revealed the access log could still be included via **`/proc/self/fd/6`**.

With log inclusion working, the **User-Agent** header is written into the log. Set User-Agent to a PHP one-liner (for example `<?php system($_GET["cmd"]); ?>`), send any request to the server, then include `/proc/self/fd/6` again through `?page=` and pass commands via a `cmd` parameter.

Successful command execution confirms RCE.

![Log poisoning via User-Agent and proc fd](/assets/img/posts/lo-fi/log-poison-rce.png)

### Container note

This RCE path can be used to obtain a shell inside the container and potentially escalate with **DirtyPipe**, but escaping the container was not achieved in this attempt.

## Takeaways

- LFI filters on leading `/` often still allow **`../` traversal**.
- **`/proc/self/fd/N`** can expose log paths when direct paths are blocked.
- Log poisoning ties **controllable input** (User-Agent) to **include()** sinks.

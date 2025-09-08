# TMG CSRF Assessment Tool

> Disclaimer
> This project is intended for educational use in lab environments or for authorized penetration testing only. You must have prior written permission from the system owner before running any tests. The authors and contributors assume no liability for misuse. Use responsibly and comply with all applicable laws, policies, and contracts.

A compact helper to assess CSRF protection and HTTP normalization in Microsoft Forefront TMG / Exchange OWA publications. It does NOT bypass defenses. Instead, it runs safe probes and reports common protection markers.

- English UI, comments, and startup prompts
- Built‑in light/dark theme toggle (persists in localStorage)
- Web config page to edit target, public host/port, Origin/Referer, and CSRF credentials
- CSRF browser PoC (form auto‑submit to CookieAuth.dll)
- Server‑side verification (basic/deep) with controllable Origin/Referer
- Suite of negative tests for URL encoding, path normalization, headers variance, and methods


## Table of Contents
- [Why](#why)
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Run](#run)
- [Usage](#usage)
  - [Endpoints](#endpoints)
  - [Web Config](#web-config)
  - [Theme Toggle](#theme-toggle)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
- [How the Verdict Works](#how-the-verdict-works)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)


## Why
CSRF testing should verify that a reverse proxy (TMG) or the application (OWA/FBA) enforces same‑origin and/or token protections. This tool:
- Mimics a cross‑site form POST (browser PoC)
- Performs server‑side checks with custom Origin/Referer
- Exercises normalization edge cases (encoded slashes, dot‑segments, duplicate headers, etc.)

> Important: This project is for defensive assessment and validation only.


## Features
- Interactive startup prompts (target URL, public host, listen port)
- English UI and comments
- Light/Dark theme toggle (remembered in localStorage)
- Web configuration page to adjust:
  - Target base (e.g., https://mail.example.com)
  - Public host/port (your exposed PoC URL)
  - Fake Origin/Referer used by server‑side verification
  - CSRF credentials (username/password) for the FBA form
- CSRF Browser PoC page: auto‑submits a form to CookieAuth.dll
- Verification pages:
  - Basic verify: single response assessment
  - Deep verify: follows redirect chain and evaluates protection markers
- Assessment suite:
  - Encoding: double percent, encoded slash, mixed hex case, UTF‑8 overlong‑like
  - Path: dot‑segments, double slashes, encoded backslash, semicolon paths
  - Headers: unusual Content‑Type, duplicate‑like header names
  - Methods: OPTIONS, PUT, TRACE


## Architecture
flowchart LR
  A[Browser opens UI] --> B[PoC page]
  B -->|Auto-submit form| D[CookieAuth.dll target]
  A --> C[Verify / Verify-Deep]
  C -->|Origin/Referer per config| D
  D --> E{Responses}
  E -->|4xx, GetLogon, cookie reset| F[Protection markers]
  F --> G[Verdict]
  A --> H[Suite probes]
  H --> D



## Getting Started
### Prerequisites
- Python 3.8+
- Optional: `pip install requests` (server-side verification and suite)

### Run
```bash
python csrf_poc_server.py
```
You will be prompted for:
- Enter target base URL (TARGET_BASE)
- Enter your public IP/host for PoC access (PUBLIC_HOST)
- Enter listen port (LISTEN_PORT/PUBLIC_PORT)

Open the printed public URL in a browser (e.g., http://YOUR_IP:PORT/).

> Tip: When testing from the same LAN over a public address, your router must support hairpin NAT (NAT loopback). Otherwise use a truly external client (e.g., mobile network).


## Usage
### Endpoints
- `/` — Overview, quick actions
- `/config` — Edit target/public host/port, fake Origin/Referer, and CSRF credentials
- `/poc` — Browser CSRF PoC (auto‑submit form to CookieAuth.dll)
- `/verify` — Basic server‑side verification (first response)
- `/verify-deep` — Deep verification (follow redirects)
- `/suite` — Assessment suite (encoding, path, headers, methods)

You can pass query parameters to `/verify` and `/verify-deep`:
- `origin=...` and `referer=...`
- `__NONE__` removes the header (e.g., `origin=__NONE__`)

### Web Config
- Change target base and public endpoint without restarting
- Provide CSRF Username/Password for FBA testing (password is not displayed after save)

### Theme Toggle
- Top‑right “Theme” button
- Persists in `localStorage` (Dark/Light)


## Configuration
### Environment Variables
You can also configure via environment variables (and then fine‑tune in `/config`).

| Variable | Default | Description |
|---|---|---|
| TARGET_BASE | https://example.com | Target base URL published via TMG |
| PUBLIC_HOST | 127.0.0.1 | Your public IP/host to access the PoC UI |
| LISTEN_HOST | 0.0.0.0 | Listen address for this helper |
| LISTEN_PORT | 4444 | Listen port for this helper |
| PUBLIC_PORT | LISTEN_PORT | Public port (for display/Origin defaults) |
| COOKIEAUTH_PATH | /CookieAuth.dll?Logon | FBA logon endpoint |
| GET_LOGON_PATH | /CookieAuth.dll?GetLogon?... | Warm‑up endpoint |
| AUTHOWA_PATH | /owa/auth.owa | OWA auth endpoint (for header tests) |
| PUBLISHED_SAFE_PATH | /owa/ | A safe published path for GET probes |
| CSRF_USERNAME | test.user | Username for FBA form payload |
| CSRF_PASSWORD | NotARealPass123 | Password for FBA form payload |
| CSRF_SUBMIT_NAME | SubmitCreds | Submit field name |
| CSRF_SUBMIT_VALUE | Sign in | Submit field value |
| CSRF_FLAGS | 0 | FBA flags |
| CSRF_FORCEDOWNLEVEL | 0 | FBA downlevel flag |
| CSRF_FORMDIR | 1 | FBA formdir |
| CSRF_TRUSTED | 0 | FBA trusted flag |
| CSRF_ISUTF8 | 1 | FBA isUtf8 |
| CSRF_CURL | Z2FowaZ2F | FBA curl value |
| CSRF_DESTINATION | /owa/ | FBA destination |
| FAKE_ORIGIN | http://PUBLIC_HOST:PUBLIC_PORT | Default Origin for server‑side verify |
| FAKE_REFERER | (empty) | Default Referer for server‑side verify |
| CERT_FILE | (empty) | Enable HTTPS if set with KEY_FILE |
| KEY_FILE | (empty) | Private key for HTTPS |


## How the Verdict Works
Deep verification considers a protection “likely enabled” if any of the following are observed in the response chain:
- HTTP 400/403
- Redirect to `CookieAuth.dll?GetLogon` (any reason)
- Cookie reset patterns (e.g., `expires=Thu, 01-Jan-1970`)

If none are present and the flow reaches `/owa/` with cookies set, it reports “possibly not enforced”. Always confirm with server logs.


## Troubleshooting
- `requests not installed — warm-up skipped`
  - Install requests: `pip install requests`
- UI opens but redirects/calls fail
  - Verify TARGET_BASE and that the resource is reachable from the helper host
- Browser PoC shows wrong Origin
  - Access the UI via your public URL (host:port) that matches the expected Origin
- Can’t access via public IP from LAN
  - Router may lack hairpin NAT; try an external client
- Port already in use
  - Change LISTEN_PORT or stop the conflicting service


## Security Notes
- For defensive assessment only. Do not use to bypass controls.
- Credentials are only sent to the configured target and are not logged by the helper.
- Prefer testing against a staging environment with test accounts.
- TMG is EOL; consider migrating publication to a supported reverse proxy/WAF where possible.


## Roadmap
- Optional export of results (HTML/JSON)
- CLI flags to pre‑seed config without prompts
- Fetch Metadata validation probes (Sec‑Fetch‑*)
- Minimal SOAP probe for EWS (separate, opt‑in)


## Contributing
PRs and issues are welcome. Please:
- Keep features defensive and non‑evasive
- Add docstrings and comments
- Include a brief test plan for new probes


## License
MIT

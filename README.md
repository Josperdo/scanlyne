# Scanlyne

Network change detection with security context. Scanlyne runs nmap scans, stores the results, and shows you what changed between snapshots — with plain-English notes on why a given change might be worth investigating.

---

## The gap this fills

Most network monitoring tools are either too much or too little:

- **Enterprise solutions** (Nessus, Qualys, SolarWinds) are expensive, complex to operate, and built for teams with dedicated security staff.
- **Raw nmap CLI** gives you everything but answers nothing. A 500-line XML dump doesn't tell you whether the new open port on your NAS is a misconfiguration or expected.

Scanlyne sits in between. It's for people who run their own infrastructure — homelabbers, sysadmins, small teams — who want a simple answer to: **"What changed on my network since I last checked, and should I care?"**

---

## Who it's for

- **Homelabbers** tracking service sprawl across VMs, containers, and devices
- **Sysadmins** verifying that patch windows or config changes didn't leave unexpected ports open
- **Security analysts** who want a lightweight audit trail without standing up a full SIEM
- **Students** learning network security concepts through hands-on tooling

---

## What it does

1. **Run a scan** — submit a target (IP, CIDR, hostname) and optional nmap flags through the web UI. Results are stored in SQLite and the raw XML is kept on disk.

2. **Save a baseline** — after a scan that reflects a known-good state, mark it as the baseline for that target. This is the reference point all future scans are compared against.

3. **Detect changes** — run another scan, then open Change Detection. Scanlyne diffs the two scans and surfaces:
   - **New hosts** — devices that appeared on the network
   - **Removed hosts** — devices that disappeared
   - **Changed hosts** — same IP, but ports or services differ:
     - Ports that opened or closed
     - Services whose version or state changed

4. **Triage with context** — each change includes a short risk hint. Not a verdict, just a starting point:

```
[!] New open port: 3306/tcp — MySQL — database, verify intentional exposure
[!] Port 4444/tcp opened — Common reverse shell port
[~] Service version changed on 443/tcp — may indicate an upgrade or a substitution
[✓] Port 8080/tcp closed — previously open, now gone
```

---

## Example: catching an unexpected service

You baseline your home server on a Sunday. Mid-week you update some packages. You run another scan and open Change Detection:

```
Target: 192.168.1.10
Baseline: Scan #3 (2024-11-10 14:32)  →  Current: Scan #7 (2024-11-13 09:15)

Changed hosts
└── 192.168.1.10

    New ports
    ┌─────────┬──────────┬───────┬────────────────────────────────────────────────────┐
    │ Port    │ Protocol │ State │ Risk hint                                          │
    ├─────────┼──────────┼───────┼────────────────────────────────────────────────────┤
    │ 6379    │ tcp      │ open  │ Redis — often misconfigured with no auth           │
    └─────────┴──────────┴───────┴────────────────────────────────────────────────────┘

    Service changes
    ┌──────┬──────────┬─────────────────────┬─────────────────────┬──────────────────┐
    │ Port │ Protocol │ Old service         │ New service         │ Risk hint        │
    ├──────┼──────────┼─────────────────────┼─────────────────────┼──────────────────┤
    │ 443  │ tcp      │ Apache httpd 2.4.51 │ Apache httpd 2.4.58 │ Version changed  │
    └──────┴──────────┴─────────────────────┴─────────────────────┴──────────────────┘
```

Redis wasn't there before. A package update pulled it in as a dependency and it bound to all interfaces. Worth knowing.

<img width="1077" height="615" alt="Scanlyne-scan-page" src="https://github.com/user-attachments/assets/47187b05-75c3-40bd-8749-5f813fa26f1b" />


---

## Architecture

```
scanlyne/
├── app.py              # Flask application factory, auth, scheduler startup
├── config.py           # Configuration (SECRET_KEY, DB path, scan output dir)
├── models.py           # SQLAlchemy models: Scan, Host, Port, Schedule
├── scanner.py          # nmap subprocess execution with input validation
├── parser.py           # nmap XML → Python dict
├── diff.py             # Scan comparison + risk hint generation
├── blueprints/
│   ├── scan.py         # Run scans, manage baselines
│   ├── results.py      # Scan history and detail views
│   ├── compare.py      # Change detection — the primary view
│   └── schedules.py    # Recurring scan schedule CRUD
├── templates/
│   ├── base.html
│   ├── scan/
│   ├── results/
│   ├── compare/
│   └── schedules/
└── static/
    ├── css/style.css
    └── js/main.js
```

**Data persistence:** SQLite via Flask-SQLAlchemy. No external database required. Scan results live in `instance/scanner.db`. Raw nmap XML is stored in `scans/` and referenced by path in the database.

**Dependencies:** Flask, Flask-SQLAlchemy, APScheduler, gunicorn. No message queues, no external services. APScheduler runs inside the Flask process for scheduled scans.

---

## Setup

**Requirements:** Python 3.8+, nmap installed and in PATH.

```bash
git clone <repo-url>
cd scanlyne
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`. The database and scan output directory are created automatically on first run.

For production (single worker required for the background scheduler):

```bash
gunicorn --workers 1 "app:create_app()"
```

Set `SECRET_KEY` via environment variable before deploying.

To enable HTTP Basic Auth, set both variables before starting the app:

```bash
export SCANLYNE_USERNAME=admin
export SCANLYNE_PASSWORD=yourpassword
```

When unset, the app is open — rely on network-level access control (firewall, VPN).

---

## Docker

The easiest way to run Scanlyne. nmap is included in the image.

```bash
docker compose up --build
```

Open `http://localhost:5000`. The database and scan output are stored in named Docker volumes and survive container restarts.

**Environment variables** can be set directly in `docker-compose.yml` or passed on the command line:

```bash
SECRET_KEY=mysecret SCANLYNE_USERNAME=admin SCANLYNE_PASSWORD=pass docker compose up
```

**Scanning your LAN** — by default the container runs on Docker's bridge network. To reach LAN hosts from a Linux host, switch to host networking in `docker-compose.yml`:

```yaml
# Replace the ports: mapping with:
network_mode: host
```

This is not supported on Docker Desktop for Mac or Windows — use the host's IP range as the scan target instead.

---

## Workflow

```
Run Scan → mark as baseline → Run Scan → Change Detection → review diff
```

1. **Run Scan** — enter a target and flags (e.g. `-sV -T4`). Scans run asynchronously; the detail page polls for completion.
2. **Mark as baseline** — on the scan detail page, promote a completed scan to baseline status. Add an optional label (e.g. "pre-patch", "post-change"). Multiple baselines per target are supported.
3. **Run another scan** — same target, same or different flags.
4. **Change Detection** — the app surfaces all baseline-vs-latest pairs automatically. One click to see the diff.
5. **Manual comparison** — compare any two completed scans, not just baseline pairs.
6. **Schedules** — configure recurring scans at `/schedules`. The app fires them in the background on the configured interval.

---

## Security design

Scanlyne executes nmap as a subprocess. Several controls are in place to prevent abuse:

- **Target validation** — regex allowlist blocks shell metacharacters (`; | & $ >` etc.)
- **Flag allowlist** — only a fixed set of nmap flags are permitted (no `--script`, no `--lua`)
- **No `shell=True`** — subprocess is always called with an argument list
- **Optional HTTP Basic Auth** — set `SCANLYNE_USERNAME` and `SCANLYNE_PASSWORD` environment variables to enable. Off by default; designed for trusted LAN use. Do not expose to the public internet without enabling auth and putting it behind HTTPS.

---

## Known limitations

- **Scheduler requires a single worker.** If you run gunicorn with multiple workers, each worker starts its own scheduler and will fire duplicate scans. Use `--workers 1`.
- **No HTTPS.** Run behind a reverse proxy (nginx, Caddy) if you expose this beyond localhost.
- **SQLite only.** Fine for homelab scale; not suitable for high-concurrency multi-user deployments.

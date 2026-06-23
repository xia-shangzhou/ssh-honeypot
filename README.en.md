# 🐝 SSH Honeypot

An interactive SSH honeypot that simulates a real Ubuntu SSH server, automatically captures brute-force login attempts and attacker commands, and generates a visual analytics dashboard.

[中文文档](README.md)

## ✨ Features

- **Interactive Shell Simulation** — Attackers get a fake shell after login; all commands are logged
- **Smart Classification** — Automatically distinguishes scanners/bots from real interactive attackers
- **Visual Dashboard** — Attack source map, password stats, timeline, command classification
- **GeoIP Lookup** — Auto-downloads GeoLite2 database for IP geolocation
- **One-Click Deploy** — Docker Compose ready out of the box
- **Low Resource Usage** — ~60MB memory, < 0.1% CPU

## 📊 Dashboard Preview

The dashboard includes:
- 📈 Overview stats (login attempts, unique IPs, scanners, interactive attackers)
- 🗺️ Attack source world map (ECharts)
- ⚡ Top 15 attacking IPs
- 🔑 Top 10 passwords / usernames
- 📅 Daily attack trends
- ⏰ 24-hour attack distribution
- 💻 Command classification stats
- 🏆 Interactive attacker details (with executed commands)

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/xia-shangzhou/ssh-honeypot.git
cd ssh-honeypot/docker

# Start
docker compose up -d

# View logs
docker compose logs -f
```

Dashboard: `http://localhost:8088/dashboard.html`

> The GeoLite2-City.mmdb (~65MB) is auto-downloaded on first startup for IP geolocation.

### Option 2: Manual Installation

```bash
# 1. Clone
git clone https://github.com/xia-shangzhou/ssh-honeypot.git
cd ssh-honeypot

# 2. Install dependencies
pip install paramiko geoip2

# 3. Start honeypot (default port 22, configurable via SSH_PORT env var)
python3 honeypot.py &

# 4. Start dashboard
python3 -m http.server 8088 --directory web &

# 5. Manually refresh dashboard
python3 analyze.py
```

### Option 3: Systemd Services

```bash
# Copy service files
sudo cp deploy/ssh-honeypot.service /etc/systemd/system/
sudo cp deploy/ssh-dashboard.service /etc/systemd/system/

# Enable and start
sudo systemctl enable --now ssh-honeypot ssh-dashboard
```

## ⚙️ Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_PORT` | `22` | Honeypot SSH listen port |
| `WEB_PORT` | `8088` | Web dashboard port |
| `HONEYPOT_LOG_DIR` | `./logs` | Log directory |
| `HONEYPOT_HOST_KEY` | `./keys/fake_host_key` | SSH host key path |
| `HONEYPOT_GEOIP_DB` | `./data/GeoLite2-City.mmdb` | GeoIP database path |
| `HONEYPOT_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | SSH banner string |
| `HONEYPOT_EXCLUDE_IPS` | `127.0.0.1,::1` | IPs to exclude from analysis (comma-separated) |

For Docker, set these in `docker-compose.yml` or a `.env` file.

## 📁 Project Structure

```
ssh-honeypot/
├── honeypot.py              # Honeypot main program
├── analyze.py               # Analysis script (generates dashboard)
├── update-dashboard.sh      # Scheduled update script
├── web/
│   ├── dashboard.html       # Visual dashboard (auto-generated on first run)
│   └── world.json           # ECharts world map data
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-entrypoint.sh
│   ├── honeypot.py          # Docker version (paths adapted)
│   ├── analyze.py           # Docker version
│   └── web/
├── keys/                    # SSH host keys (auto-generated, not committed)
├── logs/                    # Log files (not committed)
├── data/                    # GeoIP database (auto-downloaded, not committed)
├── .gitignore
├── LICENSE
└── README.md
```

## 📝 Data Format

### Login Attempts (logs/attempts.jsonl)

```json
{
  "timestamp": "2026-06-04T22:54:51.100224",
  "ip": "193.32.162.13",
  "port": 57216,
  "username": "root",
  "password": "***",
  "auth_type": "password"
}
```

### Commands (logs/commands.jsonl)

```json
{
  "timestamp": "2026-06-05T12:01:57.189831",
  "ip": "193.32.162.13",
  "username": "root",
  "command": "uname -s -v -n -r -m"
}
```

## 🔧 Customization

### Fake Command Responses

Edit `FAKE_RESPONSES` in `honeypot.py`:

```python
FAKE_RESPONSES = {
    "uname -s -v -n -r -m": "Linux 5.15.0-94-generic ... x86_64",
    "whoami": "root",
    # add more...
}
```

### Analysis Logic

Edit `classify_attackers()` and `analyze()` in `analyze.py`.

## 📦 Resource Usage

| Resource | Docker | Bare Metal |
|----------|--------|------------|
| Memory | ~60MB | ~60MB |
| CPU | < 0.1% | < 0.1% |
| Disk | ~258MB (image) | ~65MB |
| Log growth | ~1MB/day | ~1MB/day |

## 🛡️ Security Notes

- Do not map the honeypot port to your real port 22 unless you fully understand the risks
- Log files contain attacker IPs and passwords — do not make them public
- GeoLite2 database is subject to MaxMind's license; this project does not redistribute it
- The dashboard has no built-in authentication — protect it with a reverse proxy + Basic Auth

## 📄 License

[MIT](LICENSE)

## 🙏 Credits

- [Paramiko](https://www.paramiko.org/) — SSH protocol library
- [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — MaxMind IP geolocation
- [ECharts](https://echarts.apache.org/) — Visualization library
- [Chart.js](https://www.chartjs.org/) — Lightweight charting library

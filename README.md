# UniFi Claude Code Skill

A [Claude Code](https://claude.ai/claude-code) skill for managing a UniFi OS controller
(Dream Machine Pro/SE, Cloud Gateway, Dream Router…) through its local API. Once
installed, Claude can tell you who is on the network, block devices, reserve IPs, manage
firewall zone policies, traffic rules and port forwards, restart APs, power-cycle PoE
ports, run speed tests, hand out guest vouchers and more — just by asking.

## Requirements

- Python 3.10+ (standard library only)
- A UniFi OS controller with Network Application 9.x or 10.x and API-key support
- [Claude Code](https://claude.ai/claude-code)

## Installation

### 1. Put the skill into place

```bash
git clone git@github.com:dlewis7444/unifi-claude-skill.git
ln -s "$PWD/unifi-claude-skill" ~/.claude/skills/unifi
```

A symlink keeps the installed skill in sync with the repo; the script reads `.env`
from the repo root. Copying (`cp -r unifi-claude-skill ~/.claude/skills/unifi`) works too.

### 2. Generate a UniFi API key

The key is created in the **local** controller UI (not on unifi.ui.com — Site Manager
keys are for the cloud API and do not work here):

1. Open `https://<controller-ip>` and sign in with a **local** admin account
   (Owner or Super Admin, or a dedicated admin — see below).
2. Open the **Network** application → **Settings** (gear icon) → **Control Plane** →
   **Integrations**.
3. Click **Create API Key**, give it a name (e.g. `claude`) and an expiry, then
   **copy the key right away** — it is shown only once.

Older UniFi OS builds put the same button under **UniFi OS Settings → Admins & Users →
(your admin) → API Keys**. If you don't see *Integrations*, update the Network
application (API keys arrived in Network 9.0).

**Permissions.** A key acts with the permissions of the admin who created it. For least
privilege, create a dedicated local admin (e.g. `claude`, *Restrict to local access only*)
with the **Network → Site Admin** role and generate the key while signed in as that admin.
A *View Only* admin gives a read-only key: status and lists work, every change fails
with HTTP 401/403.

Check that the key works:

```bash
curl -sk -H "X-API-Key: <key>" https://<controller-ip>/proxy/network/integration/v1/sites
```

A JSON list of sites means the key is valid; `401` means wrong key or wrong account type.

### 3. Configure (`.env`)

```bash
cp .env.example .env
$EDITOR .env
chmod 600 .env
```

| Key | Purpose | Default |
|---|---|---|
| `UDM_HOST` | Controller hostname or IP | `unifi.local` |
| `UDM_SITE` | Site name (internal name, as in the URL) | `default` |
| `UDM_TIMEOUT` | HTTP timeout, seconds | `30` |
| `UNIFI_API_KEY` | API key | falls back to `pass` |
| `UNIFI_PASS_PATH` | [`pass`](https://www.passwordstore.org/) entry holding the key | `internal/unifi/api-key` |

Real environment variables override `.env`; the `--host`, `--site` and `--timeout`
flags override both. `.env` is gitignored.

### 4. Try it

```bash
python ~/.claude/skills/unifi/scripts/udm.py summary
python ~/.claude/skills/unifi/scripts/udm.py clients --brief
```

## Usage

Talk to Claude:

- "Is the network healthy?" / "Why is the internet slow?"
- "Who's connected? Block the Xbox."
- "Give the printer a fixed IP of 192.168.1.20 and call it Office printer"
- "Forward port 443 to the NAS"
- "Block the IoT zone from reaching the LAN"
- "Change the guest WiFi password" / "Create 5 guest vouchers for today"
- "Power-cycle the camera on switch port 7"

Claude follows the safety rules in `SKILL.md`: it looks objects up first, asks before any
change, and previews non-trivial changes with `--dry-run`.

### Secrets are masked by default

The UniFi API returns credentials in plain text (WiFi passphrases, SSH/RADIUS/PPPoE
passwords, VPN and TLS private keys, API tokens). `udm.py` prints them as `"<redacted>"`,
so they don't end up in your terminal history or in Claude's context. Updates still
work: when an object is PUT back with `"<redacted>"` placeholders, the script restores
the real values from the controller before sending (a POST with placeholders is
refused). Pass `--show-secrets` to see raw values.

The helper also works on its own — see `udm.py --help` and
[references/commands.md](references/commands.md).

## Alerts (push / email)

`scripts/monitor.py` is a small read-only monitor for an always-on host (homelab, NAS,
Raspberry Pi). Run every few minutes, it reports each change once when it starts and
once when it clears:

- internet down / back, UniFi devices offline / online, site-to-site VPN tunnels
- gateway CPU temperature outside `MONITOR_TEMP_MIN`..`MONITOR_TEMP_MAX`
- new IPS threats and honeypot hits, admin logins from IPs not in `MONITOR_ADMIN_IPS`
- clients that were never seen on the network before

The first run only saves a baseline. Delivery: push through [ntfy](https://ntfy.sh)
(`NTFY_URL`, install the ntfy app and subscribe to the same topic) and/or email through a local MTA (`SENDMAIL_CMD="msmtp -t"`) or SMTP
(`SMTP_*`; both need `MAIL_TO`) — see `.env.example`. Do not give it your admin API key: a key
always carries the full rights of the admin who created it, and View Only admins cannot
create keys. Instead create a local admin with the **View Only** role for UniFi Network
and set `UNIFI_USERNAME` / `UNIFI_PASSWORD`; the monitor logs in like the web UI and
reuses the session (stored with mode 600 in its state file).

```bash
python3 scripts/monitor.py --test       # send a test notification
python3 scripts/monitor.py --dry-run    # print what would be sent
# every 5 minutes with systemd (user units):
mkdir -p ~/.config/systemd/user && cp contrib/systemd/udm-monitor.* ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now udm-monitor.timer
sudo loginctl enable-linger "$USER"     # keep user timers running without a login
```

## Layout

```
SKILL.md                 # what Claude reads first: safety rules + command picker
references/
  commands.md            # full command reference
  workflows.md           # step-by-step recipes
  api-notes.md           # API layers, Network 10.x changes, quirks
scripts/
  udm.py                 # entry point
  monitor.py             # read-only alerting (ntfy push / email), for cron or systemd
  udmlib/
    config.py            # .env, settings, API key lookup
    client.py            # HTTP client: timeouts, error handling, --dry-run
    resources.py         # generic list/get/create/update(--patch)/delete/enable/disable
    util.py              # MAC parsing, JSON args, brief tables
    secrets.py           # masks secrets in output, restores them on PUT
    commands/            # one module per area: clients, devices, network, firewall,
                         # logs, stats, guests, system
contrib/systemd/         # udm-monitor.service + .timer (every 5 minutes)
tests/                   # unit tests with a fake controller (no network needed)
```

Adding a new config collection is usually one `Resource(...)` declaration in the relevant
`commands/*.py` module.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).

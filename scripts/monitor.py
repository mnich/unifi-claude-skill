#!/usr/bin/env python3
"""Read-only UniFi monitor: sends push (ntfy) and/or email alerts on changes.

Run it every few minutes from cron or a systemd timer on an always-on host. It only
reads from the controller (GET, plus the read-only system-log POST) and keeps its
own state in a small JSON file, so each problem is reported once when it starts
and once when it clears.

Checks:
  - internet (WAN / www subsystems) down or back
  - UniFi devices going offline / back online
  - gateway temperature outside MONITOR_TEMP_MIN..MONITOR_TEMP_MAX (°C)
  - site-to-site VPN tunnels dropping / reconnecting
  - new IPS threats, honeypot hits, admin logins from unexpected IPs
  - clients never seen before joining the network

Configuration (environment or the skill's .env):
  UDM_HOST                           controller address
  UNIFI_USERNAME, UNIFI_PASSWORD     preferred: a local admin with the View Only role
                                     (UniFi OS does not let View Only admins create API
                                     keys, and a key inherits its creator's full rights)
  UNIFI_API_KEY                      fallback when no username is set
  NTFY_URL                           e.g. https://ntfy.sh/<long-random-topic>
  NTFY_TOKEN                         optional access token for a protected topic
  SENDMAIL_CMD                       e.g. "msmtp -t": send email via a local MTA
  SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD   or direct SMTP (STARTTLS)
  MAIL_FROM, MAIL_TO
  MONITOR_TEMP_MIN (5), MONITOR_TEMP_MAX (75)
  MONITOR_ADMIN_IPS                  comma-separated IPs whose admin logins are expected
  MONITOR_IGNORE_DEVICES             comma-separated device MACs to skip (e.g. retired)
  MONITOR_STATE                      state file (default ~/.local/state/udm-monitor.json)

Usage:
  monitor.py            run all checks once
  monitor.py --test     send a test notification and exit
  monitor.py --dry-run  print alerts instead of sending them
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import smtplib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from udmlib.client import APIError, UDMClient  # noqa: E402
from udmlib.config import ConfigError, Settings, get_api_key, load_dotenv  # noqa: E402

PRIORITY = {"low": "2", "default": "3", "high": "4", "urgent": "5"}
EVENT_PAGES = 5  # 100 events per page; enough for a few minutes between runs


def _csv(name: str) -> set[str]:
    return {v.strip().lower() for v in os.environ.get(name, "").split(",") if v.strip()}


def _param(event: dict, key: str) -> Any:
    v = (event.get("parameters") or {}).get(key)
    return (v.get("name") or v.get("id")) if isinstance(v, dict) else v


class Monitor:
    def __init__(self, client: UDMClient, state: dict, now_ms: int):
        self.c = client
        self.state = state
        self.now_ms = now_ms
        self.alerts: list[tuple[str, str, str]] = []  # (priority, title, body)

    def alert(self, priority: str, title: str, body: str = "") -> None:
        self.alerts.append((priority, title, body))

    def flag(self, key: str, bad: bool, title_bad: str, title_ok: str,
             body: str = "", priority: str = "high") -> None:
        """Report a condition once when it starts and once when it clears."""
        flags = self.state.setdefault("flags", {})
        was = flags.get(key, False)
        if bad and not was:
            self.alert(priority, title_bad, body)
        elif was and not bad:
            self.alert("default", title_ok, body)
        flags[key] = bad

    # ── checks ──────────────────────────────────────────────────────────────

    def check_health(self) -> None:
        for s in self.c.get(self.c.legacy("stat/health")):
            sub = s.get("subsystem")
            if sub in ("wan", "www"):
                st = s.get("status")
                self.flag(f"health:{sub}", st not in ("ok", None),
                          f"Internet: {sub.upper()} status {st}",
                          f"Internet: {sub.upper()} back to ok", priority="urgent")
            elif sub == "vpn" and s.get("site_to_site_enabled"):
                active = s.get("site_to_site_num_active", 0)
                prev = self.state.get("s2s_active")
                if prev is not None and active < prev:
                    self.alert("high", "Site-to-site VPN tunnel down",
                               f"active tunnels {prev} -> {active}")
                elif prev is not None and active > prev:
                    self.alert("default", "Site-to-site VPN tunnel up",
                               f"active tunnels {prev} -> {active}")
                self.state["s2s_active"] = active

    def check_devices(self) -> None:
        ignore = _csv("MONITOR_IGNORE_DEVICES")
        tmin = float(os.environ.get("MONITOR_TEMP_MIN", "5"))
        tmax = float(os.environ.get("MONITOR_TEMP_MAX", "75"))
        for d in self.c.get(self.c.legacy("stat/device")):
            mac = (d.get("mac") or "").lower()
            if mac in ignore:
                continue
            name = d.get("name") or d.get("model") or mac
            self.flag(f"dev:{mac}", d.get("state") != 1,
                      f"Device offline: {name}", f"Device online again: {name}")
            for t in d.get("temperatures") or []:
                if t.get("type") != "cpu" or t.get("value") is None:
                    continue
                v = float(t["value"])
                self.flag(f"temp:{mac}:low", v < tmin,
                          f"{name}: temperature low ({v:.0f} °C)",
                          f"{name}: temperature back to normal ({v:.0f} °C)",
                          body=f"threshold {tmin:.0f} °C")
                self.flag(f"temp:{mac}:high", v > tmax,
                          f"{name}: temperature high ({v:.0f} °C)",
                          f"{name}: temperature back to normal ({v:.0f} °C)",
                          body=f"threshold {tmax:.0f} °C", priority="urgent")

    def check_events(self) -> None:
        since = self.state.get("last_event_ts", self.now_ms)
        admin_ips = _csv("MONITOR_ADMIN_IPS")
        newest = since
        for page in range(EVENT_PAGES):
            resp = self.c.post(self.c.v2("system-log/all"),
                               {"pageNumber": page, "pageSize": 100},
                               unwrap=False, mutating=False)
            batch = resp.get("data", []) if isinstance(resp, dict) else []
            for e in batch:
                ts = e.get("timestamp", 0)
                if ts <= since:
                    continue
                newest = max(newest, ts)
                self._event(e, admin_ips)
            if not batch or batch[-1].get("timestamp", 0) <= since:
                break
            if page + 1 >= resp.get("total_page_count", 0):
                break
        self.state["last_event_ts"] = newest

    def _event(self, e: dict, admin_ips: set[str]) -> None:
        key = e.get("key") or ""
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("timestamp", 0) / 1000))
        if key.startswith("THREAT_") or "HONEYPOT" in key:
            src, dst = _param(e, "SRC_IP"), _param(e, "DST_IP")
            self.alert("high", f"IPS: {e.get('title_raw') or key}",
                       f"{when} {src} -> {dst} (severity {e.get('severity')})")
        elif key == "ADMIN_ACCESS":
            ip = str(_param(e, "IP") or "")
            if _param(e, "ADMIN") == os.environ.get("UNIFI_USERNAME"):
                return  # the monitor's own session logins
            if admin_ips and ip.lower() not in admin_ips:
                self.alert("urgent", "Admin login from unexpected IP",
                           f"{when} {_param(e, 'ADMIN')} from {ip} ({_param(e, 'PLATFORM')})")

    def check_new_clients(self) -> None:
        known = self.state.get("known_clients")
        clients = self.c.get(self.c.legacy("stat/alluser"))
        macs = {(c.get("mac") or "").lower(): c for c in clients if c.get("mac")}
        if known is not None:
            for mac in sorted(set(macs) - set(known)):
                c = macs[mac]
                self.alert("default", "New device on the network",
                           f"{c.get('name') or c.get('hostname') or '?'} {mac} "
                           f"{c.get('oui') or ''} ip {c.get('last_ip') or c.get('ip') or '?'}")
        self.state["known_clients"] = sorted(set(macs) | set(known or []))

    def run(self) -> None:
        for check in (self.check_health, self.check_devices,
                      self.check_events, self.check_new_clients):
            try:
                check()
            except APIError as e:
                self.flag(f"err:{check.__name__}", True,
                          f"Monitor cannot read controller ({check.__name__})", "",
                          body=str(e)[:300])
                continue
            self.state.setdefault("flags", {})[f"err:{check.__name__}"] = False


# ── session login (View Only admin) ────────────────────────────────────────

def _login(host: str, user: str, password: str, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # UniFi OS ships a self-signed certificate
    req = urllib.request.Request(
        f"https://{host}/api/auth/login", method="POST",
        data=json.dumps({"username": user, "password": password,
                         "rememberMe": True}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            cookies = [c.split(";", 1)[0] for c in resp.headers.get_all("Set-Cookie") or []]
            csrf = resp.headers.get("X-Updated-CSRF-Token") or resp.headers.get("X-CSRF-Token")
    except urllib.error.HTTPError as e:
        raise APIError(f"Login as {user!r} failed: HTTP {e.code}", status=e.code) from e
    except urllib.error.URLError as e:
        raise APIError(f"Cannot reach {host}: {e.reason}") from e
    token = next((c for c in cookies if c.startswith("TOKEN=")), None)
    if not token:
        raise APIError(f"Login as {user!r} returned no session cookie")
    return {"cookie": token, "csrf": csrf or ""}


def make_client(settings: Settings, state: dict) -> UDMClient:
    user = os.environ.get("UNIFI_USERNAME")
    if not user:
        return UDMClient(settings.host, get_api_key(), settings.site, settings.timeout)
    client = UDMClient(settings.host, "", settings.site, settings.timeout)
    client.headers.pop("X-API-Key", None)

    def use(session: dict) -> None:
        client.headers["Cookie"] = session["cookie"]
        if session.get("csrf"):
            client.headers["X-CSRF-Token"] = session["csrf"]

    session = state.get("session")
    if session:  # reuse the stored session so every run is not a new admin login
        use(session)
        try:
            client.get(client.legacy("stat/health"))
            return client
        except APIError as e:
            if e.status not in (401, 403):
                raise
    password = os.environ.get("UNIFI_PASSWORD")
    if not password:
        raise ConfigError("UNIFI_USERNAME is set but UNIFI_PASSWORD is missing")
    state["session"] = _login(settings.host, user, password, settings.timeout)
    use(state["session"])
    return client


# ── delivery ────────────────────────────────────────────────────────────────

def send(alerts: list[tuple[str, str, str]], dry_run: bool) -> None:
    if not alerts:
        return
    if dry_run:
        for p, t, b in alerts:
            print(f"[{p}] {t}" + (f" — {b}" if b else ""))
        return
    ntfy = os.environ.get("NTFY_URL")
    smtp = os.environ.get("SMTP_HOST")
    sendmail = os.environ.get("SENDMAIL_CMD")
    if not (ntfy or smtp or sendmail):
        raise ConfigError("Set NTFY_URL and/or SENDMAIL_CMD / SMTP_HOST + MAIL_TO")
    if (smtp or sendmail) and not os.environ.get("MAIL_TO"):
        raise ConfigError("Email delivery is configured but MAIL_TO is missing")
    if ntfy:
        server, _, topic = ntfy.rstrip("/").rpartition("/")
        for p, t, b in alerts:
            # JSON publishing keeps non-ASCII titles intact (HTTP headers would not)
            payload = {"topic": topic, "title": t, "message": b or t,
                       "priority": int(PRIORITY.get(p, "3")),
                       "tags": ["warning"] if p in ("high", "urgent") else ["information_source"]}
            req = urllib.request.Request(server, data=json.dumps(payload).encode(),
                                         method="POST",
                                         headers={"Content-Type": "application/json"})
            if os.environ.get("NTFY_TOKEN"):
                req.add_header("Authorization", f"Bearer {os.environ['NTFY_TOKEN']}")
            urllib.request.urlopen(req, timeout=15).read()
    if smtp or sendmail:
        msg = EmailMessage()
        msg["Subject"] = alerts[0][1] if len(alerts) == 1 else f"UniFi: {len(alerts)} alerts"
        msg["From"] = os.environ.get("MAIL_FROM") or os.environ.get("SMTP_USER", "")
        msg["To"] = os.environ["MAIL_TO"]
        msg.set_content("\n\n".join(f"[{p}] {t}\n{b}".rstrip() for p, t, b in alerts))
    if sendmail:  # local MTA (e.g. "msmtp -t"): credentials stay in its own config
        subprocess.run(shlex.split(sendmail), input=msg.as_bytes(), check=True, timeout=60)
    elif smtp:
        with smtplib.SMTP(smtp, int(os.environ.get("SMTP_PORT", "587")), timeout=30) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--test", action="store_true", help="send a test notification")
    ap.add_argument("--dry-run", action="store_true", help="print alerts, do not send")
    args = ap.parse_args(argv)
    load_dotenv()
    try:
        if args.test:
            send([("default", "UniFi monitor: test", "Notifications work.")], args.dry_run)
            return 0
        settings = Settings.from_env()
        state_path = Path(os.environ.get(
            "MONITOR_STATE", Path.home() / ".local/state/udm-monitor.json")).expanduser()
        state = json.loads(state_path.read_text()) if state_path.is_file() else {}
        first_run = not state.get("known_clients")
        try:
            client = make_client(settings, state)
        except APIError as e:
            print(f"controller error: {e}", file=sys.stderr)
            return 1
        mon = Monitor(client, state, int(time.time() * 1000))
        mon.run()
        if first_run:  # baseline only: do not report everything that already exists
            mon.alerts = [("low", "UniFi monitor started",
                           "Baseline saved; you will be notified about changes.")]
        send(mon.alerts, args.dry_run)
        if not args.dry_run:  # a dry run must not consume events or change flags
            state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = state_path.with_suffix(".tmp")
            tmp.touch(mode=0o600)
            tmp.chmod(0o600)  # holds the session cookie
            tmp.write_text(json.dumps(state))
            tmp.replace(state_path)
        return 0
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError) as e:
        print(f"delivery error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

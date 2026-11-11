"""Tests for scripts/monitor.py (no network)."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from helpers import FakeController, make_client

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import monitor  # noqa: E402


def controller(cpu=40.0, state=1, events=(), clients=("aa:aa:aa:aa:aa:01",)):
    fc = FakeController()
    fc.on("GET", "stat/health", [{"subsystem": "wan", "status": "ok"},
                                 {"subsystem": "www", "status": "ok"}])
    fc.on("GET", "stat/device", [{"mac": "D0:00:00:00:00:01", "name": "GW", "state": state,
                                  "temperatures": [{"type": "cpu", "value": cpu}]}])
    fc.on("POST", "system-log/all", {"data": list(events), "total_page_count": 1},
          envelope=False)
    fc.on("GET", "stat/alluser", [{"mac": m, "name": m[-2:]} for m in clients])
    return fc


class MonitorTests(unittest.TestCase):
    def run_once(self, fc, state):

        mon = monitor.Monitor(make_client(fc), state, now_ms=2_000)
        mon.run()
        return [a[1] for a in mon.alerts]

    def test_conditions_reported_once_and_on_recovery(self):
        state = {"last_event_ts": 1_000}
        self.assertEqual(self.run_once(controller(), state), [])
        down = self.run_once(controller(state=0, cpu=90), state)
        self.assertIn("Device offline: GW", down)
        self.assertTrue(any("temperature high" in t for t in down))
        self.assertEqual(self.run_once(controller(state=0, cpu=90), state), [])
        up = self.run_once(controller(), state)
        self.assertIn("Device online again: GW", up)

    def test_new_events_and_unexpected_admin_ip(self):
        events = [
            {"timestamp": 1_500, "key": "THREAT_BLOCKED_V3", "severity": "HIGH",
             "parameters": {"SRC_IP": "1.2.3.4", "DST_IP": "10.0.0.5"}},
            {"timestamp": 1_400, "key": "ADMIN_ACCESS",
             "parameters": {"IP": "10.0.0.9", "ADMIN": "x"}},
            {"timestamp": 1_300, "key": "ADMIN_ACCESS",
             "parameters": {"IP": "10.0.0.2", "ADMIN": "x"}},
            {"timestamp": 900, "key": "THREAT_BLOCKED_V3", "parameters": {}},  # already seen
        ]
        state = {"last_event_ts": 1_000, "known_clients": ["aa:aa:aa:aa:aa:01"]}
        with mock.patch.dict(os.environ, {"MONITOR_ADMIN_IPS": "10.0.0.2"}):
            alerts = self.run_once(controller(events=events), state)
        self.assertEqual(sum("IPS" in a for a in alerts), 1)
        self.assertEqual(alerts.count("Admin login from unexpected IP"), 1)
        self.assertEqual(state["last_event_ts"], 1_500)

    def test_new_client(self):
        state = {"last_event_ts": 1_000, "known_clients": ["aa:aa:aa:aa:aa:01"]}
        alerts = self.run_once(
            controller(clients=("aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02")), state)
        self.assertEqual(alerts, ["New device on the network"])


if __name__ == "__main__":
    unittest.main()

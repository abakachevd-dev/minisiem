import os, tempfile, unittest
from datetime import datetime, timedelta
import generate_logs, minisiem as m

def ev(i, ip="1.2.3.4", action="fail", user="root", sec=1):
    return {"ts": datetime(2026, 11, 25) + timedelta(seconds=i * sec), "source": "ssh", "ip": ip,
            "user": user, "action": action, "detail": "x"}

class SiemTests(unittest.TestCase):
    def test_parse_ssh(self):
        e = list(m.parse_ssh(["Nov  5 03:12:45 web01 sshd[1]: Failed password for invalid user admin from 9.9.9.9 port 22 ssh2"]))[0]
        self.assertEqual((e["ip"], e["user"], e["action"]), ("9.9.9.9", "admin", "fail"))

    def test_parse_web_decodes_path(self):
        line = '1.1.1.1 - - [25/Nov/2026:03:12:45 +0000] "GET /a?b=1%20UNION%20SELECT HTTP/1.1" 500 10 "-" "curl"'
        self.assertIn("UNION SELECT", list(m.parse_web([line]))[0]["path"])

    def test_threshold_not_met(self):
        self.assertEqual(m.detect([ev(i) for i in range(5)]), [])

    def test_brute_force_one_alert_per_burst(self):
        alerts = m.detect([ev(i) for i in range(30)])
        self.assertEqual([a["rule"] for a in alerts], ["SSH-001"])
        self.assertEqual(alerts[0]["count"], 30)

    def test_breakin_needs_prior_failures(self):
        self.assertEqual(m.detect_breakin([ev(0, action="ok")]), [])
        evs = [ev(i) for i in range(6)] + [ev(7, action="ok")]
        self.assertEqual(m.detect_breakin(evs)[0]["severity"], "critical")

    def test_full_pipeline_finds_all_attackers_and_no_noise(self):
        with tempfile.TemporaryDirectory() as d:
            generate_logs.generate(d)
            alerts = m.detect(m.load(os.path.join(d, "auth.log"), os.path.join(d, "access.log")))
        self.assertEqual({a["rule"] for a in alerts}, {"SSH-001", "SSH-002", "SSH-003", "WEB-001", "WEB-002"})
        self.assertEqual({a["ip"] for a in alerts},
                         {"198.51.100.23", "203.0.113.45", "192.0.2.77", "198.51.100.99", "203.0.113.200"})

if __name__ == "__main__":
    unittest.main()

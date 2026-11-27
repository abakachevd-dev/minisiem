#!/usr/bin/env python3
"""MiniSIEM: parse logs, run detection rules, render an alert dashboard.

Usage: python minisiem.py --ssh logs/auth.log --web logs/access.log -o dashboard.html
"""
import argparse, html, re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

SSH_RE = re.compile(r"^(\w{3}\s+\d+ [\d:]{8}) \S+ sshd\[\d+\]: (Failed|Accepted) \w+ for (?:invalid user )?(\S+) from (\S+) port")
WEB_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
BAD_PATH = re.compile(r"(\.\./|union\s+select|<script|/etc/passwd|\$\{jndi:|;\s*(wget|curl)\b)", re.I)
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---- 1. Parsers: every log line becomes one normalized event dict ----
def parse_ssh(lines, year=2026):
    for ln in lines:
        m = SSH_RE.match(ln)
        if m:
            ts = datetime.strptime(f"{year} {' '.join(m[1].split())}", "%Y %b %d %H:%M:%S")
            fail = m[2] == "Failed"
            yield {"ts": ts, "source": "ssh", "ip": m[4], "user": m[3], "action": "fail" if fail else "ok",
                   "detail": f"{m[2]} login for {m[3]}"}


def parse_web(lines):
    for ln in lines:
        m = WEB_RE.match(ln)
        if m:
            ts = datetime.strptime(m[2], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).replace(tzinfo=None)
            yield {"ts": ts, "source": "web", "ip": m[1], "user": "", "action": m[3], "path": unquote(m[4]),
                   "status": int(m[5]), "detail": f"{m[3]} {unquote(m[4])} ({m[5]})"}


def load(ssh=None, web=None, year=2026):
    events = []
    for path, parser in ((ssh, lambda f: parse_ssh(f, year)), (web, parse_web)):
        if path:
            with open(path, errors="replace") as fh:
                events += list(parser(fh))
    return sorted(events, key=lambda e: e["ts"])


# ---- 2. Rules: declarative, Sigma-style (match + group by IP + threshold in a time window) ----
RULES = [
    dict(id="SSH-001", title="SSH brute force", mitre="T1110.001", severity="high", source="ssh",
         window=300, threshold=8, match=lambda e: e["action"] == "fail"),
    dict(id="SSH-002", title="Password spraying", mitre="T1110.003", severity="high", source="ssh",
         window=600, threshold=6, match=lambda e: e["action"] == "fail", distinct="user"),
    dict(id="WEB-001", title="Web directory scanning", mitre="T1595.002", severity="medium", source="web",
         window=120, threshold=15, match=lambda e: e["status"] == 404),
    dict(id="WEB-002", title="Web exploit attempt", mitre="T1190", severity="high", source="web",
         window=300, threshold=2, match=lambda e: bool(BAD_PATH.search(e["path"]))),
]


def run_rule(rule, events):
    groups, open_alert, alerts = defaultdict(deque), {}, []
    for e in events:
        if e["source"] != rule["source"] or not rule["match"](e):
            continue
        q = groups[e["ip"]]
        q.append(e)
        while (e["ts"] - q[0]["ts"]).total_seconds() > rule["window"]:
            q.popleft()
        n = len({x["user"] for x in q}) if rule.get("distinct") else len(q)
        if n < rule["threshold"]:
            continue
        a = open_alert.get(e["ip"])
        if a and (e["ts"] - a["last"]).total_seconds() <= rule["window"]:
            a["last"], a["count"] = e["ts"], a["count"] + 1      # same burst: extend, don't re-alert
        else:
            what = "distinct usernames" if rule.get("distinct") else "matching events"
            a = open_alert[e["ip"]] = {"rule": rule["id"], "title": rule["title"], "mitre": rule["mitre"],
                "severity": rule["severity"], "ip": e["ip"], "first": q[0]["ts"], "last": e["ts"], "count": n,
                "detail": f"{rule['threshold']}+ {what} within {rule['window']}s. Example: {e['detail'][:70]}"}
            alerts.append(a)
    return alerts


def detect_breakin(events, fails=5, window=600):
    """Correlation rule: a successful login shortly after many failures from the same IP."""
    recent, out = defaultdict(deque), []
    for e in events:
        if e["source"] != "ssh":
            continue
        q = recent[e["ip"]]
        while q and (e["ts"] - q[0]).total_seconds() > window:
            q.popleft()
        if e["action"] == "fail":
            q.append(e["ts"])
        elif len(q) >= fails:
            out.append({"rule": "SSH-003", "title": "Login succeeded after repeated failures", "mitre": "T1078",
                        "severity": "critical", "ip": e["ip"], "first": q[0], "last": e["ts"], "count": len(q) + 1,
                        "detail": f"{len(q)} failures, then a successful login as {e['user']}"})
            q.clear()
    return out


def detect(events):
    alerts = [a for r in RULES for a in run_rule(r, events)] + detect_breakin(events)
    return sorted(alerts, key=lambda a: a["first"])


# ---- 3. Dashboard ----
CSS = """
:root{--bg:#f2f5f9;--card:#fff;--ink:#14202e;--mut:#5d6b7c;--line:#dde3ea;--crit:#9b1c4a;--high:#c2362b;--medium:#b4690e;--low:#2b6cb0;color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{--bg:#0e151d;--card:#18212c;--ink:#e8edf3;--mut:#93a1b1;--line:#2b3846;--crit:#ff7fa6;--high:#f0705f;--medium:#e3a24a;--low:#6aa8ee}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px;font-size:1.6rem}h2{margin:32px 0 12px;font-size:1.1rem}
.mut,small{color:var(--mut)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.c,.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}.c b{display:block;font-size:1.7rem}
.box{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.s{border:1px solid currentColor;border-radius:10px;padding:1px 8px;font-size:.8rem;font-weight:600}.s.critical{color:var(--crit)}.s.high{color:var(--high)}.s.medium{color:var(--medium)}.s.low{color:var(--low)}
ol{padding-left:20px}li{margin-bottom:8px}
"""


def render(events, alerts):
    e = html.escape
    sev = {s: sum(a["severity"] == s for a in alerts) for s in SEV}
    lo = min(x["ts"] for x in events).replace(minute=0, second=0, microsecond=0)
    hi = max(x["ts"] for x in events)
    hrs, t = [], lo
    while t <= hi:
        hrs.append(t)
        t += timedelta(hours=1)
    cnt = defaultdict(int)
    for a in alerts:
        cnt[a["first"].replace(minute=0, second=0, microsecond=0)] += 1
    mx, w = max(cnt.values(), default=1), 720 / len(hrs)
    bars = "".join(
        f'<rect x="{i*w+2:.1f}" y="{110-max(90*cnt[h]/mx, 3):.1f}" width="{w-4:.1f}" height="{max(90*cnt[h]/mx, 3):.1f}" rx="3" '
        f'fill="var(--{"high" if cnt[h] else "line"})"><title>{h:%d %b %H:%M}: {cnt[h]} alerts</title></rect>'
        + (f'<text x="{i*w+w/2:.1f}" y="128" text-anchor="middle" font-size="10" fill="var(--mut)">{h:%H}</text>' if i % 3 == 0 else "")
        for i, h in enumerate(hrs))
    by = defaultdict(list)
    for a in alerts:
        by[a["ip"]].append(a)
    srcs = ""
    for ip, al in sorted(by.items(), key=lambda kv: (min(SEV[a["severity"]] for a in kv[1]), -len(kv[1])))[:6]:
        worst = min(al, key=lambda a: SEV[a["severity"]])["severity"]
        srcs += (f'<li><b>{e(ip)}</b> <span class="s {worst}">{worst}</span><br>'
                 f'<small>{e(", ".join(sorted({a["title"] for a in al})))}</small></li>')
    rows = "".join(
        f'<tr><td>{a["first"]:%H:%M:%S}</td><td><span class="s {a["severity"]}">{a["severity"]}</span></td>'
        f'<td>{e(a["title"])}<br><small>{a["rule"]}, ATT&amp;CK {a["mitre"]}</small></td><td>{e(a["ip"])}</td>'
        f'<td>{a["count"]}</td><td>{e(a["detail"])}</td></tr>'
        for a in sorted(alerts, key=lambda a: (SEV[a["severity"]], a["first"])))
    cards = "".join(f'<div class="c"><b>{v}</b><small>{k}</small></div>'
                    for k, v in [("events analyzed", len(events)), ("alerts", len(alerts)), *sev.items()])
    names = ", ".join(sorted({x["source"] for x in events}))
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MiniSIEM dashboard</title><style>{CSS}</style><main>
<h1>MiniSIEM dashboard</h1><p class="mut">{len(events)} events from {e(names)} logs, {lo:%d %b %Y %H:%M} to {hi:%d %b %Y %H:%M} UTC</p>
<div class="cards">{cards}</div>
<h2>Alerts per hour</h2><div class="box"><svg viewBox="0 0 720 134" width="100%" role="img" aria-label="Alerts per hour">{bars}</svg></div>
<h2>Top sources</h2><ol>{srcs}</ol>
<h2>Alerts</h2><div class="box"><table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source IP</th><th>Events</th><th>Detail</th></tr>{rows}</table></div>
</main></html>"""


def main():
    ap = argparse.ArgumentParser(description="Mini SIEM: detect attacks in SSH and web logs")
    ap.add_argument("--ssh", help="SSH auth log (syslog format)")
    ap.add_argument("--web", help="web access log (combined format)")
    ap.add_argument("--year", type=int, default=2026, help="year for syslog timestamps, which omit it")
    ap.add_argument("-o", "--output", help="write an HTML dashboard to this path")
    a = ap.parse_args()
    events = load(a.ssh, a.web, a.year)
    if not events:
        raise SystemExit("No events parsed. Check the log paths and formats.")
    alerts = detect(events)
    print(f"{len(events)} events, {len(alerts)} alerts")
    for x in alerts:
        print(f"  [{x['severity']:<8}] {x['first']:%H:%M:%S} {x['rule']} {x['title']} from {x['ip']}")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(render(events, alerts))
        print("Dashboard written to", a.output)


if __name__ == "__main__":
    main()

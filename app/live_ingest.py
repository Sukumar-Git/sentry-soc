"""Follow a live log source, normalize it to SENTRY's format, append to a file."""
import argparse
import random
import re
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "logs" / "live.log"

SSH_FAILED = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) \S+ "
    r"sshd\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)"
)
SSH_OK = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) \S+ "
    r"sshd\[\d+\]: Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)
SENTRY_LINE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ")


def _timestamp(m):
    year = datetime.now().year
    dt = datetime.strptime(
        f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
    )
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def normalize(line):
    """Return a SENTRY-format line, or None if the line isn't recognized."""
    line = line.rstrip("\n")
    if SENTRY_LINE.match(line):
        return line  # already in our format

    m = SSH_FAILED.match(line)
    if m:
        return f"{_timestamp(m)} WARNING Failed login username={m['user']} ip={m['ip']}"

    m = SSH_OK.match(line)
    if m:
        return f"{_timestamp(m)} INFO Login successful username={m['user']} ip={m['ip']}"

    return None


def follow(path, poll=1.0):
    """Yield new lines appended to `path` (like `tail -f`), surviving rotation."""
    path = Path(path)
    while not path.exists():
        time.sleep(poll)
    f = path.open("r", encoding="utf-8", errors="replace")
    f.seek(0, 2)  # start at end: only new lines
    pos = f.tell()
    while True:
        line = f.readline()
        if line:
            pos = f.tell()
            yield line
            continue
        time.sleep(poll)
        try:
            if path.stat().st_size < pos:  # truncated or rotated
                f.close()
                f = path.open("r", encoding="utf-8", errors="replace")
                pos = 0
        except FileNotFoundError:
            pass


def simulate(out_path, interval=1.0):
    """Write fake events so you can test on any OS (e.g. Windows)."""
    attackers = ["203.0.113.5", "198.51.100.23", "185.220.101.5"]
    users = ["admin", "root", "test", "ubuntu"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        roll = random.random()
        ip = random.choice(attackers)
        user = random.choice(users)
        if roll < 0.25:  # brute-force burst
            lines = [
                f"{now} WARNING Failed login username={random.choice(users)} ip={ip}"
                for _ in range(random.randint(4, 8))
            ]
        elif roll < 0.35:
            lines = [f"{now} WARNING Port scan detected ip={ip}"]
        elif roll < 0.45:
            lines = [
                f"{now} WARNING Sudo authentication failure username={user}"]
        elif roll < 0.52:
            lines = [f"{now} WARNING Account locked username={user} ip={ip}"]
        elif roll < 0.58:
            lines = [f"{now} WARNING Large outbound transfer ip=192.168.1.30"]
        elif roll < 0.65:
            lines = [
                f"{now} WARNING Connection to suspicious destination ip={ip}"]
        else:
            lines = [
                f"{now} INFO Login successful username=sukumar ip=192.168.1.10"]
        with out_path.open("a", encoding="utf-8") as out:
            out.write("\n".join(lines) + "\n")
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser(description="SENTRY live log ingestion")
    p.add_argument("--source", default="/var/log/auth.log",
                   help="log file to follow")
    p.add_argument("--out", default=str(DEFAULT_OUT),
                   help="normalized output file")
    p.add_argument("--simulate", action="store_true",
                   help="generate fake events")
    args = p.parse_args()
    out_path = Path(args.out)

    if args.simulate:
        print(f"Simulating events -> {out_path} (Ctrl+C to stop)")
        simulate(out_path)
        return

    print(f"Following {args.source} -> {out_path} (Ctrl+C to stop)")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    for raw in follow(args.source):
        norm = normalize(raw)
        if norm:
            with out_path.open("a", encoding="utf-8") as out:
                out.write(norm + "\n")


if __name__ == "__main__":
    main()

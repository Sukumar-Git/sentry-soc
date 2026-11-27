"""Low-interaction SSH honeypot: logs every connection in SENTRY's format."""
import argparse
import re
import socketserver
import threading
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "logs" / "live.log"
BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

_write_lock = threading.Lock()


def sanitize(text, limit=40):
    """Attacker-controlled text must never be able to forge log fields."""
    cleaned = re.sub(r"[^A-Za-z0-9._\-]", "_", text)[:limit]
    return cleaned or "none"


def format_event(ip, client_banner, now=None):
    now = now or datetime.now()
    return (
        f"{now:%Y-%m-%d %H:%M:%S} WARNING "
        f"Honeypot connection client={sanitize(client_banner)} ip={ip}"
    )


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        client = ""
        try:
            self.request.settimeout(5)
            self.request.sendall(BANNER)
            data = self.request.recv(256)
            client = data.decode("utf-8", errors="replace").split("\n")[0]
        except OSError:
            pass

        line = format_event(ip, client)
        with _write_lock:
            with self.server.out_path.open("a", encoding="utf-8") as out:
                out.write(line + "\n")
        print(line)


class HoneypotServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    p = argparse.ArgumentParser(description="SENTRY SSH honeypot")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--out", default=str(DEFAULT_OUT))
    args = p.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with HoneypotServer((args.host, args.port), Handler) as server:
        server.out_path = out_path
        print(
            f"Honeypot listening on {args.host}:{args.port} -> {out_path} (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()

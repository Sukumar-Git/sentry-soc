import time

from app.pipeline import run_pipeline
from app.response import notify_new_alerts

INTERVAL = 5  # seconds

if __name__ == "__main__":
    while True:
        r = run_pipeline()
        handled = notify_new_alerts(r["alerts"])
        print(
            f"[{time.strftime('%H:%M:%S')}] events={len(r['events'])} "
            f"alerts={len(r['alerts'])} correlations={len(r['correlations'])} "
            f"incidents={len(r['incidents'])} notified={len(handled)}"
        )
        time.sleep(INTERVAL)

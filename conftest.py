import os

for name in (
    "SENTRY_LOG_FILE",
    "ABUSEIPDB_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
):
    os.environ.pop(name, None)

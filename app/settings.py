from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "keys"

try:
    from app.local import (
        API_KEY,
        DEBUG,
        DEFAULT_DOMAIN,
        DEFAULT_FROM,
        DKIM_PRIVATE_KEY,
        DKIM_SELECTOR,
        HELO_HOSTNAME,
        SMTP_HOST,
        SMTP_PASSWORD,
        SMTP_PORT,
        SMTP_TIMEOUT,
        SMTP_USERNAME,
    )
except ImportError:
    DEBUG = True
    API_KEY = "aerogram-dev-key"
    DEFAULT_DOMAIN = "lucianmarin.com"
    DEFAULT_FROM = f"noreply@{DEFAULT_DOMAIN}"
    HELO_HOSTNAME = f"mail.{DEFAULT_DOMAIN}"
    DKIM_SELECTOR = "default"
    DKIM_PRIVATE_KEY = str(KEYS_DIR / "dkim.private.pem")
    SMTP_HOST = "127.0.0.1"
    SMTP_PORT = 8025
    SMTP_USERNAME = "aerogram"
    SMTP_PASSWORD = API_KEY
    SMTP_TIMEOUT = 15

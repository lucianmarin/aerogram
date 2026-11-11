# Aerogram

Stateless send mail server written in Python with **FastAPI**, **aiosmtpd**, **dkimpy**, and **dnspython**.

Aerogram signs outgoing messages with **DKIM** and delivers them directly to recipient **MX** servers over SMTP with opportunistic `STARTTLS`, without needing an external relay or database. It exposes both an **HTTP JSON API** and a local **SMTP submission server**.

## Specs & Architecture

- **Framework**: FastAPI + Uvicorn (HTTP API over Unix domain socket `aero.socket` or `127.0.0.1:8000` in development)
- **SMTP Submission**: `aiosmtpd` controller listening on `127.0.0.1:8025` with `AUTH PLAIN` / `AUTH LOGIN` support
- **Direct MX Delivery**: Resolves recipient MX records via `dnspython` in priority order and delivers via `smtplib` with opportunistic `STARTTLS`
- **DKIM Signing**: Automatically generates a 2048-bit RSA keypair (`keys/dkim.private.pem`) and signs `From`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, and `Content-Type` headers using `dkimpy`
- **DNS Verification**: Built-in CLI and HTTP endpoints to inspect **MX**, **SPF**, **DKIM**, and **DMARC** records for any domain
- **Stateless**: Zero database overhead; messages are constructed, signed, and delivered in-flight

## DNS Requirements (MX, SPF, DKIM, DMARC)

Before sending mail in production from `mail.lucianmarin.com` (for `lucianmarin.com`), configure the following DNS records:

1. **A & PTR (Reverse DNS)**:
   - `mail.lucianmarin.com` -> `A` record pointing to your server IP
   - Server IP -> `PTR` record pointing to `mail.lucianmarin.com`

2. **MX (`MX` on `@` / `lucianmarin.com`)**:
   ```text
   10 mail.lucianmarin.com.
   ```

3. **SPF (`TXT` on `@` / `lucianmarin.com`)**:
   ```text
   v=spf1 mx a:mail.lucianmarin.com -all
   ```

4. **DKIM (`TXT` on `default._domainkey.lucianmarin.com`)**:
   Generate your keypair and print the DNS TXT value:
   ```bash
   python3 main.py dkim lucianmarin.com default
   ```
   Publish the output value (`v=DKIM1; k=rsa; p=MIIBIjANBg...`) as a `TXT` record.

5. **DMARC (`TXT` on `_dmarc.lucianmarin.com`)**:
   ```text
   v=DMARC1; p=quarantine; rua=mailto:postmaster@lucianmarin.com
   ```

## Install & Setup

1. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure `app/local.py`:**
   ```python
   DEBUG = False
   API_KEY = "your-secret-api-key"
   DEFAULT_DOMAIN = "lucianmarin.com"
   DEFAULT_FROM = "noreply@lucianmarin.com"
   HELO_HOSTNAME = "mail.lucianmarin.com"
   DKIM_SELECTOR = "default"
   DKIM_PRIVATE_KEY = "keys/dkim.private.pem"
   SMTP_HOST = "127.0.0.1"
   SMTP_PORT = 8025
   SMTP_USERNAME = "aerogram"
   SMTP_PASSWORD = API_KEY
   SMTP_TIMEOUT = 15
   ```

3. **Generate DKIM keys and verify DNS:**
   ```bash
   python3 main.py dkim
   python3 main.py dns
   ```

4. **Run the server:**
   ```bash
   python3 main.py
   ```

## Usage

### 1. HTTP JSON API

**Send an email (`POST /api/send`):**
```bash
curl -X POST https://mail.lucianmarin.com/api/send \
  -H "X-API-Key: your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "Subreply <noreply@subreply.com>",
    "to": "user@example.com",
    "subject": "Account recovery",
    "text": "Recover your account at https://subreply.com/recover/token"
  }'
```

**Other Routes:**
- `GET /` — Server status, HELO hostname, DKIM readiness, and SMTP submission address
- `GET /api/dns?domain=lucianmarin.com&selector=default` — Verify MX, SPF, DKIM, and DMARC records
- `GET /api/mx/{domain}` — Resolve prioritized MX servers for a recipient domain
- `POST /api/dkim` — Regenerate DKIM RSA keypair and return the public DNS TXT record (requires API key)

### 2. SMTP Submission (`127.0.0.1:8025`)

Any local service (e.g. `subreply`) can submit email over standard SMTP:

```python
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = "noreply@subreply.com"
msg["To"] = "user@example.com"
msg["Subject"] = "Recovery link"
msg.set_content("Send https://subreply.com/recover/token")

with smtplib.SMTP("127.0.0.1", 8025) as smtp:
    smtp.send_message(msg)
```

## Production Deployment

- **systemd**: `aero.service` runs Uvicorn bound to `/home/lucian/aerogram/aero.socket`
- **Nginx**: `aero.conf` proxies HTTPS traffic for `mail.lucianmarin.com` to `unix:/home/lucian/aerogram/aero.socket`

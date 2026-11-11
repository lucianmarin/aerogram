import asyncio
import sys
from contextlib import asynccontextmanager
from hmac import compare_digest
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.dkim import generate_dkim_keys, load_private_key, query_mx, verify_domain_dns
from app.mailer import send_email_async
from app.settings import (
    API_KEY,
    DEFAULT_DOMAIN,
    DEFAULT_FROM,
    DKIM_PRIVATE_KEY,
    DKIM_SELECTOR,
    HELO_HOSTNAME,
    SMTP_HOST,
    SMTP_PORT,
)
from app.smtp import SMTPSubmissionServer

smtp_server = SMTPSubmissionServer(host=SMTP_HOST, port=SMTP_PORT)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not Path(DKIM_PRIVATE_KEY).exists():
        generate_dkim_keys(
            private_key_path=DKIM_PRIVATE_KEY,
            selector=DKIM_SELECTOR,
            domain=DEFAULT_DOMAIN,
        )
    smtp_server.start()
    try:
        yield
    finally:
        smtp_server.stop()


app = FastAPI(
    title="Aerogram",
    description="Stateless send mail server written in Python with DKIM signing, direct MX delivery, and SMTP submission.",
    version="1.0.0",
    lifespan=lifespan,
)


class SendEmailRequest(BaseModel):
    to: str | list[str] = Field(..., description="Recipient email address or list of addresses")
    subject: str = Field(..., min_length=1, max_length=998, description="Email subject line")
    text: str = Field(default="", description="Plain text message body")
    html: str = Field(default="", description="HTML message body")
    from_addr: str = Field(default=DEFAULT_FROM, alias="from", description="Sender email address")
    reply_to: str = Field(default="", description="Reply-To email address")
    headers: dict[str, str] = Field(default_factory=dict, description="Additional custom RFC 5322 headers")

    model_config = {"populate_by_name": True}


class DKIMGenerateRequest(BaseModel):
    domain: str = Field(default=DEFAULT_DOMAIN)
    selector: str = Field(default=DKIM_SELECTOR)


def verify_api_key(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
):
    token = ""
    if x_api_key:
        token = x_api_key.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    if not token or not compare_digest(token, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@app.get("/")
async def status_resource():
    return {
        "service": "aerogram",
        "status": "ok",
        "domain": DEFAULT_DOMAIN,
        "helo": HELO_HOSTNAME,
        "dkim_selector": DKIM_SELECTOR,
        "dkim_ready": load_private_key() is not None,
        "smtp_submission": f"{SMTP_HOST}:{SMTP_PORT}",
    }


@app.get("/api/dns")
async def dns_check_resource(domain: str = DEFAULT_DOMAIN, selector: str = DKIM_SELECTOR):
    return await asyncio.to_thread(verify_domain_dns, domain, selector)


@app.get("/api/mx/{domain}")
async def mx_lookup_resource(domain: str):
    records = await asyncio.to_thread(query_mx, domain)
    return {
        "domain": domain,
        "mx": [{"priority": pref, "host": host} for pref, host in records],
    }


@app.post("/api/dkim", dependencies=[Depends(verify_api_key)])
async def generate_dkim_resource(payload: DKIMGenerateRequest):
    return await asyncio.to_thread(
        generate_dkim_keys,
        private_key_path=DKIM_PRIVATE_KEY,
        selector=payload.selector,
        domain=payload.domain,
    )


@app.post("/api/send", dependencies=[Depends(verify_api_key)])
async def send_email_resource(payload: SendEmailRequest):
    try:
        return await send_email_async(
            to_addr=payload.to,
            subject=payload.subject,
            text=payload.text,
            html=payload.html,
            from_addr=payload.from_addr,
            reply_to=payload.reply_to,
            headers=payload.headers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "dkim":
        domain = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DOMAIN
        selector = sys.argv[3] if len(sys.argv) > 3 else DKIM_SELECTOR
        info = generate_dkim_keys(selector=selector, domain=domain)
        print(f"Private key saved to: {info['private_key_path']}")
        print(f"Public key saved to:  {info['public_key_path']}")
        print(f"\nPublish this DNS TXT record at {info['dns_name']}:\n{info['dns_value']}")
    elif len(sys.argv) > 1 and sys.argv[1] == "dns":
        domain = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DOMAIN
        selector = sys.argv[3] if len(sys.argv) > 3 else DKIM_SELECTOR
        import json
        print(json.dumps(verify_domain_dns(domain, selector), indent=2))
    else:
        import uvicorn
        uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

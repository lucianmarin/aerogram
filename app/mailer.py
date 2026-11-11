import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import formatdate, make_msgid, parseaddr

from app.dkim import query_mx, sign_message
from app.settings import (
    DEFAULT_DOMAIN,
    DEFAULT_FROM,
    DKIM_SELECTOR,
    HELO_HOSTNAME,
    SMTP_TIMEOUT,
)


def extract_domain(address: str) -> str:
    _, email_addr = parseaddr(address)
    if "@" not in email_addr:
        raise ValueError(f"Invalid email address: {address}")
    return email_addr.rsplit("@", 1)[1].lower()


def build_message(
    to_addr: str | list[str],
    subject: str,
    text: str = "",
    html: str = "",
    from_addr: str = DEFAULT_FROM,
    reply_to: str = "",
    headers: dict[str, str] | None = None,
) -> tuple[bytes, str, str, list[str]]:
    """Construct an RFC 5322 email message, sign with DKIM if key is present, and return raw bytes."""
    recipients = [to_addr] if isinstance(to_addr, str) else list(to_addr)
    if not recipients:
        raise ValueError("At least one recipient is required")
    if not text and not html:
        raise ValueError("Email must include text or html body")

    _, sender_email = parseaddr(from_addr)
    sender_domain = extract_domain(sender_email or DEFAULT_FROM)
    msg_id = make_msgid(domain=sender_domain)

    msg = EmailMessage(policy=SMTP_POLICY)
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = msg_id

    if reply_to:
        msg["Reply-To"] = reply_to

    if headers:
        for key, value in headers.items():
            msg[key] = value

    if text and html:
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
    elif html:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content(text)

    raw_bytes = msg.as_bytes()
    signed_bytes = sign_message(
        raw_bytes,
        domain=sender_domain,
        selector=DKIM_SELECTOR,
    )
    return signed_bytes, msg_id, sender_email, recipients


def deliver_to_domain(
    sender: str,
    recipients: list[str],
    domain: str,
    raw_message: bytes,
    helo_hostname: str = HELO_HOSTNAME,
    timeout: int = SMTP_TIMEOUT,
) -> dict:
    """Deliver a raw RFC 5322 message directly to a recipient domain's MX servers."""
    mx_hosts = query_mx(domain)
    if not mx_hosts:
        raise RuntimeError(f"No MX records found for domain '{domain}'")

    last_error = None
    tls_context = ssl.create_default_context()

    for priority, mx_host in mx_hosts:
        try:
            with smtplib.SMTP(mx_host, 25, local_hostname=helo_hostname, timeout=timeout) as smtp:
                smtp.ehlo(helo_hostname)
                if smtp.has_extn("starttls"):
                    try:
                        smtp.starttls(context=tls_context)
                        smtp.ehlo(helo_hostname)
                    except smtplib.SMTPException:
                        # Fall back to Opportunistic TLS behavior if peer TLS fails
                        pass
                refused = smtp.sendmail(sender, recipients, raw_message)
                return {
                    "domain": domain,
                    "mx_host": mx_host,
                    "priority": priority,
                    "delivered": True,
                    "refused": refused,
                }
        except Exception as exc:
            last_error = str(exc)

    raise RuntimeError(f"Delivery to {domain} failed across all MX servers: {last_error}")


def send_raw_email(
    sender: str,
    recipients: list[str],
    raw_message: bytes,
    sign_dkim: bool = True,
) -> list[dict]:
    """Group recipients by domain, optionally DKIM-sign, and deliver via MX servers."""
    if sign_dkim and b"DKIM-Signature:" not in raw_message[:2048]:
        try:
            sender_domain = extract_domain(sender)
        except ValueError:
            sender_domain = DEFAULT_DOMAIN
        raw_message = sign_message(raw_message, domain=sender_domain, selector=DKIM_SELECTOR)

    by_domain: dict[str, list[str]] = {}
    for rcpt in recipients:
        _, clean_rcpt = parseaddr(rcpt)
        target = clean_rcpt or rcpt
        domain = extract_domain(target)
        by_domain.setdefault(domain, []).append(target)

    results = []
    for domain, domain_recipients in by_domain.items():
        res = deliver_to_domain(
            sender=parseaddr(sender)[1] or sender,
            recipients=domain_recipients,
            domain=domain,
            raw_message=raw_message,
        )
        results.append(res)
    return results


async def send_email_async(
    to_addr: str | list[str],
    subject: str,
    text: str = "",
    html: str = "",
    from_addr: str = DEFAULT_FROM,
    reply_to: str = "",
    headers: dict[str, str] | None = None,
) -> dict:
    """Build, DKIM-sign, and deliver an email asynchronously in a worker thread."""
    signed_bytes, msg_id, sender_email, recipients = build_message(
        to_addr=to_addr,
        subject=subject,
        text=text,
        html=html,
        from_addr=from_addr,
        reply_to=reply_to,
        headers=headers,
    )
    deliveries = await asyncio.to_thread(
        send_raw_email,
        sender=sender_email,
        recipients=recipients,
        raw_message=signed_bytes,
        sign_dkim=False,
    )
    return {
        "message_id": msg_id,
        "from": sender_email,
        "to": recipients,
        "dkim_signed": b"DKIM-Signature:" in signed_bytes[:2048],
        "deliveries": deliveries,
    }

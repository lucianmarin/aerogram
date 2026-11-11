from base64 import b64encode
from pathlib import Path

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Timeout, resolve

from app.settings import DEFAULT_DOMAIN, DKIM_PRIVATE_KEY, DKIM_SELECTOR, KEYS_DIR


def generate_dkim_keys(
    private_key_path: Path | str = DKIM_PRIVATE_KEY,
    selector: str = DKIM_SELECTOR,
    domain: str = DEFAULT_DOMAIN,
    key_size: int = 2048,
) -> dict:
    """Generate an RSA keypair for DKIM signing and return DNS record details."""
    priv_path = Path(private_key_path)
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path = priv_path.with_suffix(".public.pem")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    priv_path.chmod(0o600)
    pub_path.write_bytes(pub_pem)

    pub_b64 = b64encode(pub_der).decode("ascii")
    dns_name = f"{selector}._domainkey.{domain}"
    dns_value = f"v=DKIM1; k=rsa; p={pub_b64}"

    return {
        "private_key_path": str(priv_path),
        "public_key_path": str(pub_path),
        "selector": selector,
        "domain": domain,
        "dns_name": dns_name,
        "dns_value": dns_value,
    }


def load_private_key(private_key_path: Path | str = DKIM_PRIVATE_KEY) -> bytes | None:
    path = Path(private_key_path)
    if path.is_file():
        return path.read_bytes()
    return None


def sign_message(
    raw_message: bytes,
    domain: str = DEFAULT_DOMAIN,
    selector: str = DKIM_SELECTOR,
    private_key: bytes | None = None,
) -> bytes:
    """Sign an RFC 5322 email byte string with DKIM and prepend the DKIM-Signature header."""
    key_bytes = private_key or load_private_key()
    if not key_bytes:
        return raw_message

    # Normalize LF to CRLF as required by RFC 6376 / dkimpy
    normalized = raw_message.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    include_headers = [b"From", b"To", b"Subject", b"Date", b"Message-ID", b"MIME-Version", b"Content-Type"]
    signature = dkim.sign(
        message=normalized,
        selector=selector.encode("ascii"),
        domain=domain.encode("ascii"),
        privkey=key_bytes,
        include_headers=include_headers,
    )
    return signature + normalized


def query_txt(name: str) -> list[str]:
    try:
        answers = resolve(name, "TXT")
        records = []
        for rdata in answers:
            txt = "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            records.append(txt)
        return records
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout, Exception):
        return []


def query_mx(domain: str) -> list[tuple[int, str]]:
    """Resolve MX records sorted by priority (lowest preference number first)."""
    try:
        answers = resolve(domain, "MX")
        hosts = [
            (int(rdata.preference), str(rdata.exchange).rstrip("."))
            for rdata in answers
        ]
        return sorted(hosts, key=lambda item: item[0])
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout, Exception):
        return []


def verify_domain_dns(domain: str = DEFAULT_DOMAIN, selector: str = DKIM_SELECTOR) -> dict:
    """Check MX, SPF, DKIM, and DMARC DNS records for a domain."""
    mx_records = query_mx(domain)
    root_txt = query_txt(domain)
    spf_records = [r for r in root_txt if r.lower().startswith("v=spf1")]

    dkim_name = f"{selector}._domainkey.{domain}"
    dkim_txt = query_txt(dkim_name)
    dkim_records = [r for r in dkim_txt if "v=dkim1" in r.lower() or "p=" in r.lower()]

    dmarc_name = f"_dmarc.{domain}"
    dmarc_txt = query_txt(dmarc_name)
    dmarc_records = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]

    return {
        "domain": domain,
        "selector": selector,
        "mx": {
            "configured": bool(mx_records),
            "records": [{"priority": pref, "host": host} for pref, host in mx_records],
            "recommended": f"10 mail.{domain}.",
        },
        "spf": {
            "configured": bool(spf_records),
            "records": spf_records,
            "recommended": f"v=spf1 mx a:{f'mail.{domain}'} -all",
        },
        "dkim": {
            "configured": bool(dkim_records),
            "name": dkim_name,
            "records": dkim_records,
        },
        "dmarc": {
            "configured": bool(dmarc_records),
            "name": dmarc_name,
            "records": dmarc_records,
            "recommended": f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}",
        },
        "ready": bool(mx_records and spf_records and dkim_records and dmarc_records),
    }

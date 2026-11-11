import smtplib
import unittest
from email.message import EmailMessage
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import dkim
from fastapi.testclient import TestClient

from app.dkim import generate_dkim_keys, sign_message, verify_domain_dns
from app.mailer import build_message, send_raw_email
from app.settings import API_KEY
from main import app


class AerogramTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.priv_path = Path(self.tmpdir.name) / "dkim.private.pem"
        self.key_info = generate_dkim_keys(
            private_key_path=self.priv_path,
            selector="default",
            domain="lucianmarin.com",
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_dkim_generation_and_signing(self):
        raw, msg_id, sender, rcpts = build_message(
            to_addr="user@example.com",
            subject="Hello",
            text="Plain text body",
            html="<p>HTML body</p>",
            from_addr="Lucian <noreply@lucianmarin.com>",
        )
        signed = sign_message(
            raw,
            domain="lucianmarin.com",
            selector="default",
            private_key=self.priv_path.read_bytes(),
        )
        self.assertIn(b"DKIM-Signature:", signed)
        self.assertIn("v=DKIM1; k=rsa; p=", self.key_info["dns_value"])

        # Verify cryptographic DKIM signature using our generated public DNS record
        dns_txt = self.key_info["dns_value"].encode("ascii")
        is_valid = dkim.verify(signed, dnsfunc=lambda name, **kw: dns_txt)
        self.assertTrue(is_valid)

    @patch("app.mailer.query_mx", return_value=[(10, "mx1.example.com")])
    @patch("app.mailer.smtplib.SMTP")
    def test_http_api_send_and_auth(self, mock_smtp_cls, mock_mx):
        smtp_instance = MagicMock()
        smtp_instance.has_extn.return_value = True
        smtp_instance.sendmail.return_value = {}
        mock_smtp_cls.return_value.__enter__.return_value = smtp_instance

        with TestClient(app) as client:
            # Status endpoint
            status_resp = client.get("/")
            self.assertEqual(status_resp.status_code, 200)
            self.assertEqual(status_resp.json()["service"], "aerogram")

            # Unauthorized request
            unauth_resp = client.post(
                "/api/send",
                json={"to": "user@example.com", "subject": "Test", "text": "Hello"},
            )
            self.assertEqual(unauth_resp.status_code, 401)

            # Authorized request
            send_resp = client.post(
                "/api/send",
                headers={"X-API-Key": API_KEY},
                json={
                    "from": "Subreply <noreply@subreply.com>",
                    "to": ["user@example.com"],
                    "subject": "Account recovery",
                    "text": "Recover at https://subreply.com/recover/token",
                },
            )
            self.assertEqual(send_resp.status_code, 200)
            data = send_resp.json()
            self.assertTrue(data["dkim_signed"])
            self.assertEqual(data["deliveries"][0]["mx_host"], "mx1.example.com")
            smtp_instance.sendmail.assert_called_once()

    @patch("app.mailer.query_mx", return_value=[(10, "mx.example.com")])
    @patch("app.mailer.deliver_to_domain")
    def test_smtp_submission_server(self, mock_deliver, mock_mx):
        mock_deliver.return_value = {
            "domain": "example.com",
            "mx_host": "mx.example.com",
            "priority": 10,
            "delivered": True,
            "refused": {},
        }

        with TestClient(app):
            msg = EmailMessage()
            msg["From"] = "noreply@subreply.com"
            msg["To"] = "reader@example.com"
            msg["Subject"] = "SMTP Submission Test"
            msg.set_content("Hello via aiosmtpd submission")

            with smtplib.SMTP("127.0.0.1", 8025, timeout=5) as client:
                client.send_message(msg)

            mock_deliver.assert_called_once()
            sent_bytes = mock_deliver.call_args.kwargs["raw_message"]
            self.assertIn(b"DKIM-Signature:", sent_bytes)

    @patch("app.dkim.query_mx", return_value=[(10, "mail.lucianmarin.com")])
    @patch("app.dkim.query_txt")
    def test_verify_domain_dns(self, mock_txt, mock_mx):
        def fake_txt(name):
            if name == "lucianmarin.com":
                return ["v=spf1 mx a:mail.lucianmarin.com -all"]
            if name == "default._domainkey.lucianmarin.com":
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"]
            if name == "_dmarc.lucianmarin.com":
                return ["v=DMARC1; p=quarantine; rua=mailto:postmaster@lucianmarin.com"]
            return []

        mock_txt.side_effect = fake_txt
        report = verify_domain_dns("lucianmarin.com", "default")
        self.assertTrue(report["ready"])
        self.assertTrue(report["mx"]["configured"])
        self.assertTrue(report["spf"]["configured"])
        self.assertTrue(report["dkim"]["configured"])
        self.assertTrue(report["dmarc"]["configured"])


if __name__ == "__main__":
    unittest.main()

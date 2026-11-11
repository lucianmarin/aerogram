import asyncio
from hmac import compare_digest

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from app.mailer import send_raw_email
from app.settings import SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME


class SubmissionAuthenticator:
    """Authenticate local/client SMTP submissions via AUTH PLAIN / LOGIN."""

    def __call__(self, server, session, envelope, mechanism, auth_data):
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in ("LOGIN", "PLAIN"):
            return fail_nothandled
        if not isinstance(auth_data, LoginPassword):
            return fail_nothandled

        username = auth_data.login.decode("utf-8", errors="replace")
        password = auth_data.password.decode("utf-8", errors="replace")

        if compare_digest(username, SMTP_USERNAME) and compare_digest(password, SMTP_PASSWORD):
            return AuthResult(success=True)
        return fail_nothandled


class SubmissionHandler:
    """Receive outbound messages via SMTP submission, DKIM-sign, and relay to MX."""

    async def handle_DATA(self, server, session, envelope):
        peer_ip = session.peer[0] if session.peer else ""
        is_localhost = peer_ip in ("127.0.0.1", "::1", "localhost")

        if not is_localhost and not session.authenticated:
            return "530 5.7.0 Authentication required"

        try:
            await asyncio.to_thread(
                send_raw_email,
                sender=envelope.mail_from,
                recipients=list(envelope.rcpt_tos),
                raw_message=envelope.original_content or envelope.content,
                sign_dkim=True,
            )
            return "250 2.0.0 Message accepted for delivery"
        except ValueError as exc:
            return f"550 5.1.3 {exc}"
        except Exception as exc:
            return f"451 4.4.1 Outbound delivery failed: {exc}"


class SMTPSubmissionServer:
    def __init__(self, host: str = SMTP_HOST, port: int = SMTP_PORT):
        self.host = host
        self.port = port
        self.controller: Controller | None = None

    def start(self):
        if self.port <= 0:
            return
        self.controller = Controller(
            SubmissionHandler(),
            hostname=self.host,
            port=self.port,
            authenticator=SubmissionAuthenticator(),
            auth_required=False,
            auth_require_tls=False,
        )
        self.controller.start()

    def stop(self):
        if self.controller is not None:
            self.controller.stop()
            self.controller = None

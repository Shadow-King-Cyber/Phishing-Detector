"""Email (.eml) parser extracting headers, links, and attachments."""

import re
import email
import email.policy
from email import policy
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


@dataclass
class AuthHeaders:
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    spf_pass: bool | None = None
    dkim_pass: bool | None = None
    dmarc_pass: bool | None = None

    def to_dict(self) -> dict:
        return {
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "spf_pass": self.spf_pass,
            "dkim_pass": self.dkim_pass,
            "dmarc_pass": self.dmarc_pass,
        }


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    date: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    auth: AuthHeaders = field(default_factory=AuthHeaders)
    headers_raw: dict = field(default_factory=dict)
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "from": self.from_addr,
            "to": self.to_addr,
            "date": self.date,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "message_id": self.message_id,
            "auth": self.auth.to_dict(),
            "links": self.links,
            "attachments": [
                {"filename": a["filename"], "content_type": a["content_type"]}
                for a in self.attachments
            ],
            "has_html": bool(self.body_html),
            "body_length": len(self.body_text),
        }


class EmailParser:
    """Parse .eml files and extract security-relevant features."""

    URL_PATTERN = re.compile(
        r"https?://[^\s<>\"')\]]+|"
        r"www\.[^\s<>\"')\]]+",
        re.IGNORECASE,
    )

    def parse(self, source: str | Path | BinaryIO) -> ParsedEmail:
        if isinstance(source, (str, Path)):
            with open(source, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
        else:
            msg = email.message_from_binary_file(source, policy=policy.default)

        result = ParsedEmail()
        result.subject = msg.get("subject", "")
        result.from_addr = msg.get("from", "")
        result.to_addr = msg.get("to", "")
        result.date = msg.get("date", "")
        result.reply_to = msg.get("reply-to", "")
        result.return_path = msg.get("return-path", "")
        result.message_id = msg.get("message-id", "")

        for key in msg.keys():
            result.headers_raw[key] = msg.get(key, "")

        result.auth = self._extract_auth_headers(result.headers_raw)
        result.links = self._extract_links(msg)
        result.attachments = self._extract_attachments(msg)
        result.body_text, result.body_html = self._extract_body(msg)

        return result

    def _extract_auth_headers(self, headers: dict) -> AuthHeaders:
        auth = AuthHeaders()
        received_spf = headers.get("Received-SPF", "")
        auth_results = headers.get("Authentication-Results", "")
        dkim_header = headers.get("DKIM-Signature", "")

        auth.spf = received_spf or self._extract_from_auth_results(
            auth_results, "spf"
        )
        auth.dkim = self._extract_from_auth_results(auth_results, "dkim") or (
            "present" if dkim_header else ""
        )
        auth.dmarc = self._extract_from_auth_results(auth_results, "dmarc")

        auth.spf_pass = self._parse_pass_fail(auth.spf)
        auth.dkim_pass = self._parse_pass_fail(auth.dkim)
        auth.dmarc_pass = self._parse_pass_fail(auth.dmarc)

        return auth

    def _extract_from_auth_results(self, auth_results: str, mechanism: str) -> str:
        if not auth_results:
            return ""
        match = re.search(
            rf"{mechanism}=(\S+)", auth_results, re.IGNORECASE
        )
        return match.group(1) if match else ""

    def _parse_pass_fail(self, value: str) -> bool | None:
        lower = value.lower()
        if "pass" in lower:
            return True
        if "fail" in lower or "softfail" in lower or "none" in lower:
            return False
        return None

    def _extract_links(self, msg: email.message.Message) -> list[str]:
        links = set()

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/html", "text/plain"):
                    payload = part.get_content()
                    links.update(self.URL_PATTERN.findall(payload))
        else:
            payload = msg.get_content()
            links.update(self.URL_PATTERN.findall(payload))

        return sorted(links)

    def _extract_attachments(self, msg: email.message.Message) -> list[dict]:
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    attachments.append(
                        {
                            "filename": part.get_filename() or "unknown",
                            "content_type": part.get_content_type(),
                            "size": len(part.get_payload(decode=True) or b""),
                        }
                    )
        return attachments

    def _extract_body(self, msg: email.message.Message) -> tuple[str, str]:
        text_body = ""
        html_body = ""

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain" and not text_body:
                    text_body = part.get_content()
                elif ctype == "text/html" and not html_body:
                    html_body = part.get_content()
        else:
            ctype = msg.get_content_type()
            content = msg.get_content()
            if ctype == "text/html":
                html_body = content
            else:
                text_body = content

        return text_body, html_body

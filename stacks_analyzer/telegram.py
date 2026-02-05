import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = chat_id

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, text: str, parse_mode: Optional[str] = None) -> bool:
        if not self.enabled:
            return False

        endpoint = "https://api.telegram.org/bot%s/sendMessage" % self.token
        payload = {"chat_id": self.chat_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode

        data = urllib.parse.urlencode(payload).encode("utf-8")
        request = urllib.request.Request(endpoint, data=data, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(body)
            return bool(parsed.get("ok"))
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
            return False

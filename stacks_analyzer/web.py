import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse
from urllib.parse import parse_qs

STATIC_DIR = Path(__file__).with_name("static")


def _load_static_html(filename: str) -> str:
    path = STATIC_DIR / filename
    return path.read_text(encoding="utf-8")


DASHBOARD_HTML = _load_static_html("dashboard.html")
REPORT_HTML = _load_static_html("report.html")


def build_handler(
    state_provider: Callable[[], Dict[str, Any]],
    history_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    schema_provider: Optional[Callable[[], Dict[str, Any]]] = None,
    alerts_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    reports_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    report_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    report_logs_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    sql_provider: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
) -> type:
    class DashboardHandler(BaseHTTPRequestHandler):
        def _send_bytes(
            self, payload: bytes, content_type: str, status: int = 200
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path.startswith("/static/"):
                filename = parsed.path.split("/static/", 1)[1]
                if not filename or "/" in filename or "\\" in filename:
                    self._send_bytes(
                        b"not found\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                path = STATIC_DIR / filename
                if not path.exists() or not path.is_file():
                    self._send_bytes(
                        b"not found\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                if path.suffix == ".css":
                    content_type = "text/css; charset=utf-8"
                elif path.suffix == ".js":
                    content_type = "application/javascript; charset=utf-8"
                elif path.suffix == ".html":
                    content_type = "text/html; charset=utf-8"
                else:
                    self._send_bytes(
                        b"not found\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                self._send_bytes(path.read_bytes(), content_type)
                return
            if parsed.path == "/":
                self._send_bytes(DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if parsed.path == "/api/state":
                payload = json.dumps(state_provider(), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/history":
                if history_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(history_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/schema":
                if schema_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                payload = json.dumps(schema_provider(), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/alerts":
                if alerts_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(alerts_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/reports":
                if reports_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(reports_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/report":
                if report_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(report_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/report-logs":
                if report_logs_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = report_logs_provider(params)
                status = int(payload.get("status", 200))
                filename = payload.get("filename")
                content = payload.get("content", "")
                if not isinstance(content, (bytes, bytearray)):
                    content = str(content).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                if filename:
                    self.send_header(
                        "Content-Disposition",
                        "attachment; filename=\"%s\"" % filename,
                    )
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            if parsed.path == "/report":
                if report_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                self._send_bytes(REPORT_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if parsed.path == "/healthz":
                self._send_bytes(b"ok\n", "text/plain; charset=utf-8")
                return
            self._send_bytes(b"not found\n", "text/plain; charset=utf-8", status=404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/api/sql":
                self._send_bytes(b"not found\n", "text/plain; charset=utf-8", status=404)
                return
            if sql_provider is None:
                self._send_bytes(b"sql api disabled\n", "text/plain; charset=utf-8", status=404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                self._send_bytes(b"bad request\n", "text/plain; charset=utf-8", status=400)
                return
            response = sql_provider(payload)
            data = json.dumps(response, sort_keys=True).encode("utf-8")
            self._send_bytes(data, "application/json; charset=utf-8")

        def log_message(self, format: str, *args: object) -> None:
            _ = (format, args)

    return DashboardHandler


class DashboardServer:
    def __init__(
        self,
        host: str,
        port: int,
        state_provider: Callable[[], Dict[str, Any]],
        history_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        schema_provider: Optional[Callable[[], Dict[str, Any]]] = None,
        alerts_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        reports_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        report_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        report_logs_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        sql_provider: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.state_provider = state_provider
        self.history_provider = history_provider
        self.schema_provider = schema_provider
        self.alerts_provider = alerts_provider
        self.reports_provider = reports_provider
        self.report_provider = report_provider
        self.report_logs_provider = report_logs_provider
        self.sql_provider = sql_provider
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = build_handler(
            self.state_provider,
            history_provider=self.history_provider,
            schema_provider=self.schema_provider,
            alerts_provider=self.alerts_provider,
            reports_provider=self.reports_provider,
            report_provider=self.report_provider,
            report_logs_provider=self.report_logs_provider,
            sql_provider=self.sql_provider,
        )
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

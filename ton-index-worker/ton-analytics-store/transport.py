"""Bounded direct HTTP adapter for the two reviewed analytics tables only."""

from __future__ import annotations

import http.client
import json
import os
import re
import time
from urllib.parse import urlencode, urlsplit

from store import Conflict, MAX_JSON_BYTES, SqlRows, canonical


TABLES = ("ton_analytics.analytic_parts", "ton_analytics.analytic_completions")
SELECTS = {
    "SELECT * FROM " + table + " WHERE scope_key = {scope_key:String} "
    "AND batch_id = {batch_id:String}": table for table in TABLES
}
INSERTS = {"INSERT INTO " + table + " FORMAT JSONEachRow": table for table in TABLES}
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_ROWS = 2048
SETTINGS = {
    "max_threads": 2,
    "max_memory_usage": 1073741824,
    "max_execution_time": 30,
    "max_rows_to_read": 200000,
    "max_result_rows": MAX_RESPONSE_ROWS,
    "max_result_bytes": MAX_RESPONSE_BYTES,
    "result_overflow_mode": "throw",
    "read_overflow_mode": "throw",
    "timeout_overflow_mode": "throw",
    "async_insert": 0,
    "wait_for_async_insert": 1,
    "wait_end_of_query": 1,
    "output_format_json_quote_64bit_integers": 0,
}


class TransportError(RuntimeError):
    """Safe diagnostic: no URL, server error body, query or credentials."""


class HTTPTransport:
    def __init__(self, endpoint: str, user: str, password: str = ""):
        try:
            url = urlsplit(endpoint)
            if (url.scheme not in ("http", "https") or not url.hostname or
                url.username is not None or url.password is not None or
                url.query or url.fragment or url.path not in ("", "/") or
                any(c in endpoint for c in "\r\n\t") or
                not re.fullmatch(r"[a-zA-Z0-9_]{1,128}", user)):
                raise ValueError()
            port = url.port or (443 if url.scheme == "https" else 8123)
            if not 1 <= port <= 65535 or any(c in password for c in "\r\n\x00"):
                raise ValueError()
        except (ValueError, TypeError):
            raise TransportError("invalid transport configuration") from None
        self.host, self.port, self.scheme = url.hostname, port, url.scheme
        self.user, self._password = user, password
        self.rows = SqlRows(self.insert_json, self.select)

    @classmethod
    def from_env(cls):
        endpoint = os.environ.get("TONSTAT_CH_URL")
        if not endpoint:
            raise TransportError("TONSTAT_CH_URL is required")
        return cls(endpoint,
                   os.environ.get("TONSTAT_CH_USER", "tonstat_analytics_writer"),
                   os.environ.get("TONSTAT_CH_PASSWORD", ""))

    @property
    def identity(self):
        return [self.scheme, self.host, self.port, self.user]

    def _request(self, body: bytes, parameters: dict[str, str]) -> bytes:
        if len(body) > MAX_JSON_BYTES + 1024:
            raise TransportError("request budget exceeded")
        connection = None
        try:
            kind = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
            connection = kind(self.host, self.port, timeout=40)
            deadline = time.monotonic() + 40
            # No environment proxies, redirects or implicit auth.
            headers = {"X-ClickHouse-User": self.user, "Content-Type": "text/plain; charset=utf-8"}
            if self._password:
                headers["X-ClickHouse-Key"] = self._password
            connection.connect()
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
            connection.request("POST", "/?" + urlencode({**SETTINGS, **parameters}), body, headers)
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
            request_socket = connection.sock
            response = connection.getresponse()
            if response.status != 200:
                raise TransportError("ClickHouse HTTP request rejected")
            if response.getheader("X-ClickHouse-Exception-Code"):
                raise TransportError("ClickHouse query failed")
            data = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportError("HTTP deadline exceeded")
                # Keep the socket reference even when HTTPConnection detaches it
                # for a Connection: close response; response.fp still owns the FD.
                request_socket.settimeout(remaining)
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise TransportError("response byte budget exceeded")
            return bytes(data)
        except TransportError:
            raise
        except Exception:
            raise TransportError("HTTP transport failed") from None
        finally:
            if connection is not None:
                connection.close()

    def select(self, query: str, parameters: dict[str, str]):
        if query not in SELECTS or set(parameters) != {"scope_key", "batch_id"}:
            raise TransportError("query not allowed")
        if (not isinstance(parameters["scope_key"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", parameters["scope_key"]) or
            not isinstance(parameters["batch_id"], str) or not 1 <= len(parameters["batch_id"]) <= 256):
            raise TransportError("invalid read identity")
        raw = self._request((query + " FORMAT JSONEachRow").encode(),
                            {"param_" + k: v for k, v in parameters.items()})
        try:
            lines = raw.splitlines()
            if len(lines) > MAX_RESPONSE_ROWS:
                raise ValueError()
            rows = [json.loads(line) for line in lines]
            if any(not isinstance(row, dict) or type(row.get("revision")) is not int for row in rows):
                raise ValueError()
            return rows
        except (ValueError, TypeError, UnicodeError):
            raise TransportError("invalid or oversized readback") from None

    def insert_json(self, query: str, payload: bytes):
        if query not in INSERTS or not isinstance(payload, bytes) or len(payload) > MAX_JSON_BYTES + 1:
            raise TransportError("insert not allowed")
        try:
            row = json.loads(payload)
            if not isinstance(row, dict) or (canonical(row) + "\n").encode() != payload:
                raise ValueError()
            parameters = {"scope_key": row["scope_key"], "batch_id": row["batch_id"]}
        except (ValueError, TypeError, KeyError):
            raise TransportError("invalid insert payload") from None
        reply = self._request(query.encode() + b"\n" + payload, {})
        if reply.strip():
            raise TransportError("unexpected insert reply")
        select = next(sql for sql, table in SELECTS.items() if table == INSERTS[query])
        visible = self.select(select, parameters)
        if row not in visible:
            raise Conflict("insert not visible on configured read path")
        identity = ("scope_key", "batch_id", "part_id") if "part_id" in row else ("scope_key", "batch_id")
        if any(all(other.get(k) == row[k] for k in identity) and other != row for other in visible):
            raise Conflict("conflicting readback")

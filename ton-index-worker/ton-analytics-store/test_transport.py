"""Local HTTP integration tests: no real ClickHouse, NodeDB or credentials."""

import copy
from dataclasses import asdict
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cli import ingest, locked_writer, parse_envelope
from store import BlockID, Conflict, Scope, SourceID, TypedFact, canonical, fact_payload
from transport import HTTPTransport, INSERTS, SELECTS, SETTINGS, TransportError


def envelope():
    mc = BlockID(-1, "8000000000000000", 2, "a" * 64, "b" * 64)
    prev = BlockID(-1, "8000000000000000", 1, "c" * 64, "d" * 64)
    scope = Scope("synthetic", "1" * 64, "2" * 64, "transport_selftest", "test",
                  "http-v1", {"fixture": "synthetic-v1"}, "snapshot_at_anchor", "test", mc, prev)
    fact = TypedFact("unresolved", "unresolved", (SourceID(mc, None),), status="unknown",
                     reason="synthetic missing evidence", provenance={"origin": "synthetic"})
    return {"schema_version": 1, "scope": asdict(scope), "batch_id": "test", "revision": 1,
            "parts": {"one": [fact_payload(fact)]}}


class HTTPTest(unittest.TestCase):
    def setUp(self):
        owner = self
        self.tables = {table: [] for table in INSERTS.values()}
        self.requests = []
        self.mode = "normal"

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def reply(self, status, data):
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.close_connection = True
                if status == 302:
                    self.send_header("Location", "http://127.0.0.1:1/leak")
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                params = parse_qs(urlsplit(self.path).query)
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append((params, body, dict(self.headers)))
                if owner.mode in ("reject", "redirect"):
                    self.reply(500 if owner.mode == "reject" else 302, b"sensitive-server-error")
                    return
                if body.startswith(b"INSERT"):
                    query, payload = body.decode().split("\n", 1)
                    row = json.loads(payload)
                    owner.tables[INSERTS[query]].append(row)
                    if owner.mode == "lose_ack":
                        owner.mode = "normal"
                        self.reply(500, b"sensitive-server-error")
                    else:
                        self.reply(200, b"")
                    return
                if owner.mode == "oversize":
                    self.reply(200, b"x" * 1025)
                    return
                if owner.mode == "bad_json":
                    self.reply(200, b"sensitive-server-error")
                    return
                query = body.decode().removesuffix(" FORMAT JSONEachRow")
                rows = [row for row in owner.tables[SELECTS[query]]
                        if row["scope_key"] == params["param_scope_key"][0]
                        and row["batch_id"] == params["param_batch_id"][0]]
                if owner.mode == "invisible":
                    rows = []
                self.reply(200, b"".join((json.dumps(row) + "\n").encode() for row in rows))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.transport = HTTPTransport("http://127.0.0.1:" + str(self.server.server_port),
                                       "tonstat_analytics_writer", "synthetic-secret")
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = str(Path(self.temp.name) / "ledger.sqlite3")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def parsed(self):
        return parse_envelope(canonical(envelope()).encode())

    def test_from_env_requires_explicit_endpoint(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(TransportError, "TONSTAT_CH_URL is required"):
                HTTPTransport.from_env()
        with patch.dict(os.environ, {"TONSTAT_CH_URL": "http://127.0.0.1:" + str(self.server.server_port)},
                        clear=True):
            self.assertEqual(HTTPTransport.from_env().identity, self.transport.identity)

    def test_insert_readback_restart_parameters_and_limits(self):
        data = envelope()
        data["batch_id"] = "a' OR 1=1; --"
        parsed = parse_envelope(canonical(data).encode())
        with locked_writer(self.ledger, self.transport.rows, self.transport.identity) as writer:
            summary = ingest(writer, parsed)
            self.assertEqual(summary["status"], "pending")
            self.assertFalse(summary["publication_ready"])
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(ingest(writer, parsed), summary)
        with locked_writer(self.ledger, self.transport.rows, self.transport.identity) as writer:
            self.assertEqual(ingest(writer, parsed, read_only=True), summary)
        self.assertEqual(len(self.tables["ton_analytics.analytic_parts"]), 1)
        for params, body, headers in self.requests:
            for key, value in SETTINGS.items():
                self.assertEqual(params[key], [str(value)])
            self.assertNotIn("synthetic-secret", str(params))
            self.assertEqual(headers["X-ClickHouse-Key"], "synthetic-secret")
            if body.startswith(b"SELECT"):
                self.assertNotIn(data["batch_id"].encode(), body)
                self.assertEqual(params["param_batch_id"], [data["batch_id"]])

    def test_lost_ack_retry_does_not_duplicate(self):
        self.mode = "lose_ack"
        with locked_writer(self.ledger, self.transport.rows, self.transport.identity) as writer:
            with self.assertRaises(TransportError):
                ingest(writer, self.parsed())
            self.assertEqual(ingest(writer, self.parsed())["facts"], 1)
        self.assertEqual(len(self.tables["ton_analytics.analytic_parts"]), 1)

    def test_physical_duplicate_and_conflicting_readback(self):
        with locked_writer(self.ledger, self.transport.rows, self.transport.identity) as writer:
            ingest(writer, self.parsed())
            rows = self.tables["ton_analytics.analytic_parts"]
            rows.append(copy.deepcopy(rows[0]))
            self.assertEqual(ingest(writer, self.parsed())["facts"], 1)
            rows[1]["revision"] = 2
            with self.assertRaises(Conflict):
                ingest(writer, self.parsed())

    def test_insert_ack_without_readback_is_failure(self):
        self.mode = "invisible"
        with locked_writer(self.ledger, self.transport.rows, self.transport.identity) as writer:
            with self.assertRaises(Conflict):
                ingest(writer, self.parsed())
            self.assertEqual(writer.db.execute("SELECT ready FROM batches").fetchone(), (0,))

    def test_rejected_redirect_oversize_and_server_errors_are_redacted(self):
        query = next(iter(SELECTS))
        params = {"scope_key": "a" * 64, "batch_id": "test"}
        for mode in ("reject", "redirect", "bad_json", "oversize"):
            self.mode = mode
            with patch("transport.MAX_RESPONSE_BYTES", 1024):
                with self.assertRaises(TransportError) as caught:
                    self.transport.select(query, params)
            self.assertNotIn("sensitive", str(caught.exception))
            self.assertNotIn("synthetic-secret", str(caught.exception))
            self.assertNotIn("127.0.0.1", str(caught.exception))
        self.assertEqual(len(self.requests), 4)  # redirects are never followed

    def test_only_reviewed_queries_can_reach_http(self):
        with self.assertRaises(TransportError):
            self.transport.insert_json("INSERT INTO mainnet_d.blocks FORMAT JSONEachRow", b"{}\n")
        with self.assertRaises(TransportError):
            self.transport.select("SELECT * FROM mainnet_d.transactions", {})
        with self.assertRaises(TransportError):
            self.transport.select(next(iter(SELECTS)) + "; DROP TABLE x", {})
        self.assertEqual(self.requests, [])

    def test_locked_ledger_and_transport_identity_fence(self):
        with locked_writer(self.ledger, self.transport.rows, self.transport.identity):
            with self.assertRaises(Conflict):
                with locked_writer(self.ledger, self.transport.rows, self.transport.identity):
                    self.fail("second owner acquired ledger")
        with self.assertRaises(Conflict):
            with locked_writer(self.ledger, self.transport.rows, ["other path"]):
                self.fail("ledger transport binding changed")
        link = Path(self.temp.name) / "symlink"
        link.symlink_to(self.ledger)
        with self.assertRaises(OSError):
            with locked_writer(str(link), self.transport.rows, self.transport.identity):
                self.fail("symlink ledger accepted")

    def test_unresolved_omits_value_and_duplicate_keys_are_rejected(self):
        data = envelope()
        for value in (None, "0", 0):
            data["parts"]["one"][0]["value_decimal"] = value
            with self.assertRaises(Conflict):
                parse_envelope(canonical(data).encode())
        with self.assertRaises(Conflict):
            parse_envelope(b'{"schema_version":1,"schema_version":1}')
        data = envelope()
        data["parts"]["two"] = data["parts"]["one"]
        with self.assertRaises(Conflict):
            parse_envelope(canonical(data).encode())
        self.assertEqual(self.requests, [])

    def test_url_auth_query_and_header_injection_are_rejected(self):
        for url in ("http://user:secret@localhost/", "http://localhost/?password=secret",
                    "http://localhost/#secret", "file:///etc/passwd"):
            with self.assertRaises(TransportError) as caught:
                HTTPTransport(url, "writer")
            self.assertNotIn("secret", str(caught.exception))
        with self.assertRaises(TransportError):
            HTTPTransport("http://localhost/", "writer", "secret\r\nInjected: value")


if __name__ == "__main__":
    unittest.main()

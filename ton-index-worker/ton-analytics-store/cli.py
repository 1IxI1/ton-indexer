"""One bounded typed-fact envelope on stdin; insert/readback, never auto-publish."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
from contextlib import contextmanager

from store import (BlockID, Conflict, MAX_JSON_BYTES, MAX_PARTS, Scope, SourceID,
                   TypedFact, Writer, canonical, digest, part_content)
from transport import HTTPTransport, TransportError


DEFAULT_LEDGER = "/home/toncenter/tonstat-analytics/ledger.sqlite3"


@contextmanager
def locked_writer(path: str, rows, transport_identity):
    if not path or path == ":memory:" or not Path(path).is_absolute():
        raise Conflict("a durable absolute ledger path is required")
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = target.parent.stat()
    if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
        raise Conflict("ledger directory must be owner-controlled")
    # BSD flock and SQLite record locks interact on the same inode. A permanent
    # sibling lock file fences owners without interfering with SQLite itself.
    fd = os.open(str(target) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    writer = None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise Conflict("ledger must be an owned regular file")
        if info.st_mode & 0o077:
            raise Conflict("ledger permissions must be owner-only")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Conflict("ledger is owned by another writer") from None
        ledger_fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            ledger_info = os.fstat(ledger_fd)
            if (not stat.S_ISREG(ledger_info.st_mode) or ledger_info.st_uid != os.geteuid() or
                ledger_info.st_nlink != 1 or ledger_info.st_mode & 0o077):
                raise Conflict("ledger must be an owner-only regular file")
        finally:
            os.close(ledger_fd)
        writer = Writer(str(target), rows)
        writer.db.execute("PRAGMA synchronous=FULL")
        writer.db.execute("PRAGMA journal_mode=DELETE")
        writer.db.execute("CREATE TABLE IF NOT EXISTS transport_owner (id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL)")
        binding = digest(canonical(transport_identity))
        with writer.transaction():
            old = writer.db.execute("SELECT identity FROM transport_owner WHERE id=1").fetchone()
            if old is not None and old[0] != binding:
                raise Conflict("ledger belongs to another transport path")
            writer.db.execute("INSERT OR IGNORE INTO transport_owner VALUES(1,?)", (binding,))
        yield writer
    finally:
        if writer is not None:
            writer.db.close()
        os.close(fd)


def parse_envelope(raw: bytes):
    if len(raw) > MAX_JSON_BYTES:
        raise Conflict("envelope budget exceeded")
    def no_duplicates(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Conflict("duplicate JSON member")
            result[key] = value
        return result
    data = json.loads(raw, object_pairs_hook=no_duplicates)
    if set(data) != {"schema_version", "scope", "batch_id", "revision", "parts"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise Conflict("invalid envelope fields/version")
    scope_data = dict(data["scope"])
    for field in ("mc_anchor", "mc_predecessor", "end_mc_anchor"):
        if scope_data.get(field) is not None:
            scope_data[field] = BlockID(**scope_data[field])
    scope = Scope(**scope_data)
    Writer.identity(data["batch_id"], data["revision"])
    if not isinstance(data["parts"], dict) or not 1 <= len(data["parts"]) <= MAX_PARTS:
        raise Conflict("invalid parts")
    parts = {}
    manifest = {}
    keys = set()
    for part_id, facts in data["parts"].items():
        if not isinstance(facts, list):
            raise Conflict("invalid facts")
        parsed = []
        for fact in facts:
            if not isinstance(fact, dict):
                raise Conflict("invalid fact")
            common = {"key", "record_type", "source_ids", "provenance"}
            fields = common | ({"value_decimal"} if fact.get("record_type") == "numeric_verified" else {"status", "reason"})
            if set(fact) != fields:
                raise Conflict("typed fact fields mismatch; unresolved must omit value")
            converted = dict(fact)
            converted["source_ids"] = tuple(SourceID(BlockID(**ref["block"]), ref["state_root"])
                                             for ref in fact["source_ids"]
                                             if set(ref) == {"block", "state_root"})
            if len(converted["source_ids"]) != len(fact["source_ids"]):
                raise Conflict("source fields mismatch")
            typed = TypedFact(**converted)
            if typed.key in keys:
                raise Conflict("duplicate logical key across parts")
            keys.add(typed.key)
            parsed.append(typed)
        parts[part_id] = parsed
        manifest[part_id] = part_content(scope, data["batch_id"], part_id, parsed)[1]
    if scope.kind == "address_subset_at_anchor":
        if keys != set(scope.address_manifest):
            raise Conflict("subset address coverage mismatch")
        for facts in parts.values():
            for fact in facts:
                if (any(ref.state_root is None for ref in fact.source_ids) or
                    not any(ref.block == scope.mc_anchor for ref in fact.source_ids)):
                    raise Conflict("subset needs full anchor/state sources")
    return scope, data["batch_id"], data["revision"], parts, manifest


def ingest(writer, parsed, read_only=False):
    scope, batch, revision, parts, manifest = parsed
    if not read_only:
        writer.declare(scope, batch, revision, manifest)
        for part_id, facts in parts.items():
            writer.put_part(scope, batch, part_id, facts)
    recorded_revision, recorded_manifest, _, _, ready = writer._batch(scope, batch)
    if revision != recorded_revision or manifest != recorded_manifest:
        raise Conflict("ledger/envelope mismatch")
    facts = writer._verified_parts(scope, batch, revision, manifest, True)
    unresolved = sum(f.record_type == "unresolved" for f in facts)
    return {"scope_key": scope.key, "revision": revision, "parts": len(parts),
            "facts": len(facts), "unresolved": unresolved, "writer_committed": True,
            "readback_verified": True, "status": "READY" if ready else "pending",
            "publication_ready": False, "global_metric_complete": False}


def main():
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, "invalid command arguments; see --help\n")
    parser = SafeParser(description=__doc__)
    parser.add_argument("command", choices=("ingest", "readback"))
    parser.add_argument("--ledger", default=os.environ.get("TONSTAT_LEDGER", DEFAULT_LEDGER))
    options = parser.parse_args()
    try:
        parsed = parse_envelope(sys.stdin.buffer.read(MAX_JSON_BYTES + 1))
        transport = HTTPTransport.from_env()
        with locked_writer(options.ledger, transport.rows, transport.identity) as writer:
            summary = ingest(writer, parsed, read_only=options.command == "readback")
        print(json.dumps(summary, sort_keys=True))
        return 0
    except Conflict:
        print("store conflict or invalid immutable input", file=sys.stderr)
        return 3
    except TransportError:
        print("bounded ClickHouse transport failed; retry same envelope/ledger", file=sys.stderr)
        return 4
    except Exception:
        print("store operation failed; details suppressed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

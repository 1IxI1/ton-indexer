"""Bounded, fail-closed analytics write protocol. No connections or credentials.

SQLite is the *durable, single-owner* coordinator; ClickHouse is an append-only
fact/marker store. Do not share a CH dataset among independent SQLite ledgers.
The caller supplies a CH adapter; this file never contacts a server itself.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence, Union


MAX_PARTS = 256
MAX_FACTS_PER_PART = 256
MAX_JSON_BYTES = 256_000
DECIMAL = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS = re.compile(r"-?[0-9]+:[0-9a-f]{64}\Z")
MAX_SUBSET_ADDRESSES = 256
MAX_SOURCE_IDS = 16


class Conflict(ValueError):
    """Invalid, incomplete, or conflicting immutable material; never publish."""


def canonical(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise Conflict("bounded payload exceeded")
    return text


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def checked_hash(value: str) -> None:
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise Conflict("expected lowercase 64-character SHA256/hash")


@dataclass(frozen=True)
class BlockID:
    workchain: int
    shard: str                 # unsigned 64-bit shard prefix, 16 lowercase hex digits
    seqno: int
    root_hash: str
    file_hash: str

    def __post_init__(self) -> None:
        if type(self.workchain) is not int or not -(2**31) <= self.workchain < 2**31:
            raise Conflict("invalid workchain")
        if not isinstance(self.shard, str) or not re.fullmatch(r"[0-9a-f]{16}", self.shard):
            raise Conflict("invalid shard")
        if type(self.seqno) is not int or not 0 <= self.seqno < 2**32:
            raise Conflict("invalid seqno")
        checked_hash(self.root_hash)
        checked_hash(self.file_hash)


@dataclass(frozen=True)
class Scope:
    network: str
    zerostate: str             # zerostate root hash; network label alone is insufficient
    zerostate_file_hash: str
    dataset: str
    metric: str
    calc_version: str
    dependency_versions: Mapping[str, str]
    kind: str                  # snapshot_at_anchor / event_range / lifetime / address_subset_at_anchor
    scope_id: str              # stable UTC day or logical anchor slot across revisions
    mc_anchor: BlockID
    mc_predecessor: BlockID | None  # unknown/unexported only for snapshot_at_anchor
    end_mc_anchor: BlockID | None = None
    address_manifest: tuple[str, ...] | None = None
    address_manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        checked_hash(self.zerostate)
        checked_hash(self.zerostate_file_hash)
        if (not isinstance(self.mc_anchor, BlockID) or
            (self.mc_predecessor is None and self.kind != "snapshot_at_anchor") or
            (self.mc_predecessor is not None and
             (not isinstance(self.mc_predecessor, BlockID) or self.mc_predecessor.workchain != -1)) or
            (self.end_mc_anchor is not None and not isinstance(self.end_mc_anchor, BlockID)) or
            self.mc_anchor.workchain != -1 or
            (self.end_mc_anchor is not None and self.end_mc_anchor.workchain != -1)):
            raise Conflict("full masterchain IDs are required")
        for text in (self.network, self.dataset, self.metric, self.calc_version, self.scope_id):
            if not isinstance(text, str) or not text or len(text) > 256:
                raise Conflict("invalid scope identifier")
        if self.kind not in ("snapshot_at_anchor", "event_range", "lifetime", "address_subset_at_anchor"):
            raise Conflict("invalid coverage kind")
        if self.kind == "event_range" and self.end_mc_anchor is None:
            raise Conflict("event range requires right MC boundary")
        if self.kind == "address_subset_at_anchor":
            addresses = self.address_manifest
            if (not isinstance(addresses, (tuple, list)) or not 1 <= len(addresses) <= MAX_SUBSET_ADDRESSES or
                any(not isinstance(a, str) or not ADDRESS.fullmatch(a) for a in addresses) or
                len(set(addresses)) != len(addresses) or self.end_mc_anchor is not None):
                raise Conflict("subset requires a bounded, nonempty, unique raw-address manifest")
            sorted_addresses = tuple(sorted(addresses))
            sha = digest(canonical(sorted_addresses))
            if self.address_manifest_sha256 is not None and self.address_manifest_sha256 != sha:
                raise Conflict("subset address-manifest hash mismatch")
            object.__setattr__(self, "address_manifest", sorted_addresses)
            object.__setattr__(self, "address_manifest_sha256", sha)
        elif self.address_manifest is not None or self.address_manifest_sha256 is not None:
            raise Conflict("global scope must not carry a subset address manifest")
        if not isinstance(self.dependency_versions, Mapping) or any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v
            for k, v in self.dependency_versions.items()
        ):
            raise Conflict("dependency versions must be named nonempty strings")
        object.__setattr__(self, "dependency_versions", dict(self.dependency_versions))
        canonical(asdict(self))

    @property
    def encoded(self) -> str:
        return canonical(asdict(self))

    @property
    def key(self) -> str:
        # The selected MC anchor can change on a correction to the *same* day.
        # Keep its full IDs in scope_json, not in the stable publication key.
        identity = {
            "network": self.network, "zerostate": self.zerostate,
            "zerostate_file_hash": self.zerostate_file_hash,
            "dataset": self.dataset, "metric": self.metric,
            "calc_version": self.calc_version,
            "dependency_versions": self.dependency_versions,
            "kind": self.kind, "scope_id": self.scope_id,
        }
        if self.kind == "address_subset_at_anchor":
            # Unlike a daily/global correction, a subset's anchor and exact
            # membership are its logical identity; neither may be replaced.
            identity["mc_anchor"] = asdict(self.mc_anchor)
            identity["mc_predecessor"] = asdict(self.mc_predecessor)
            identity["address_manifest_sha256"] = self.address_manifest_sha256
        return digest(canonical(identity))

    @classmethod
    def from_encoded(cls, encoded: str) -> Scope:
        data = json.loads(encoded)
        for field in ("mc_anchor", "mc_predecessor", "end_mc_anchor"):
            if data[field] is not None:
                data[field] = BlockID(**data[field])
        result = cls(**data)
        if result.encoded != encoded:
            raise Conflict("noncanonical stored scope")
        return result


@dataclass(frozen=True)
class Fact:
    key: str                   # logical key unique ACROSS parts in one batch
    value_decimal: str         # exact signed integer, including negative residuals
    source_block: BlockID
    source_state_root: str | None = None
    provenance: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key or len(self.key) > 512:
            raise Conflict("invalid fact key")
        if not isinstance(self.source_block, BlockID):
            raise Conflict("full source block ID required")
        if not isinstance(self.value_decimal, str) or not DECIMAL.fullmatch(self.value_decimal):
            raise Conflict("value must be a canonical integer decimal string, never float")
        if self.source_state_root is not None:
            checked_hash(self.source_state_root)
        if self.provenance is not None and any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v
            for k, v in self.provenance.items()
        ):
            raise Conflict("provenance must contain nonempty strings")
        if self.provenance is not None:
            object.__setattr__(self, "provenance", dict(self.provenance))


@dataclass(frozen=True)
class SourceID:
    block: BlockID
    state_root: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.block, BlockID):
            raise Conflict("source ID requires a full block ID")
        if self.state_root is not None:
            checked_hash(self.state_root)


@dataclass(frozen=True)
class TypedFact:
    """Explicit numeric_verified or unresolved record; no implied numeric zero."""

    key: str
    record_type: str
    source_ids: tuple[SourceID, ...]
    value_decimal: str | None = None
    status: str | None = None  # unresolved: unknown/error/unsupported/not_present
    reason: str | None = None
    provenance: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key or len(self.key) > 512:
            raise Conflict("invalid typed fact key")
        if (not isinstance(self.source_ids, (tuple, list)) or
            not 1 <= len(self.source_ids) <= MAX_SOURCE_IDS or
            any(not isinstance(ref, SourceID) for ref in self.source_ids)):
            raise Conflict("typed fact needs 1..16 full source block/state IDs")
        refs = tuple(self.source_ids)
        if len({canonical(asdict(ref)) for ref in refs}) != len(refs):
            raise Conflict("duplicate typed source ID")
        object.__setattr__(self, "source_ids", refs)
        if self.record_type == "numeric_verified":
            if (not isinstance(self.value_decimal, str) or not DECIMAL.fullmatch(self.value_decimal) or
                self.status is not None or self.reason is not None):
                raise Conflict("verified numeric fact requires exact decimal only")
        elif self.record_type == "unresolved":
            if (self.value_decimal is not None or self.status not in
                ("unknown", "error", "unsupported", "not_present") or
                not isinstance(self.reason, str) or not self.reason or len(self.reason) > 1024):
                raise Conflict("unresolved fact needs status/reason and NO numeric value")
        else:
            raise Conflict("unknown typed fact record_type")
        if self.provenance is not None:
            if any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
                   for k, v in self.provenance.items()):
                raise Conflict("typed provenance must contain nonempty strings")
            object.__setattr__(self, "provenance", MappingProxyType(dict(self.provenance)))


StoredFact = Union[Fact, TypedFact]


def fact_payload(fact: StoredFact) -> dict[str, Any]:
    if isinstance(fact, Fact):
        return asdict(fact)  # legacy numeric wire format remains unchanged
    payload: dict[str, Any] = {
        "key": fact.key, "record_type": fact.record_type,
        "source_ids": [asdict(ref) for ref in fact.source_ids],
        "provenance": dict(fact.provenance) if fact.provenance is not None else None,
    }
    if fact.record_type == "numeric_verified":
        payload["value_decimal"] = fact.value_decimal
    else:
        payload["status"] = fact.status
        payload["reason"] = fact.reason
    return payload


def decode_fact(raw: dict[str, Any]) -> StoredFact:
    if "record_type" not in raw:
        return Fact(raw["key"], raw["value_decimal"], BlockID(**raw["source_block"]),
                    raw["source_state_root"], raw["provenance"])
    refs = tuple(SourceID(BlockID(**ref["block"]), ref["state_root"]) for ref in raw["source_ids"])
    return TypedFact(raw["key"], raw["record_type"], refs, raw.get("value_decimal"),
                     raw.get("status"), raw.get("reason"), raw["provenance"])


def part_content(scope: Scope, batch_id: str, part_id: str, facts: Sequence[StoredFact]) -> tuple[str, str]:
    if not isinstance(part_id, str) or not part_id or len(part_id) > 256:
        raise Conflict("invalid part ID")
    if len(facts) > MAX_FACTS_PER_PART or any(not isinstance(f, (Fact, TypedFact)) for f in facts):
        raise Conflict("invalid/big fact part")
    if len({f.key for f in facts}) != len(facts):
        raise Conflict("duplicate logical fact key")
    # Sorting makes replay independent of caller iteration order. Empty is valid.
    payload = canonical([fact_payload(f) for f in sorted(facts, key=lambda f: f.key)])
    return payload, digest(canonical([scope.key, batch_id, part_id, payload]))


class ClickHouseRows(Protocol):
    def put_part(self, row: dict[str, Any]) -> None: ...
    def parts(self, scope_key: str, batch_id: str) -> list[dict[str, Any]]: ...
    def put_completion(self, row: dict[str, Any]) -> None: ...
    def completions(self, scope_key: str, batch_id: str) -> list[dict[str, Any]]: ...


class SqlRows:
    """Thin CH driver adapter. Pass transport functions from an audited caller.

    insert_json(query, json_each_row_bytes) must use synchronous inserts;
    select(query, named_parameters) must read from the *publication* read path.
    No URL parsing, credentials, logging, or implicit CH client configuration.
    """

    def __init__(self, insert_json: Callable[[str, bytes], None],
                 select: Callable[[str, dict[str, str]], list[dict[str, Any]]]):
        self.insert_json = insert_json
        self.select = select

    def put_part(self, row: dict[str, Any]) -> None:
        self.insert_json("INSERT INTO ton_analytics.analytic_parts FORMAT JSONEachRow",
                         (canonical(row) + "\n").encode())

    def parts(self, scope_key: str, batch_id: str) -> list[dict[str, Any]]:
        return self.select(
            "SELECT * FROM ton_analytics.analytic_parts WHERE scope_key = {scope_key:String} "
            "AND batch_id = {batch_id:String}", {"scope_key": scope_key, "batch_id": batch_id})

    def put_completion(self, row: dict[str, Any]) -> None:
        self.insert_json("INSERT INTO ton_analytics.analytic_completions FORMAT JSONEachRow",
                         (canonical(row) + "\n").encode())

    def completions(self, scope_key: str, batch_id: str) -> list[dict[str, Any]]:
        return self.select(
            "SELECT * FROM ton_analytics.analytic_completions WHERE scope_key = {scope_key:String} "
            "AND batch_id = {batch_id:String}", {"scope_key": scope_key, "batch_id": batch_id})


class Writer:
    def __init__(self, ledger_path: str, rows: ClickHouseRows):
        self.db = sqlite3.connect(ledger_path, isolation_level=None, timeout=30)
        self.rows = rows
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS batches (
                scope_key TEXT NOT NULL, batch_id TEXT NOT NULL, scope_json TEXT NOT NULL,
                revision INTEGER NOT NULL, manifest_json TEXT NOT NULL,
                completion_json TEXT, completion_sha TEXT, ready INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (scope_key, batch_id), UNIQUE (scope_key, revision));
            CREATE TABLE IF NOT EXISTS published (
                scope_key TEXT PRIMARY KEY, batch_id TEXT NOT NULL,
                revision INTEGER NOT NULL, publication_id TEXT NOT NULL UNIQUE);
        """)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    @staticmethod
    def identity(batch_id: str, revision: int) -> None:
        if not isinstance(batch_id, str) or not batch_id or len(batch_id) > 256:
            raise Conflict("invalid batch ID")
        # SQLite signed INTEGER. Also fits CH UInt64.
        if type(revision) is not int or not 0 <= revision < 2**63:
            raise Conflict("invalid revision")

    def declare(self, scope: Scope, batch_id: str, revision: int,
                expected_parts: Mapping[str, str]) -> None:
        self.identity(batch_id, revision)
        if not expected_parts or len(expected_parts) > MAX_PARTS:
            raise Conflict("manifest must list 1..256 parts (empty facts use an empty part)")
        for part_id, sha in expected_parts.items():
            if not isinstance(part_id, str) or not part_id or len(part_id) > 256:
                raise Conflict("invalid part ID")
            checked_hash(sha)
        manifest = canonical(dict(expected_parts))
        with self.transaction():
            old = self.db.execute(
                "SELECT scope_json,revision,manifest_json FROM batches WHERE scope_key=? AND batch_id=?",
                (scope.key, batch_id)).fetchone()
            value = (scope.encoded, revision, manifest)
            if old is not None and old != value:
                raise Conflict("batch identity/manifest changed")
            if old is None:
                try:
                    self.db.execute("INSERT INTO batches(scope_key,batch_id,scope_json,revision,manifest_json) "
                                    "VALUES(?,?,?,?,?)", (scope.key, batch_id, *value))
                except sqlite3.IntegrityError as e:
                    raise Conflict("revision already belongs to another batch") from e

    def _batch(self, scope: Scope, batch_id: str) -> tuple[int, dict[str, str], str | None, str | None, int]:
        row = self.db.execute("SELECT scope_json,revision,manifest_json,completion_json,completion_sha,ready "
                              "FROM batches WHERE scope_key=? AND batch_id=?", (scope.key, batch_id)).fetchone()
        if row is None or row[0] != scope.encoded:
            raise Conflict("undeclared batch or wrong scope")
        return row[1], json.loads(row[2]), row[3], row[4], row[5]

    def _verified_parts(self, scope: Scope, batch_id: str, revision: int,
                        manifest: Mapping[str, str], require_all: bool) -> list[StoredFact]:
        found: dict[str, str] = {}
        keys: set[str] = set()
        facts: list[StoredFact] = []
        for row in self.rows.parts(scope.key, batch_id):
            part_id = row["part_id"]
            if (row["scope_key"] != scope.key or row["scope_json"] != scope.encoded or
                row["batch_id"] != batch_id or row["revision"] != revision or
                row["network"] != scope.network or row["zerostate"] != scope.zerostate or
                row["zerostate_file_hash"] != scope.zerostate_file_hash or
                row["dataset"] != scope.dataset or row["metric"] != scope.metric or
                row["calc_version"] != scope.calc_version or
                row["dependencies_sha256"] != digest(canonical(scope.dependency_versions)) or
                row["scope_kind"] != scope.kind or row["scope_id"] != scope.scope_id or
                row["address_manifest_sha256"] != scope.address_manifest_sha256 or
                part_id not in manifest):
                raise Conflict("unexpected CH part or mismatched identity")
            raw = json.loads(row["facts_json"])
            if canonical(raw) != row["facts_json"] or not isinstance(raw, list):
                raise Conflict("noncanonical CH fact payload")
            parsed = [decode_fact(f) for f in raw]
            payload, sha = part_content(scope, batch_id, part_id, parsed)
            if payload != row["facts_json"] or sha != row["content_sha256"] or sha != manifest[part_id]:
                raise Conflict("conflicting CH content for logical part")
            if part_id in found:
                continue  # physically duplicated identical row; counted only once
            found[part_id] = sha
            for fact in parsed:
                if fact.key in keys:
                    raise Conflict("fact key appears in multiple parts")
                if scope.kind == "address_subset_at_anchor":
                    if (not isinstance(fact, TypedFact) or fact.key not in scope.address_manifest or
                        not any(ref.block == scope.mc_anchor and ref.state_root is not None
                                for ref in fact.source_ids) or
                        any(ref.state_root is None for ref in fact.source_ids)):
                        raise Conflict("subset fact lacks typed status, address membership or source roots")
                keys.add(fact.key)
                facts.append(fact)
        if require_all and found.keys() != manifest.keys():
            raise Conflict("partial batch")
        if require_all and scope.kind == "address_subset_at_anchor" and keys != set(scope.address_manifest):
            raise Conflict("subset manifest has missing/unexpected addresses")
        return facts

    def put_part(self, scope: Scope, batch_id: str, part_id: str, facts: Sequence[StoredFact]) -> str:
        payload, sha = part_content(scope, batch_id, part_id, facts)
        if scope.kind == "address_subset_at_anchor" and any(
            not isinstance(f, TypedFact) or f.key not in scope.address_manifest or
            not any(ref.block == scope.mc_anchor and ref.state_root is not None for ref in f.source_ids) or
            any(ref.state_root is None for ref in f.source_ids) for f in facts
        ):
            raise Conflict("subset needs typed address facts with full source roots")
        with self.transaction():
            revision, manifest, _, _, _ = self._batch(scope, batch_id)
            if manifest.get(part_id) != sha:
                raise Conflict("part not in manifest or conflicting content")
            existing = self.rows.parts(scope.key, batch_id)
            self._verified_parts(scope, batch_id, revision, manifest, False)
            if not any(row["part_id"] == part_id for row in existing):
                self.rows.put_part({
                    "scope_key": scope.key, "network": scope.network, "zerostate": scope.zerostate,
                    "zerostate_file_hash": scope.zerostate_file_hash,
                    "dataset": scope.dataset, "metric": scope.metric, "calc_version": scope.calc_version,
                    "dependencies_sha256": digest(canonical(scope.dependency_versions)),
                    "scope_kind": scope.kind, "scope_id": scope.scope_id, "scope_json": scope.encoded,
                    "address_manifest_sha256": scope.address_manifest_sha256,
                    "batch_id": batch_id, "revision": revision, "part_id": part_id,
                    "content_sha256": sha, "facts_json": payload,
                })
        return sha

    def complete(self, scope: Scope, batch_id: str, expected_sources: Sequence[str],
                 processed_sources: Sequence[str], checks_passed: bool) -> str:
        # Sources are canonical full block/state identifiers, NOT seqnos or counts.
        # Caller must attest coverage against independent node input and validation.
        if (type(checks_passed) is not bool or not checks_passed or not expected_sources or
            len(expected_sources) > 4096 or len(processed_sources) > 4096 or
            any(not isinstance(s, str) or not s or len(s) > 1024 for s in
                (*expected_sources, *processed_sources)) or
            len(set(expected_sources)) != len(expected_sources) or
            len(set(processed_sources)) != len(processed_sources) or
            set(expected_sources) != set(processed_sources)):
            raise Conflict("missing/failed checks or incomplete/duplicate source coverage")
        for source in (*expected_sources, *processed_sources):
            try:
                ref = json.loads(source)
                if (canonical(ref) != source or not isinstance(ref, dict) or
                    set(ref) != {"block", "state_root"}):
                    raise Conflict("noncanonical source ref")
                BlockID(**ref["block"])
                if ref["state_root"] is not None:
                    checked_hash(ref["state_root"])
            except (TypeError, KeyError, ValueError) as e:
                raise Conflict("source ref needs full block ID and optional state root") from e
        with self.transaction():
            revision, manifest, prior_json, prior_sha, _ = self._batch(scope, batch_id)
            facts = self._verified_parts(scope, batch_id, revision, manifest, True)
            if any(isinstance(f, TypedFact) and f.record_type == "unresolved" for f in facts):
                raise Conflict("unresolved facts remain pending; batch cannot be READY")
            marker = canonical({"scope_key": scope.key, "batch_id": batch_id, "revision": revision,
                                "manifest": manifest, "manifest_sha256": digest(canonical(manifest)),
                                "expected_sources": sorted(expected_sources),
                                "processed_sources": sorted(processed_sources),
                                "checks_passed": checks_passed})
            sha = digest(marker)
            if prior_json is not None and (prior_json != marker or prior_sha != sha):
                raise Conflict("completion coverage/checks changed")
            if prior_json is None:
                self.db.execute("UPDATE batches SET completion_json=?,completion_sha=? "
                                "WHERE scope_key=? AND batch_id=?", (marker, sha, scope.key, batch_id))
            self._verified_completions(scope, batch_id, revision, marker, sha, False)
            if not self.rows.completions(scope.key, batch_id):
                self.rows.put_completion({"scope_key": scope.key, "batch_id": batch_id,
                                          "revision": revision, "completion_sha256": sha,
                                          "completion_json": marker})
            # Synchronous readback is required before READY; uncertain inserts retry.
            self._verified_completions(scope, batch_id, revision, marker, sha, True)
            self.db.execute("UPDATE batches SET ready=1 WHERE scope_key=? AND batch_id=?",
                            (scope.key, batch_id))
        return sha

    def _verified_completions(self, scope: Scope, batch_id: str, revision: int,
                              marker: str, sha: str, require: bool) -> None:
        found = self.rows.completions(scope.key, batch_id)
        if require and not found:
            raise Conflict("completion marker not visible")
        for row in found:
            if (row != {"scope_key": scope.key, "batch_id": batch_id, "revision": revision,
                        "completion_sha256": sha, "completion_json": marker} or digest(marker) != sha):
                raise Conflict("conflicting CH completion marker")

    def publish(self, scope: Scope, batch_id: str, publication_id: str) -> None:
        if not isinstance(publication_id, str) or not publication_id or len(publication_id) > 256:
            raise Conflict("invalid publication ID")
        with self.transaction():
            revision, manifest, marker, sha, ready = self._batch(scope, batch_id)
            if not ready or marker is None or sha is None:
                raise Conflict("batch not READY")
            self._verified_parts(scope, batch_id, revision, manifest, True)
            self._verified_completions(scope, batch_id, revision, marker, sha, True)
            old = self.db.execute("SELECT batch_id,revision,publication_id FROM published WHERE scope_key=?",
                                  (scope.key,)).fetchone()
            if old is not None:
                if old == (batch_id, revision, publication_id):
                    return
                if revision <= old[1]:
                    raise Conflict("late/competing revision cannot replace publication")
            try:
                self.db.execute("INSERT INTO published(scope_key,batch_id,revision,publication_id) "
                                "VALUES(?,?,?,?) ON CONFLICT(scope_key) DO UPDATE SET "
                                "batch_id=excluded.batch_id,revision=excluded.revision,"
                                "publication_id=excluded.publication_id",
                                (scope.key, batch_id, revision, publication_id))
            except sqlite3.IntegrityError as e:
                raise Conflict("publication ID already used") from e

    def approved(self, scope: Scope) -> tuple[str, list[StoredFact]]:
        # Pin publication once. Do not use latest revision per fact: replacements
        # (including deletions) use exactly the selected batch's entire fact set.
        row = self.db.execute("SELECT batch_id,revision,publication_id FROM published WHERE scope_key=?",
                              (scope.key,)).fetchone()
        if row is None:
            raise Conflict("no publication")
        batch_id, revision, pub_id = row
        stored = self.db.execute("SELECT scope_json FROM batches WHERE scope_key=? AND batch_id=?",
                                 (scope.key, batch_id)).fetchone()
        if stored is None:
            raise Conflict("published batch missing")
        selected_scope = Scope.from_encoded(stored[0])
        if selected_scope.key != scope.key:
            raise Conflict("published scope identity mismatch")
        recorded_rev, manifest, marker, sha, ready = self._batch(selected_scope, batch_id)
        if not ready or revision != recorded_rev or marker is None or sha is None:
            raise Conflict("published batch not ready")
        facts = self._verified_parts(selected_scope, batch_id, revision, manifest, True)
        self._verified_completions(selected_scope, batch_id, revision, marker, sha, True)
        return pub_id, facts

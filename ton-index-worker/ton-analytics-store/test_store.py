import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from cli import ingest, parse_envelope
from store import (BlockID, Conflict, Fact, Scope, SourceID, SqlRows, TypedFact,
                   Writer, canonical, digest, fact_payload, part_content)
import json


class MemoryRows:
    def __init__(self):
        self.part_rows = []
        self.marker_rows = []
        self.visible = True
        self.fail_after_part = False
        self.fail_after_marker = False

    def put_part(self, row):
        self.part_rows.append(row)
        if self.fail_after_part:
            self.fail_after_part = False
            raise OSError("unknown insert outcome")

    def parts(self, scope_key, batch_id):
        if not self.visible:
            return []
        return [r for r in self.part_rows if r["scope_key"] == scope_key and r["batch_id"] == batch_id]

    def put_completion(self, row):
        self.marker_rows.append(row)
        if self.fail_after_marker:
            self.fail_after_marker = False
            raise OSError("unknown marker outcome")

    def completions(self, scope_key, batch_id):
        if not self.visible:
            return []
        return [r for r in self.marker_rows if r["scope_key"] == scope_key and r["batch_id"] == batch_id]


class WriterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "owner.sqlite")
        self.ch = MemoryRows()
        self.writer = Writer(self.path, self.ch)
        self.mc = BlockID(-1, "8000000000000000", 11, "a" * 64, "b" * 64)
        self.prev = BlockID(-1, "8000000000000000", 10, "c" * 64, "d" * 64)
        self.scope = Scope("testnet", "e" * 64, "4" * 64, "gram", "supply", "v1", {},
                           "snapshot_at_anchor", "2026-10-16", self.mc, self.prev)
        self.a = Fact("total", "1000000000000000000000000", self.mc, "f" * 64)
        self.b = Fact("residual", "-1", self.mc)
        self.sources = [self.source(self.mc)]

    @staticmethod
    def source(block):
        from dataclasses import asdict
        from store import canonical
        return canonical({"block": asdict(block), "state_root": "f" * 64})

    def declare(self, batch, rev, parts):
        manifest = {part_id: part_content(self.scope, batch, part_id, facts)[1]
                    for part_id, facts in parts.items()}
        self.writer.declare(self.scope, batch, rev, manifest)

    def test_snapshot_null_predecessor_envelope_readback_and_restart(self):
        scope = replace(self.scope, mc_predecessor=None)
        refs = (SourceID(self.mc, "f" * 64),)
        facts = [TypedFact("total", "numeric_verified", refs, "100"),
                 TypedFact("pending", "unresolved", refs, status="unknown", reason="not exported")]
        raw = canonical({"schema_version": 1, "scope": asdict(scope), "batch_id": "null-snapshot",
                         "revision": 1, "parts": {"one": [fact_payload(f) for f in facts]}}).encode()
        self.assertIn(b'"mc_predecessor":null', raw)
        parsed = parse_envelope(raw)
        self.assertEqual(parsed[0], scope)
        self.assertIsNone(parsed[0].mc_predecessor)
        self.assertEqual(Scope.from_encoded(scope.encoded), scope)
        self.assertEqual(scope.key, self.scope.key)  # snapshot key still excludes anchor IDs
        summary = ingest(self.writer, parsed)  # declare, put_part and verified readback
        self.assertEqual((summary["facts"], summary["unresolved"], summary["status"]), (2, 1, "pending"))
        stored = self.writer.db.execute("SELECT * FROM batches").fetchall()
        self.assertEqual(stored[0][2], scope.encoded)
        self.assertEqual(self.ch.part_rows[0]["scope_json"], scope.encoded)
        self.assertIsNone(json.loads(self.ch.part_rows[0]["scope_json"])["mc_predecessor"])
        self.assertEqual(json.loads(self.ch.part_rows[0]["facts_json"]),
                         [fact_payload(f) for f in sorted(facts, key=lambda f: f.key)])
        self.writer.db.close()
        self.writer = Writer(self.path, self.ch)
        self.assertEqual(ingest(self.writer, parse_envelope(raw), read_only=True), summary)
        self.assertEqual(ingest(self.writer, parse_envelope(raw)), summary)
        self.assertEqual(self.writer.db.execute("SELECT * FROM batches").fetchall(), stored)
        self.assertEqual(len(self.ch.part_rows), 1)
        self.assertEqual(self.ch.marker_rows, [])

    def test_null_predecessor_rejected_outside_snapshot(self):
        for kind in ("event_range", "lifetime", "address_subset_at_anchor"):
            with self.subTest(kind=kind):
                valid = replace(self.scope, kind=kind,
                                end_mc_anchor=self.mc if kind == "event_range" else None,
                                address_manifest=("0:" + "1" * 64,) if kind == "address_subset_at_anchor" else None)
                with self.assertRaises(Conflict):
                    replace(valid, mc_predecessor=None)
                scope_data = dict(asdict(valid), mc_predecessor=None)
                with self.assertRaises(Conflict):
                    Scope.from_encoded(canonical(scope_data))
                with self.assertRaises(Conflict):
                    parse_envelope(canonical({"schema_version": 1, "scope": scope_data, "batch_id": "null",
                                              "revision": 1, "parts": {"one": []}}).encode())

    def test_snapshot_nonnull_predecessor_still_requires_full_mc_id(self):
        for predecessor in (False, 0, "null", {}, asdict(self.prev), replace(self.prev, workchain=0)):
            with self.subTest(predecessor=predecessor), self.assertRaises(Conflict):
                replace(self.scope, mc_predecessor=predecessor)

    def test_legacy_scope_bytes_keys_and_ledger_rows_unchanged(self):
        # Golden hashes captured before the snapshot-null extension, for every old kind.
        golden = {
            "snapshot_at_anchor": ("f8d5af2dbf1cfa406758b35939b655adc65c508e4e1e739f77f912f6a7976968",
                                   "b0fda1844625304f60a7de88cf81cc07a911e633bbe88aa2625107f7525b3107"),
            "event_range": ("da5471f5b151c9330e5fcfc588c405991087fd3feca09eb252fff64b3f2f6e0b",
                            "68b82b99d9dab943222974c591a4723497df2328d4b99ff9a4c61ef25dbf357a"),
            "lifetime": ("18eebfab12569d45468152af1446307cfe6453c05fe8c7c261011662bee62386",
                         "27d72ddefb0694a5f5fa2d772988bdbd724229085ac6186b55493c86122beea3"),
            "address_subset_at_anchor": ("0a453fe0b5509d289b30812ffcb385d7d5742273e109d0f2ed5655f588314a78",
                                         "09f2d2e59dc7794bae1ba6862951518e9e94355f5e3daf3f7cb6905c135df0fb"),
        }
        scopes = []
        address = "0:" + "1" * 64
        for kind, (encoded_sha, key) in golden.items():
            with self.subTest(kind=kind):
                scope = replace(self.scope, kind=kind,
                                end_mc_anchor=self.mc if kind == "event_range" else None,
                                address_manifest=(address,) if kind == "address_subset_at_anchor" else None)
                self.assertEqual(digest(scope.encoded), encoded_sha)
                self.assertEqual(scope.key, key)
                self.assertEqual(Scope.from_encoded(scope.encoded).encoded, scope.encoded)
                fact = TypedFact(address if scope.address_manifest else "total", "numeric_verified",
                                 (SourceID(self.mc, "f" * 64),), "100")
                manifest = {"one": part_content(scope, kind, "one", [fact])[1]}
                self.writer.declare(scope, kind, 1, manifest)
                self.writer.put_part(scope, kind, "one", [fact])
                self.writer.complete(scope, kind, self.sources, self.sources, True)
                self.writer.publish(scope, kind, "pub-" + kind)
                scopes.append((scope, fact, manifest))
        stored = self.writer.db.execute("SELECT * FROM batches ORDER BY scope_key").fetchall()
        rows = canonical(self.ch.part_rows)
        self.writer.db.close()
        self.writer = Writer(self.path, self.ch)
        for scope, fact, manifest in scopes:
            self.assertEqual(self.writer.approved(scope), ("pub-" + scope.kind, [fact]))
            self.writer.declare(scope, scope.kind, 1, manifest)
            self.writer.put_part(scope, scope.kind, "one", [fact])
        self.assertEqual(self.writer.db.execute("SELECT * FROM batches ORDER BY scope_key").fetchall(), stored)
        self.assertEqual(canonical(self.ch.part_rows), rows)

    def test_idempotent_retry_partial_and_approved_batch_replacement(self):
        self.declare("batch-1", 1, {"a": [self.a], "empty": []})
        self.writer.put_part(self.scope, "batch-1", "a", [self.a])
        self.writer.put_part(self.scope, "batch-1", "a", [self.a])
        self.assertEqual(len(self.ch.part_rows), 1)
        with self.assertRaises(Conflict):
            self.writer.complete(self.scope, "batch-1", self.sources, self.sources, True)
        with self.assertRaises(Conflict):
            self.writer.publish(self.scope, "batch-1", "publication-1")
        self.writer.put_part(self.scope, "batch-1", "empty", [])
        with self.assertRaises(Conflict):
            self.writer.complete(self.scope, "batch-1", self.sources, [], True)
        with self.assertRaises(Conflict):
            self.writer.complete(self.scope, "batch-1", self.sources, self.sources, False)
        self.writer.complete(self.scope, "batch-1", self.sources, self.sources, True)
        self.writer.complete(self.scope, "batch-1", self.sources, self.sources, True)
        self.assertEqual(len(self.ch.marker_rows), 1)
        with self.assertRaises(Conflict):
            self.writer.approved(self.scope)  # READY is not PUBLISHED
        self.writer.publish(self.scope, "batch-1", "publication-1")
        self.writer.publish(self.scope, "batch-1", "publication-1")
        self.assertEqual([f.key for f in self.writer.approved(self.scope)[1]], ["total"])
        self.declare("batch-2", 2, {"b": [self.b]})
        self.writer.put_part(self.scope, "batch-2", "b", [self.b])
        self.writer.complete(self.scope, "batch-2", self.sources, self.sources, True)
        self.writer.publish(self.scope, "batch-2", "publication-2")
        self.assertEqual([f.key for f in self.writer.approved(self.scope)[1]], ["residual"])
        with self.assertRaises(Conflict):
            self.writer.publish(self.scope, "batch-1", "late")

    def test_conflicts_fail_closed_even_with_duplicate_physical_rows(self):
        self.declare("batch", 1, {"a": [self.a]})
        self.writer.put_part(self.scope, "batch", "a", [self.a])
        self.ch.part_rows.append(dict(self.ch.part_rows[0]))
        self.writer.complete(self.scope, "batch", self.sources, self.sources, True)
        self.writer.publish(self.scope, "batch", "publication")
        self.assertEqual(len(self.writer.approved(self.scope)[1]), 1)
        self.ch.part_rows[-1]["content_sha256"] = "0" * 64
        with self.assertRaises(Conflict):
            self.writer.approved(self.scope)
        with self.assertRaises(Conflict):
            self.writer.put_part(self.scope, "batch", "a", [Fact("total", "9", self.mc)])

    def test_unknown_insert_and_process_restart(self):
        self.declare("batch", 1, {"a": [self.a]})
        self.ch.fail_after_part = True
        with self.assertRaises(OSError):
            self.writer.put_part(self.scope, "batch", "a", [self.a])
        self.writer.db.close()
        self.writer = Writer(self.path, self.ch)
        self.writer.put_part(self.scope, "batch", "a", [self.a])
        self.assertEqual(len(self.ch.part_rows), 1)
        self.ch.fail_after_marker = True
        with self.assertRaises(OSError):
            self.writer.complete(self.scope, "batch", self.sources, self.sources, True)
        self.writer.complete(self.scope, "batch", self.sources, self.sources, True)
        self.assertEqual(len(self.ch.marker_rows), 1)
        self.ch.visible = False
        with self.assertRaises(Conflict):
            self.writer.publish(self.scope, "batch", "publication")
        self.ch.visible = True
        self.writer.publish(self.scope, "batch", "publication")
        self.ch.visible = False
        with self.assertRaises(Conflict):
            self.writer.approved(self.scope)

    def test_validation_and_cross_part_key_collision(self):
        for amount in (1.0, "1.0", "01", "-0", "1e3", "NaN"):
            with self.assertRaises(Conflict):
                Fact("x", amount, self.mc)
        self.declare("batch", 1, {"a": [self.a], "b": [self.a]})
        self.writer.put_part(self.scope, "batch", "a", [self.a])
        self.writer.put_part(self.scope, "batch", "b", [self.a])
        with self.assertRaises(Conflict):
            self.writer.complete(self.scope, "batch", self.sources, self.sources, True)
        with self.assertRaises(Conflict):
            self.writer.declare(self.scope, "batch", 2, {"a": "0" * 64})

    def test_corrected_anchor_replaces_same_day_but_preserves_full_provenance(self):
        self.declare("old", 1, {"a": [self.a]})
        self.writer.put_part(self.scope, "old", "a", [self.a])
        self.writer.complete(self.scope, "old", self.sources, self.sources, True)
        self.writer.publish(self.scope, "old", "pub-old")
        corrected_mc = BlockID(-1, "8000000000000000", 12, "1" * 64, "2" * 64)
        corrected = Scope("testnet", "e" * 64, "4" * 64, "gram", "supply", "v1", {},
                          "snapshot_at_anchor", "2026-10-16", corrected_mc, self.mc)
        self.assertEqual(corrected.key, self.scope.key)
        fact = Fact("total", "99", corrected_mc, "3" * 64)
        self.writer.declare(corrected, "new", 2, {"a": part_content(corrected, "new", "a", [fact])[1]})
        self.writer.put_part(corrected, "new", "a", [fact])
        sources = [self.source(corrected_mc)]
        self.writer.complete(corrected, "new", sources, sources, True)
        self.writer.publish(corrected, "new", "pub-new")
        pub, selected = self.writer.approved(self.scope)
        self.assertEqual((pub, selected[0].source_block, selected[0].value_decimal),
                         ("pub-new", corrected_mc, "99"))
        with self.assertRaises(Conflict):
            self.writer.publish(self.scope, "old", "pub-late")

    def test_marker_conflict_and_source_ref_validation(self):
        self.declare("batch", 1, {"a": [self.a]})
        self.writer.put_part(self.scope, "batch", "a", [self.a])
        with self.assertRaises(Conflict):
            self.writer.complete(self.scope, "batch", ["11"], ["11"], True)
        self.writer.complete(self.scope, "batch", self.sources, self.sources, True)
        self.ch.marker_rows.append(dict(self.ch.marker_rows[0], completion_sha256="0" * 64))
        with self.assertRaises(Conflict):
            self.writer.publish(self.scope, "batch", "pub")

    def test_sql_adapter_only_uses_bound_select_parameters(self):
        inserts = []
        selects = []
        adapter = SqlRows(lambda sql, body: inserts.append((sql, body)),
                          lambda sql, params: selects.append((sql, params)) or [])
        attacker_id = "batch' OR 1=1 --"
        adapter.parts("a" * 64, attacker_id)
        adapter.completions("a" * 64, attacker_id)
        self.assertTrue(all(attacker_id not in sql for sql, _ in selects))
        self.assertTrue(all(params["batch_id"] == attacker_id for _, params in selects))
        adapter.put_part({"batch_id": attacker_id, "facts_json": "[]"})
        self.assertTrue(inserts[0][1].endswith(bytes([10])))

    def subset(self, addresses=None, mc=None):
        return Scope("testnet", "e" * 64, "4" * 64, "assets",
                     "jetton_wallet_address_observation", "v1", {},
                     "address_subset_at_anchor", "asset-sample", mc or self.mc, self.prev,
                     address_manifest=addresses or ("0:" + "1" * 64, "0:" + "2" * 64))

    def typed(self, address, record_type="numeric_verified", status=None, reason=None,
              value="123456789123456789123456789123456789", mc=None):
        anchor = mc or self.mc
        wallet_tip = BlockID(0, "8000000000000000", 42, "9" * 64, "8" * 64)
        return TypedFact(address, record_type,
                         (SourceID(anchor, "f" * 64), SourceID(wallet_tip, "7" * 64)),
                         value if record_type == "numeric_verified" else None,
                         status, reason, {"asset_observation_sha256": "6" * 64})

    def test_unknown_and_error_never_become_zero_or_ready(self):
        address = "0:" + "1" * 64
        scope = self.subset((address,))
        for status in ("unknown", "error"):
            with self.subTest(status=status):
                fact = self.typed(address, "unresolved", status, "getter/audit unavailable")
                payload, sha = part_content(scope, status, "one", [fact])
                raw = json.loads(payload)[0]
                self.assertEqual((raw["record_type"], raw["status"], raw["reason"]),
                                 ("unresolved", status, "getter/audit unavailable"))
                self.assertNotIn("value_decimal", raw)
                self.assertEqual(len(raw["source_ids"]), 2)
                self.writer.declare(scope, status, 1 if status == "unknown" else 2, {"one": sha})
                self.writer.put_part(scope, status, "one", [fact])
                with self.assertRaises(Conflict):
                    self.writer.complete(scope, status, self.sources, self.sources, True)
                with self.assertRaises(Conflict):
                    self.writer.publish(scope, status, "pub-" + status)
        self.assertEqual(self.ch.marker_rows, [])
        with self.assertRaises(Conflict):
            TypedFact(address, "unresolved", (SourceID(self.mc, "f" * 64),),
                      "0", "unknown", "not verified")
        with self.assertRaises(Conflict):
            TypedFact(address, "unresolved", (SourceID(self.mc, "f" * 64),),
                      None, "error", "")
        with self.assertRaises(Conflict):
            TypedFact(address, "numeric_verified", (SourceID(self.mc, "f" * 64),), "01")
        evidence = {"report": "original"}
        frozen = TypedFact(address, "unresolved", (SourceID(self.mc, "f" * 64),),
                           None, "unknown", "not verified", evidence)
        evidence["report"] = "changed"
        self.assertEqual(frozen.provenance["report"], "original")
        with self.assertRaises(TypeError):
            frozen.provenance["report"] = "changed"

    def test_subset_manifest_and_anchor_are_immutable_identity(self):
        a, b, c = ("0:" + digit * 64 for digit in "123")
        subset = self.subset((b, a))
        self.assertEqual(subset.address_manifest, (a, b))
        self.assertEqual(subset.key, self.subset((a, b)).key)
        self.assertEqual(subset.address_manifest_sha256, self.subset((a, b)).address_manifest_sha256)
        changed = self.subset((a, c))
        self.assertNotEqual(subset.key, changed.key)
        self.assertNotEqual(subset.address_manifest_sha256, changed.address_manifest_sha256)
        new_mc = BlockID(-1, "8000000000000000", 12, "5" * 64, "b" * 64)
        self.assertNotEqual(subset.key, self.subset((a, b), new_mc).key)
        with self.assertRaises(Conflict):
            self.subset((a, a))
        with self.assertRaises(Conflict):
            Scope("testnet", "e" * 64, "4" * 64, "assets", "balance", "v1", {},
                  "address_subset_at_anchor", "sample", self.mc, self.prev,
                  address_manifest=(a,), address_manifest_sha256="0" * 64)
        with self.assertRaises(Conflict):
            self.subset(tuple("0:" + format(i, "064x") for i in range(257)))

    def test_subset_missing_member_foreign_member_and_coverage_fail_closed(self):
        a, b, c = ("0:" + digit * 64 for digit in "123")
        scope = self.subset((a, b))
        fa, fb = self.typed(a), self.typed(b)
        self.writer.declare(scope, "missing", 1, {"a": part_content(scope, "missing", "a", [fa])[1]})
        self.writer.put_part(scope, "missing", "a", [fa])
        with self.assertRaises(Conflict):
            self.writer.complete(scope, "missing", self.sources, self.sources, True)
        with self.assertRaises(Conflict):
            self.writer.put_part(scope, "missing", "a", [self.typed(c)])
        self.writer.declare(scope, "foreign", 3,
                            {"c": part_content(scope, "foreign", "c", [self.typed(c)])[1]})
        with self.assertRaises(Conflict):
            self.writer.put_part(scope, "foreign", "c", [self.typed(c)])
        wrong_mc = BlockID(-1, "8000000000000000", 12, "5" * 64, "b" * 64)
        self.writer.declare(scope, "wrong-source", 4,
                            {"a": part_content(scope, "wrong-source", "a", [self.typed(a, mc=wrong_mc)])[1]})
        with self.assertRaises(Conflict):
            self.writer.put_part(scope, "wrong-source", "a", [self.typed(a, mc=wrong_mc)])
        self.writer.declare(scope, "complete", 2,
                            {"a": part_content(scope, "complete", "a", [fa, fb])[1]})
        self.writer.put_part(scope, "complete", "a", [fa, fb])
        with self.assertRaises(Conflict):
            self.writer.complete(scope, "complete", self.sources, [], True)
        with self.assertRaises(Conflict):
            self.writer.complete(scope, "complete", self.sources, self.sources, False)
        self.writer.complete(scope, "complete", self.sources, self.sources, True)
        self.writer.publish(scope, "complete", "subset-pub")
        self.assertEqual(len(self.writer.approved(scope)[1]), 2)
        with self.assertRaises(Conflict):
            self.writer.approved(self.subset((a, c)))
        # An old revision on this subset cannot replace it.
        with self.assertRaises(Conflict):
            self.writer.publish(scope, "missing", "old-subset")

    def test_subset_ready_does_not_publish_or_complete_global(self):
        address = "0:" + "1" * 64
        subset = self.subset((address,))
        global_scope = Scope("testnet", "e" * 64, "4" * 64, "assets",
                             "jetton_wallet_address_observation", "v1", {},
                             "snapshot_at_anchor", "asset-sample", self.mc, self.prev)
        self.assertNotEqual(subset.key, global_scope.key)
        fact = self.typed(address)
        self.writer.declare(subset, "subset", 1, {"one": part_content(subset, "subset", "one", [fact])[1]})
        self.writer.put_part(subset, "subset", "one", [fact])
        self.writer.complete(subset, "subset", self.sources, self.sources, True)
        with self.assertRaises(Conflict):
            self.writer.approved(subset)
        self.writer.publish(subset, "subset", "subset-pub")
        with self.assertRaises(Conflict):
            self.writer.approved(global_scope)
        with self.assertRaises(Conflict):
            self.writer.publish(global_scope, "subset", "global-pub")


if __name__ == "__main__":
    unittest.main()

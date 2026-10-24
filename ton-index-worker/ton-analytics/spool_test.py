"""Synthetic wire tests only; no source reads, credentials or transport calls."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

import pack_spool as pack

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ton-analytics-store"))
from cli import parse_envelope


def block(seqno=100, workchain=-1):
    return dict(workchain=workchain, shard="8000000000000000", seqno=seqno,
                root_hash="a" * 64, file_hash="b" * 64)


def row():
    return dict(schema_version=1, producer_version="ton-analytics-ndjson-v1", scope_id="c" * 64,
                source_sha256="d" * 64, ton_revision="fixture-only", network="mainnet",
                zerostate_root="e" * 64, zerostate_file="f" * 64, mc=block(), mc_predecessor=block(99),
                mc_state_root="1" * 64, mc_gen_utime=1788220800, source="node_db_secondary",
                mc_signatures_checked=False, cryptographic_zerostate_link_checked=False,
                publication_ready=False, lifetime_complete=False, dataset="block_flow", fact_key="block100",
                status="extracted", payload=dict(block=block(), block_inventory_complete=True, tx_count=1,
                    tx_fee_augmentation_nanoton="10", import_fee_augmentation_nanoton="2", gross_fees_nanoton="12",
                    created_nanoton="3", burned_nanoton=None, burn_status="value_flow_v1_absent", minted_grams_nanoton="0",
                    zero_sink_sent_count=0, zero_sink_sent_nanoton="0"))


class SpoolTests(unittest.TestCase):
    def test_numeric_and_absent_burn_have_distinct_types(self):
        result = list(pack.envelopes(row()))
        self.assertEqual(len(result), 9)
        for envelope in result:
            parsed = parse_envelope(pack.canonical(envelope).encode())
            fact = parsed[3]["facts"][0]
            if envelope["scope"]["metric"] == "burned_nanoton":
                self.assertEqual(fact.record_type, "unresolved")
                self.assertIsNone(fact.value_decimal)
            else:
                self.assertEqual(fact.record_type, "numeric_verified")
        r = row(); r["scope_id"] = "9" * 64
        self.assertEqual(result, list(pack.envelopes(r)))

    def test_independent_blocks_never_collide_in_store_revision_scope(self):
        a = list(pack.envelopes(row()))[0]
        r = row(); r["fact_key"] = "shard101"; r["payload"]["block"] = block(101, 0)
        b = list(pack.envelopes(r))[0]
        self.assertNotEqual(parse_envelope(pack.canonical(a).encode())[0].key,
                            parse_envelope(pack.canonical(b).encode())[0].key)

    def test_count_ready_stake_pending_and_no_invented_zero(self):
        r = row(); r.update(dataset="validators", status="per_metric")
        r["payload"] = {"metrics": {"count": {"status": "ready", "value_decimal": "382"},
                                   "frozen_remaining": {"status": "pending", "value_decimal": None, "reason": "unsupported code"}}}
        result = list(pack.envelopes(r))
        self.assertEqual(result[0]["parts"]["facts"][0]["value_decimal"], "382")
        self.assertNotIn("value_decimal", result[1]["parts"]["facts"][0])
        for item in result:
            parse_envelope(pack.canonical(item).encode())

    def test_nonzero_supply_residual_rejected(self):
        r = row(); r.update(dataset="supply_transition", status="verified_local_archive")
        r["payload"] = {"previous_mc": block(99), "previous_state_root": "2" * 64, "residual_nanoton": "1"}
        with self.assertRaises(ValueError):
            list(pack.envelopes(r))

    def test_commit_checksum_and_partial_spool(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "100.committed"; path.mkdir()
            raw = (json.dumps(row()) + "\n").encode()
            (path / "facts.ndjson").write_bytes(raw)
            (path / "receipt.txt").write_text("c" * 64 + "\nfull-id\n" + hashlib.sha256(raw).hexdigest() + "\n-1:all:100\n")
            self.assertEqual(list(pack.committed_rows(path)), [row()])
            (path / "facts.ndjson").write_bytes(raw + b"{}\n")
            with self.assertRaises(ValueError):
                list(pack.committed_rows(path))
            pending = Path(root) / "100.pending"; pending.mkdir()
            with self.assertRaises(ValueError):
                list(pack.committed_rows(pending))


if __name__ == "__main__":
    unittest.main()

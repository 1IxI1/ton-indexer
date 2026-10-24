#!/usr/bin/env python3
"""Offline mapper: one committed runner directory -> store v1 envelopes as NDJSON.

No transport, credentials, database, publication or completion calls. Feed each
output line separately to ton-analytics-store/cli.py ingest. Numeric facts remain
producer evidence; the store's separate readiness/publication protocol still applies.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 64 * 1024 * 1024
MAX_LINE = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 256_000  # ton-analytics-store v1 wire budget
MAPPER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
HEX = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*|-[1-9][0-9]*)\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def checked(condition, reason):
    if not condition:
        raise ValueError(reason)


def no_duplicates(items):
    result = {}
    for key, value in items:
        checked(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def scalar(value):
    checked(type(value) in (str, int), "numeric fact must be an exact integer")
    result = str(value)
    checked(bool(DECIMAL.fullmatch(result)), "noncanonical decimal")
    return result


def metrics(row):
    body, dataset = row["payload"], row["dataset"]
    if dataset == "block_flow":
        checked(row["status"] == "extracted" and body["block_inventory_complete"] is True,
                "block flow is not extracted")
        for name in ("tx_count", "tx_fee_augmentation_nanoton", "import_fee_augmentation_nanoton",
                     "gross_fees_nanoton", "created_nanoton", "burned_nanoton", "minted_grams_nanoton",
                     "zero_sink_sent_count", "zero_sink_sent_nanoton"):
            value = body[name]
            yield name, None if value is None else scalar(value), body.get("burn_status", "field unavailable")
    elif dataset == "validators":
        for name, item in body["metrics"].items():
            value = scalar(item["value_decimal"]) if item["status"] == "ready" else None
            yield name, value, item.get("reason") or "stage metric not ready"
    elif dataset == "supply_transition":
        checked(row["status"] == "verified_local_archive" and body["residual_nanoton"] == "0",
                "Supply transition has nonzero/unverified residual")
        for name, value in body["after_nanoton"].items():
            yield name + "_nanoton", scalar(value), ""
        yield "created_nanoton", scalar(body["created_nanoton"]), ""
        yield "residual_nanoton", "0", ""
    else:
        # Preserve full address/event payload in provenance. Do not turn a raw
        # observation into a verified lifetime metric or a sampled account total.
        yield "observation", None, body.get("reason") or "raw producer observation; no numeric metric certified"


def envelopes(row):
    checked(row["schema_version"] == 1 and row["producer_version"] == "ton-analytics-ndjson-v1", "unsupported runner version")
    checked(row["source"] == "node_db_secondary" and row["publication_ready"] is False and row["lifetime_complete"] is False,
            "unexpected source/publication flags")
    for name in ("source_sha256", "zerostate_root", "zerostate_file", "scope_id", "mc_state_root"):
        checked(isinstance(row[name], str) and HEX.fullmatch(row[name]), "invalid source/version hash")
    source = [{"block": row["mc"], "state_root": row["mc_state_root"]}]
    body = row["payload"]
    for name, state in (("block", None), ("source_block", None), ("execution_config_mc", body.get("execution_config_state_root"))):
        if name in body:
            ref = {"block": body[name], "state_root": state}
            if not any(item["block"] == ref["block"] for item in source):
                source.append(ref)
    if row["dataset"] == "supply_transition":
        source.append({"block": body["previous_mc"], "state_root": body["previous_state_root"]})
    event = row["dataset"] in ("block_flow", "zero_sink_send", "wallet_active_witness", "wallet_qualifying_send",
                               "wallet_coverage", "nft_initialization_candidate", "nft_coverage")
    for metric, value, reason in metrics(row):
        logical_key = hashlib.sha256(row["fact_key"].encode()).hexdigest()
        scope = {"network": row["network"], "zerostate": row["zerostate_root"], "zerostate_file_hash": row["zerostate_file"],
                 "dataset": row["dataset"], "metric": metric, "calc_version": row["producer_version"],
                 "dependency_versions": {"source_sha256": row["source_sha256"], "ton_revision": row["ton_revision"],
                                         "spool_mapper_sha256": MAPPER_SHA256},
                 "kind": "event_range" if event else "snapshot_at_anchor",
                 "scope_id": f"mc:{row['mc']['seqno']}:{row['mc']['root_hash']}/fact:{logical_key}",
                 "mc_anchor": row["mc"], "mc_predecessor": row["mc_predecessor"]}
        if event:
            scope["end_mc_anchor"] = row["mc"]
        key = logical_key + "/" + metric
        # Run selection is recorded in the original spool. Excluding it here
        # keeps the same versioned source fact identical across overlapping runs.
        provenance = {k: v for k, v in row.items() if k not in
                      ("scope_id", "requested_anchor_time_from", "requested_anchor_time_to")}
        row_sha256 = hashlib.sha256(canonical(provenance).encode()).hexdigest()
        if row["dataset"] == "validators":
            provenance["payload"] = {k: v for k, v in body.items() if k != "metrics"}
            provenance["payload"]["metrics"] = {metric: body["metrics"][metric]}
        elif row["dataset"] == "anchor":
            provenance["payload"] = {"evidence_retained_in_original_ndjson": True,
                                      "independent_tip_frontier_checked": body["independent_tip_frontier_checked"]}
        fact = {"key": key, "source_ids": source,
                "provenance": {"runner_row": canonical(provenance), "source_fact_sha256": row_sha256}}
        if value is None:
            fact.update(record_type="unresolved", status="unknown", reason=reason[:1024])
        else:
            fact.update(record_type="numeric_verified", value_decimal=value)
        # Full identity/version/content-derived ID makes repeated ingestion stable.
        batch = hashlib.sha256(canonical([scope, fact]).encode()).hexdigest()
        yield {"schema_version": 1, "scope": scope, "batch_id": batch, "revision": 1, "parts": {"facts": [fact]}}


def committed_rows(directory):
    checked(directory.name.endswith(".committed") and directory.is_dir() and not directory.is_symlink(), "expected committed directory")
    facts, receipt = directory / "facts.ndjson", directory / "receipt.txt"
    checked(not facts.is_symlink() and not receipt.is_symlink(), "symlink in spool")
    checked(facts.stat().st_size <= MAX_BYTES and receipt.stat().st_size <= 4 * 1024 * 1024, "spool exceeds mapper budget")
    header = receipt.read_text().splitlines()
    checked(len(header) >= 4, "truncated receipt")
    raw = facts.read_bytes()
    checked(hashlib.sha256(raw).hexdigest() == header[2], "facts do not match committed receipt")
    checked(raw.endswith(b"\n"), "truncated NDJSON")
    for line in raw.splitlines():
        checked(0 < len(line) <= MAX_LINE, "invalid/oversized fact line")
        row = json.loads(line, object_pairs_hook=no_duplicates)
        checked(row["scope_id"] == header[0], "fact/receipt scope mismatch")
        yield row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("committed_directory", type=Path)
    options = parser.parse_args()
    try:
        for row in committed_rows(options.committed_directory):
            for envelope in envelopes(row):
                line = canonical(envelope)
                checked(len(line.encode()) <= MAX_ENVELOPE_BYTES, "store envelope exceeds 256000-byte wire budget")
                print(line)
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"spool mapping failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

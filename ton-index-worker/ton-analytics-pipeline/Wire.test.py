"""Actual native processor output -> existing spool mapper -> store parser; no I/O transport."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "ton-analytics-store"))
from cli import parse_envelope

spec = importlib.util.spec_from_file_location("pack_spool", root / "ton-analytics/pack_spool.py")
mapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mapper)
with tempfile.TemporaryDirectory(prefix="pipeline-wire-") as tmp:
    spool = Path(tmp) / "spool"
    subprocess.run([sys.argv[1], str(spool)], check=True, timeout=60)
    rows = list(mapper.committed_rows(spool / "10.committed"))
    assert any(r["dataset"] == "wallet_qualifying_send" for r in rows)
    assert any(r["dataset"] == "flow_pending" and r["payload"]["value"] is None for r in rows)
    count = 0
    for row in rows:
        for envelope in mapper.envelopes(row):
            encoded = mapper.canonical(envelope).encode()
            assert len(encoded) <= mapper.MAX_ENVELOPE_BYTES
            parse_envelope(encoded)
            count += 1
    assert count >= len(rows)
    print(f"validated {len(rows)} native pipeline rows / {count} store envelopes")

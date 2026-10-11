
import json
import re
from pathlib import Path
from urllib.parse import urlparse

path = Path("service_labels.json")
required = [
    "service", "category", "address", "chain",
    "source_name", "source_url", "evidence_type",
    "notes", "verified_by", "verified_date"
]

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print("FILE ERROR:", exc)
    raise SystemExit(1)

if not isinstance(data, list):
    print("PROBLEM: The top-level JSON value is not a list.")
    print("Actual type:", type(data).__name__)
    raise SystemExit(1)

print("Total records:", len(data))

accepted = 0

for i, record in enumerate(data, start=1):
    problems = []

    if not isinstance(record, dict):
        print(f"Record {i}: REJECTED — not an object")
        continue

    missing = [
        key for key in required
        if not isinstance(record.get(key), str)
        or not record[key].strip()
    ]
    if missing:
        problems.append("missing/empty fields: " + ", ".join(missing))

    address = record.get("address", "")
    if not isinstance(address, str) or not re.fullmatch(
        r"0x[0-9a-fA-F]{40}", address
    ):
        problems.append("invalid Ethereum address")

    if str(record.get("chain", "")).lower() != "ethereum":
        problems.append("chain is not ethereum")

    if record.get("verified") is not True:
        problems.append("verified is not true")

    url = record.get("source_url", "")
    parsed = urlparse(url if isinstance(url, str) else "")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        problems.append("source_url is not a valid HTTP(S) URL")

    if str(record.get("evidence_type", "")).lower() == "simulated_demo_record":
        problems.append("simulated demo record")

    if problems:
        print(f"Record {i}: REJECTED — " + "; ".join(problems))
    else:
        accepted += 1
        print(
            f"Record {i}: ACCEPTED — "
            f"{record['service']} ({record['address']})"
        )

print(f"\nAccepted records: {accepted}/{len(data)}")

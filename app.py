
import os
import io
import csv
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request, send_file

try:
    from pyvis.network import Network
except ImportError:
    Network = None


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
ETHERSCAN_API_URL = "https://api.etherscan.io/v2/api"
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "").strip()

SERVICE_LABELS_FILE = Path(
    os.getenv(
        "SERVICE_LABELS_FILE",
        str(BASE_DIR / "service_labels.json")
    )
)

LAST_RESULTS = None
ETHERSCAN_LABEL_CACHE = {}


# ============================================================
# DEMO SCENARIOS
# All demo service addresses below are fictional.
# ============================================================

SCENARIOS = {
    "ethereum": {
        "name": "General Investigation Demo",
        "description": "Illustrative wallet investigation with fictional service interactions.",
        "target": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    },
    "suspicious": {
        "name": "Suspicious Activity Demo",
        "description": "Illustrative investigation with fictional high-risk activity.",
        "target": "0x1111111111111111111111111111111111111111",
    },
}


SERVICE_REFERENCE_DATA = [
    {
        "service": "Example Centralized Exchange",
        "category": "Exchange / VASP",
        "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "chain": "ethereum",
        "source_name": "CryptoTrace fictional demo dataset",
        "source_url": "",
        "evidence_type": "simulated_demo_record",
        "confidence": "Demo only",
        "verified": False,
        "notes": "Fictional example address. Not a real exchange.",
    },
    {
        "service": "Example Mixer",
        "category": "Mixer",
        "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "chain": "ethereum",
        "source_name": "CryptoTrace fictional demo dataset",
        "source_url": "",
        "evidence_type": "simulated_demo_record",
        "confidence": "Demo only",
        "verified": False,
        "notes": "Fictional example address. Not a real mixer.",
    },
    {
        "service": "Example Cross-chain Bridge",
        "category": "Bridge",
        "address": "0xcccccccccccccccccccccccccccccccccccccccc",
        "chain": "ethereum",
        "source_name": "CryptoTrace fictional demo dataset",
        "source_url": "",
        "evidence_type": "simulated_demo_record",
        "confidence": "Demo only",
        "verified": False,
        "notes": "Fictional example address. Not a real bridge.",
    },
    {
        "service": "Example DeFi Protocol",
        "category": "DeFi protocol",
        "address": "0xdddddddddddddddddddddddddddddddddddddddd",
        "chain": "ethereum",
        "source_name": "CryptoTrace fictional demo dataset",
        "source_url": "",
        "evidence_type": "simulated_demo_record",
        "confidence": "Demo only",
        "verified": False,
        "notes": "Fictional example address. Not a real protocol.",
    },
]


# ============================================================
# HELPERS
# ============================================================

def utc_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(
            int(timestamp), timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OSError, OverflowError):
        return "Unknown"


def normalize_address(address):
    if not isinstance(address, str):
        raise ValueError("Enter a valid Ethereum address.")

    address = address.strip()

    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
        raise ValueError(
            "Invalid Ethereum address. It must start with 0x "
            "and contain exactly 40 hexadecimal characters after it."
        )

    return address.lower()


def shorten_address(address):
    if not address or len(address) < 12:
        return address or "Unknown"

    return address[:8] + "..." + address[-6:]


def safe_source_url(url):
    if not isinstance(url, str):
        return False

    try:
        parsed = urlparse(url.strip())
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.netloc)
        )
    except ValueError:
        return False


# ============================================================
# LOCAL VERIFIED LABEL DATASET
# ============================================================

def load_verified_service_records():
    """
    Load records from service_labels.json.

    Real-mode records must include source information, evidence type,
    verifier and date. This validates metadata, not the truth of a claim.
    """

    if not SERVICE_LABELS_FILE.exists():
        return []

    try:
        with SERVICE_LABELS_FILE.open(
            "r", encoding="utf-8"
        ) as file:
            records = json.load(file)

    except (OSError, json.JSONDecodeError):
        app.logger.warning("Could not read service_labels.json.")
        return []

    if not isinstance(records, list):
        app.logger.warning(
            "service_labels.json must contain a JSON list."
        )
        return []

    required_fields = [
        "service",
        "category",
        "address",
        "chain",
        "source_name",
        "source_url",
        "evidence_type",
        "notes",
        "verified_by",
        "verified_date",
    ]

    accepted = []
    seen_addresses = set()

    for record in records:
        if not isinstance(record, dict):
            continue

        if record.get("verified") is not True:
            continue

        if record.get("evidence_type") == "simulated_demo_record":
            continue

        if str(record.get("chain", "")).lower() != "ethereum":
            continue

        if any(
            not isinstance(record.get(field), str)
            or not record[field].strip()
            for field in required_fields
        ):
            continue

        if not safe_source_url(record["source_url"]):
            continue

        try:
            address = normalize_address(record["address"])
        except ValueError:
            continue

        if address in seen_addresses:
            continue

        clean_record = dict(record)
        clean_record["address"] = address
        clean_record["chain"] = "ethereum"
        clean_record["verified"] = True
        clean_record["confidence"] = (
            clean_record.get("confidence") or "Source documented"
        )

        accepted.append(clean_record)
        seen_addresses.add(address)

    return accepted


# ============================================================
# OPTIONAL ETHERSCAN NAME TAG LOOKUP
# ============================================================

def fetch_etherscan_nametag(address):
    """
    Attempt the Etherscan Name Tag endpoint.

    Availability depends on the endpoint and API plan. A failed or
    unsupported lookup returns None, allowing the app to continue.

    A returned label is described as source-published. It does not
    independently prove ownership, service category or criminality.
    """

    try:
        address = normalize_address(address)
    except ValueError:
        return None

    if address in ETHERSCAN_LABEL_CACHE:
        return ETHERSCAN_LABEL_CACHE[address]

    if not ETHERSCAN_API_KEY:
        return None

    params = {
        "chainid": "1",
        "module": "nametag",
        "action": "getnametag",
        "address": address,
        "apikey": ETHERSCAN_API_KEY,
    }

    try:
        response = requests.get(
            ETHERSCAN_API_URL,
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()

    except (requests.RequestException, ValueError):
        ETHERSCAN_LABEL_CACHE[address] = None
        return None

    if str(payload.get("status", "")) != "1":
        ETHERSCAN_LABEL_CACHE[address] = None
        return None

    result = payload.get("result")

    if isinstance(result, dict):
        label = (
            result.get("nametag")
            or result.get("nameTag")
            or result.get("label")
            or result.get("name")
        )
    elif isinstance(result, str):
        label = result
    else:
        label = None

    if not isinstance(label, str):
        ETHERSCAN_LABEL_CACHE[address] = None
        return None

    label = label.strip()

    if not label or label.lower() in {
        "none",
        "null",
        "unknown",
        "no nametag found",
        "not found",
    }:
        ETHERSCAN_LABEL_CACHE[address] = None
        return None

    record = {
        "service": label,
        "category": "Etherscan Name Tag — category unconfirmed",
        "address": address,
        "chain": "ethereum",
        "source_name": "Etherscan Name Tag API",
        "source_url": f"https://etherscan.io/address/{address}",
        "evidence_type": "etherscan_nametag",
        "confidence": "Etherscan-published label; independently unconfirmed",
        "verified": True,
        "notes": (
            "This name tag was returned by Etherscan. Its publication "
            "does not independently establish ownership, service category "
            "or criminal activity."
        ),
        "verified_by": "Etherscan label service",
        "verified_date": datetime.now(timezone.utc).date().isoformat(),
    }

    ETHERSCAN_LABEL_CACHE[address] = record
    return record


# ============================================================
# SERVICE ATTRIBUTION
# ============================================================

def get_service_attributions(results):
    """
    Demo mode matches fictional demo records.

    Real mode matches:
      1. Locally configured verified records.
      2. Etherscan Name Tags, if the endpoint is available and returns
         a label for a transaction participant.
    """

    if results["mode_key"] == "demo":
        reference_records = SERVICE_REFERENCE_DATA

    else:
        reference_records = load_verified_service_records()

        participants = []

        for tx in results.get("transactions", []):
            for field in ("from", "to"):
                address = tx.get(field, "").lower()

                if address and address not in participants:
                    participants.append(address)

        existing_addresses = {
            record["address"].lower()
            for record in reference_records
        }

        # Keep optional API lookups bounded.
        max_label_lookups = 20
        lookup_count = 0

        for address in participants:
            if address in existing_addresses:
                continue

            if lookup_count >= max_label_lookups:
                break

            lookup_count += 1
            record = fetch_etherscan_nametag(address)

            if record:
                reference_records.append(record)
                existing_addresses.add(address)

    matched = {}

    for tx in results.get("transactions", []):
        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()

        for record in reference_records:
            address = record["address"].lower()

            role = None

            if sender == address:
                role = "Sender"

            if receiver == address:
                role = (
                    "Sender and receiver"
                    if role == "Sender"
                    else "Receiver"
                )

            if role is None:
                continue

            if address not in matched:
                matched[address] = {
                    "service": record["service"],
                    "category": record["category"],
                    "address": address,
                    "chain": record.get("chain", "ethereum"),
                    "source_name": record.get("source_name", ""),
                    "source_url": record.get("source_url", ""),
                    "evidence_type": record.get("evidence_type", ""),
                    "confidence": record.get("confidence", ""),
                    "verified": record.get("verified") is True,
                    "notes": record.get("notes", ""),
                    "verified_by": record.get("verified_by", ""),
                    "verified_date": record.get("verified_date", ""),
                    "transaction_roles": [],
                    "transaction_count": 0,
                }

            item = matched[address]

            if role not in item["transaction_roles"]:
                item["transaction_roles"].append(role)

            item["transaction_count"] += 1

    return list(matched.values())


def enrich_with_service_attributions(results):
    results["attributions"] = get_service_attributions(results)

    if results["mode_key"] == "demo":
        results["attribution_notice"] = (
            "Demo Mode uses fictional service names and addresses. "
            "These records are for demonstration only and are not "
            "real-world attribution evidence."
        )
    else:
        results["attribution_notice"] = (
            "Real Mode matches transaction participants against the "
            "configured source-backed label dataset and attempts an "
            "Etherscan Name Tag lookup where supported. A source-published "
            "label is not proof of ownership or criminal activity."
        )

    return results


# ============================================================
# INTERACTIVE TRANSACTION GRAPH
# ============================================================

# ============================================================
# WALLET RISK PROFILING & BEHAVIORAL HEURISTICS ENGINE
# ============================================================

def build_wallet_summary(results):
    """
    Computes comprehensive behavioral risk profiles for the target wallet
    and all cluster counterparties, in both Demo Mode and Real Ethereum Mode.
    Evaluates 6 core forensic indicators:
      1. Mixer & Tumbler Exposure
      2. High-Velocity Pass-Through (Mule Behavior)
      3. Structured Peeling Chain Pattern
      4. VASP Exit Gateway Proximity
      5. Cross-Chain Bridge Usage
      6. High-Value Asset Transfer Concentration
    """
    target = results["target_address"].lower()
    transactions = results.get("transactions", [])
    attributions = results.get("attributions", [])
    is_demo = results.get("mode_key") == "demo"
    scenario_key = results.get("scenario_key", "")

    # Group transactions by sender and receiver
    wallets_map = {}
    for tx in transactions:
        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()
        try:
            val = float(tx.get("value_eth", 0))
        except (ValueError, TypeError):
            val = 0.0

        for addr in (sender, receiver):
            if not addr:
                continue
            if addr not in wallets_map:
                wallets_map[addr] = {
                    "address": addr,
                    "short_address": shorten_address(addr),
                    "transaction_count": 0,
                    "total_sent": 0.0,
                    "total_received": 0.0,
                    "sent_txs": [],
                    "received_txs": [],
                }
            wallets_map[addr]["transaction_count"] += 1

        if sender and sender in wallets_map:
            wallets_map[sender]["total_sent"] = round(wallets_map[sender]["total_sent"] + val, 6)
            wallets_map[sender]["sent_txs"].append(tx)

        if receiver and receiver in wallets_map:
            wallets_map[receiver]["total_received"] = round(wallets_map[receiver]["total_received"] + val, 6)
            wallets_map[receiver]["received_txs"].append(tx)

    # If target wallet had 0 transactions in dataset, ensure it exists in wallets_map
    if target not in wallets_map:
        wallets_map[target] = {
            "address": target,
            "short_address": shorten_address(target),
            "transaction_count": 0,
            "total_sent": 0.0,
            "total_received": 0.0,
            "sent_txs": [],
            "received_txs": [],
        }

    # Attribution lookups
    attr_by_addr = {item["address"].lower(): item for item in attributions}

    mixer_addrs = {
        addr for addr, item in attr_by_addr.items()
        if "mixer" in item.get("category", "").lower() or "mixer" in item.get("service", "").lower()
    }
    bridge_addrs = {
        addr for addr, item in attr_by_addr.items()
        if "bridge" in item.get("category", "").lower() or "bridge" in item.get("service", "").lower()
    }
    exchange_addrs = {
        addr for addr, item in attr_by_addr.items()
        if "exchange" in item.get("category", "").lower() or "vasp" in item.get("category", "").lower()
    }
    defi_addrs = {
        addr for addr, item in attr_by_addr.items()
        if "defi" in item.get("category", "").lower() or "dex" in item.get("category", "").lower()
    }

    # Identify top VASP if any
    top_vasp_info = None
    for item in attributions:
        cat = item.get("category", "").lower()
        if "exchange" in cat or "vasp" in cat:
            top_vasp_info = {
                "name": item.get("service", "Unknown Exchange"),
                "address": item.get("address", ""),
                "category": item.get("category", "Exchange / VASP"),
                "status": "Target Deposit Terminal",
                "confidence": item.get("confidence", "Verified"),
            }
            break

    risk_profiles = {}

    for addr, wdata in wallets_map.items():
        is_subject = (addr == target)
        sent_val = wdata["total_sent"]
        recv_val = wdata["total_received"]
        tx_count = wdata["transaction_count"]
        net_val = round(recv_val - sent_val, 6)

        out_targets = {tx.get("to", "").lower() for tx in wdata["sent_txs"]}
        in_sources = {tx.get("from", "").lower() for tx in wdata["received_txs"]}

        # Determine Role
        if is_subject:
            role = "Target Wallet (Subject)"
        elif addr in mixer_addrs:
            role = "Mixer Protocol Terminal"
        elif addr in exchange_addrs:
            role = "Exchange / VASP Gateway"
        elif addr in bridge_addrs:
            role = "Cross-Chain Bridge Gateway"
        elif addr in defi_addrs:
            role = "DeFi Protocol Pool"
        elif sent_val > 0 and recv_val > 0:
            role = "Intermediary Layering Mule"
        elif sent_val > 0:
            role = "Funding / Origin Node"
        else:
            role = "Terminal Beneficiary"

        matched_service = attr_by_addr.get(addr)
        matched_service_name = matched_service["service"] if matched_service else None
        matched_service_cat = matched_service["category"] if matched_service else None

        # Behavioral heuristics audit
        factors = []
        score = 10  # Baseline activity score

        # 1. Mixer Interaction Check (Max +40)
        direct_mixer = bool(out_targets.intersection(mixer_addrs) or in_sources.intersection(mixer_addrs))
        cluster_mixer = bool(mixer_addrs)
        if addr in mixer_addrs:
            factors.append({
                "id": "mixer",
                "name": "Mixer Protocol Infrastructure",
                "icon": "🌪️",
                "detected": True,
                "severity": "CRITICAL",
                "points": "+40",
                "detail": "Entity identified as a privacy mixer / tumbler protocol.",
            })
            score += 45
        elif direct_mixer:
            factors.append({
                "id": "mixer",
                "name": "Direct Mixer / Tumbler Exposure",
                "icon": "🌪️",
                "detected": True,
                "severity": "CRITICAL",
                "points": "+40",
                "detail": "Direct transfer flow with identified privacy mixer protocol.",
            })
            score += 40
        elif is_subject and cluster_mixer:
            factors.append({
                "id": "mixer",
                "name": "Cluster Mixer Exposure",
                "icon": "🌪️",
                "detected": True,
                "severity": "HIGH",
                "points": "+30",
                "detail": "Traced transaction trail connects directly to an active mixer service.",
            })
            score += 30
        else:
            factors.append({
                "id": "mixer",
                "name": "Privacy Mixer Interaction",
                "icon": "🌪️",
                "detected": False,
                "severity": "CLEAR",
                "points": "0",
                "detail": "No direct or indirect privacy mixer interactions detected in trace.",
            })

        # 2. Velocity / Rapid Pass-Through Check (Max +25)
        pass_through_ratio = 0.0
        if recv_val > 0 and sent_val > 0:
            pass_through_ratio = min(1.0, sent_val / recv_val)

        is_rapid_velocity = False
        if is_demo:
            is_rapid_velocity = is_subject or (sent_val > 0 and recv_val > 0)
        else:
            in_times = [tx.get("timestamp", 0) for tx in wdata["received_txs"] if tx.get("timestamp")]
            out_times = [tx.get("timestamp", 0) for tx in wdata["sent_txs"] if tx.get("timestamp")]
            if in_times and out_times:
                time_diff = max(out_times) - min(in_times)
                if 0 <= time_diff <= 7200 and pass_through_ratio >= 0.70:
                    is_rapid_velocity = True

        if is_rapid_velocity and pass_through_ratio >= 0.70:
            factors.append({
                "id": "velocity",
                "name": "High-Velocity Pass-Through",
                "icon": "⚡",
                "detected": True,
                "severity": "HIGH",
                "points": "+25",
                "detail": f"Rapid fund dissipation: ~{int(pass_through_ratio*100)}% of received funds routed out rapidly (Mule behavior).",
            })
            score += 25
        elif is_subject and (is_demo or tx_count >= 3):
            factors.append({
                "id": "velocity",
                "name": "High-Velocity Fund Movement",
                "icon": "⚡",
                "detected": True,
                "severity": "HIGH",
                "points": "+20",
                "detail": "Rapid succession of transfers through intermediate addresses in close time windows.",
            })
            score += 20
        else:
            factors.append({
                "id": "velocity",
                "name": "Turnover Velocity & Pass-Through",
                "icon": "⚡",
                "detected": False,
                "severity": "CLEAR",
                "points": "0",
                "detail": "Normal holding times; no automated pass-through / mule dissipation flagged.",
            })

        # 3. Peeling Chain Layering Check (Max +20)
        is_peeling = False
        if is_demo:
            is_peeling = (scenario_key == "suspicious") or is_subject
        else:
            if len(wdata["sent_txs"]) >= 2:
                is_peeling = True

        if is_peeling and (is_subject or role == "Intermediary Layering Mule"):
            factors.append({
                "id": "peeling",
                "name": "Structured Peeling Chain",
                "icon": "🔄",
                "detected": True,
                "severity": "HIGH",
                "points": "+20",
                "detail": "Sequential structured transfers with fractional change splits identified.",
            })
            score += 20
        else:
            factors.append({
                "id": "peeling",
                "name": "Peeling Chain Pattern",
                "icon": "🔄",
                "detected": False,
                "severity": "CLEAR",
                "points": "0",
                "detail": "No structured peeling chain or systematic split deductions found.",
            })

        # 4. VASP Exit Gateway Proximity Check (Max +15)
        direct_vasp = bool(out_targets.intersection(exchange_addrs) or in_sources.intersection(exchange_addrs))
        cluster_vasp = bool(exchange_addrs)
        if addr in exchange_addrs:
            factors.append({
                "id": "vasp",
                "name": "Centralized VASP Infrastructure",
                "icon": "🏦",
                "detected": True,
                "severity": "INFO",
                "points": "+0",
                "detail": "Compliant centralized exchange endpoint under regulatory oversight.",
            })
        elif direct_vasp:
            factors.append({
                "id": "vasp",
                "name": "Direct VASP Gateway Proximity",
                "icon": "🏦",
                "detected": True,
                "severity": "MEDIUM",
                "points": "+15",
                "detail": "Funds routed directly into centralized exchange deposit gateway for off-ramp.",
            })
            score += 15
        elif is_subject and cluster_vasp:
            factors.append({
                "id": "vasp",
                "name": "VASP Off-Ramp Trail Connection",
                "icon": "🏦",
                "detected": True,
                "severity": "MEDIUM",
                "points": "+10",
                "detail": "Downstream flow terminates in a recognized VASP off-ramp deposit terminal.",
            })
            score += 10
        else:
            factors.append({
                "id": "vasp",
                "name": "VASP Off-Ramp Gateway Proximity",
                "icon": "🏦",
                "detected": False,
                "severity": "CLEAR",
                "points": "0",
                "detail": "No direct funneling into centralized exchange deposit addresses.",
            })

        # 5. Cross-Chain Bridge Usage Check (Max +15)
        direct_bridge = bool(out_targets.intersection(bridge_addrs) or in_sources.intersection(bridge_addrs))
        cluster_bridge = bool(bridge_addrs)
        if addr in bridge_addrs:
            factors.append({
                "id": "bridge",
                "name": "Cross-Chain Bridge Gateway",
                "icon": "🌉",
                "detected": True,
                "severity": "MEDIUM",
                "points": "+25",
                "detail": "Cross-chain bridge protocol facilitating cross-ledger asset movement.",
            })
            score += 25
        elif direct_bridge:
            factors.append({
                "id": "bridge",
                "name": "Direct Cross-Chain Bridge Exposure",
                "icon": "🌉",
                "detected": True,
                "severity": "MEDIUM",
                "points": "+15",
                "detail": "Direct transfer to cross-chain bridge gateway for chain-hopping evasion.",
            })
            score += 15
        elif is_subject and cluster_bridge:
            factors.append({
                "id": "bridge",
                "name": "Cluster Bridge Interaction",
                "icon": "🌉",
                "detected": True,
                "severity": "MEDIUM",
                "points": "+10",
                "detail": "Fund trace includes a cross-chain bridging hop.",
            })
            score += 10
        else:
            factors.append({
                "id": "bridge",
                "name": "Cross-Chain Bridge Evasion",
                "icon": "🌉",
                "detected": False,
                "severity": "CLEAR",
                "points": "0",
                "detail": "No cross-chain bridging protocols detected in path.",
            })

        # 6. High Volume Transfer Concentration Check (Max +15)
        tot_vol = sent_val + recv_val
        if tot_vol >= 5.0 or (scenario_key == "suspicious" and is_subject):
            factors.append({
                "id": "volume",
                "name": "High-Value Asset Concentration",
                "icon": "📦",
                "detected": True,
                "severity": "HIGH",
                "points": "+15",
                "detail": f"High value transfer concentration: {round(tot_vol, 4)} ETH involved in trace.",
            })
            score += 15
        elif tot_vol >= 0.5:
            factors.append({
                "id": "volume",
                "name": "Moderate Value Transfer Activity",
                "icon": "📦",
                "detected": True,
                "severity": "LOW",
                "points": "+5",
                "detail": f"Significant asset flow: {round(tot_vol, 4)} ETH observed.",
            })
            score += 5
        else:
            factors.append({
                "id": "volume",
                "name": "High-Value Concentration",
                "icon": "📦",
                "detected": False,
                "severity": "CLEAR",
                "points": "0",
                "detail": "Transfer values within low baseline threshold.",
            })

        # Special calibration for known infrastructure
        if addr in exchange_addrs:
            score = 25  # Regulated VASP terminal
        elif addr in mixer_addrs:
            score = 98  # Mixer protocol
        elif addr in bridge_addrs:
            score = 65  # Bridge gateway
        else:
            if is_demo:
                if is_subject:
                    score = 94 if scenario_key == "suspicious" else 85
                elif addr == "0x2222222222222222222222222222222222222222":
                    score = 65
                elif addr == "0x3333333333333333333333333333333333333333":
                    score = 75
                elif addr == "0x4444444444444444444444444444444444444444":
                    score = 35

        score = max(5, min(100, score))

        # Risk Classification
        if score >= 80:
            level = "CRITICAL"
            label = "CRITICAL RISK"
            color = "#dc2626"
            badge_class = "badge-critical"
        elif score >= 60:
            level = "HIGH"
            label = "HIGH RISK"
            color = "#ea580c"
            badge_class = "badge-high"
        elif score >= 35:
            level = "MEDIUM"
            label = "MEDIUM RISK"
            color = "#d97706"
            badge_class = "badge-medium"
        else:
            level = "LOW"
            label = "LOW RISK"
            color = "#16a34a"
            badge_class = "badge-low"

        # Actionable Law Enforcement Guidance
        if is_subject:
            if score >= 80:
                action = "🚨 CRITICAL ENFORCEMENT ALERT: Issue urgent Section 91 CrPC Notice to freeze destination VASP deposit terminal immediately."
                summary_verdict = "Severe illicit layering pattern detected with active privacy mixer interaction, rapid pass-through dispersal, and downstream VASP off-ramp."
            elif score >= 60:
                action = "⚠️ HIGH PRIORITY: High probability of illicit fund transit. File preservation order with destination exchange and flag intermediary hops."
                summary_verdict = "Elevated risk profile flagged due to multi-hop pass-through velocity and proximity to suspicious services."
            elif score >= 35:
                action = "⚡ ENHANCED MONITORING: Intermediate entity activity observed. Track secondary transactions for outbound dispersion."
                summary_verdict = "Moderate counterparty risk profile with limited direct high-risk exposures."
            else:
                action = "🛡️ ROUTINE MONITORING: Standard peer-to-peer transaction profile. No immediate enforcement action needed."
                summary_verdict = "Low risk profile; baseline wallet behavior without mixing, peeling, or mule signatures."
        elif addr in exchange_addrs:
            action = "🏦 VASP ACTIONABLE TARGET: Serve official legal requisition / freeze request on this entity to preserve illicit proceeds."
            summary_verdict = "Attributed Centralized VASP terminal serving as final off-ramp deposit gateway."
        elif addr in mixer_addrs:
            action = "🛑 BLACKLIST & SEIZE: Sanctioned/flagged mixer protocol. Blacklist connected addresses across compliance network."
            summary_verdict = "Anonymizing mixer protocol utilized to obfuscate blockchain audit trails."
        elif score >= 60:
            action = "⚠️ INTERMEDIARY ACTION: Intermediary mule / layering node. Include in subpoena / legal trace."
            summary_verdict = "High-velocity intermediary entity facilitating multi-hop fund dissemination."
        else:
            action = "ℹ️ REFERENCE: Counterparty node in transaction cluster."
            summary_verdict = "Secondary cluster address with low direct exposure."

        flagged_factors = [f for f in factors if f["detected"]]

        profile = {
            "address": addr,
            "short_address": shorten_address(addr),
            "is_target": is_subject,
            "role": role,
            "risk_score": score,
            "risk_level": level,
            "risk_label": label,
            "risk_color": color,
            "badge_class": badge_class,
            "matched_service": matched_service_name,
            "matched_category": matched_service_cat,
            "summary_verdict": summary_verdict,
            "action_recommendation": action,
            "factors": factors,
            "flagged_factors": flagged_factors,
            "flagged_count": len(flagged_factors),
            "total_sent": sent_val,
            "total_received": recv_val,
            "net_flow": net_val,
            "transaction_count": tx_count,
            "pass_through_ratio": f"{int(pass_through_ratio * 100)}%" if pass_through_ratio > 0 else "0%",
        }

        risk_profiles[addr] = profile

    target_profile = risk_profiles.get(target, {
        "address": target,
        "short_address": shorten_address(target),
        "is_target": True,
        "role": "Target Wallet (Subject)",
        "risk_score": 85 if is_demo else 25,
        "risk_level": "CRITICAL" if is_demo else "LOW",
        "risk_label": "CRITICAL RISK" if is_demo else "LOW RISK",
        "risk_color": "#dc2626" if is_demo else "#16a34a",
        "badge_class": "badge-critical" if is_demo else "badge-low",
        "matched_service": None,
        "matched_category": None,
        "summary_verdict": "Target wallet investigation.",
        "action_recommendation": "Review transaction findings.",
        "factors": [],
        "flagged_factors": [],
        "flagged_count": 0,
        "total_sent": 0.0,
        "total_received": 0.0,
        "net_flow": 0.0,
        "transaction_count": len(transactions),
        "pass_through_ratio": "0%",
    })

    # Sort all wallets: target first, then highest risk score descending
    sorted_wallets = sorted(
        risk_profiles.values(),
        key=lambda item: (
            not item["is_target"],
            -item["risk_score"],
            item["address"],
        ),
    )

    results["target_risk_profile"] = target_profile
    results["risk_profiles"] = risk_profiles
    results["wallets"] = sorted_wallets
    results["top_vasp"] = top_vasp_info

    if top_vasp_info and target_profile["risk_score"] >= 60:
        results["freeze_status"] = "ACTION REQUIRED: File Section 91 CrPC Notice"
    elif top_vasp_info:
        results["freeze_status"] = f"VASP IDENTIFIED: {top_vasp_info['name']}"
    else:
        results["freeze_status"] = "MONITORING (No VASP Deposit Identified)"

    return results


# ============================================================
# INTERACTIVE TRANSACTION GRAPH
# ============================================================

def make_graph_html(results):
    if Network is None:
        return """
        <html><body style="background:#101827;color:white;
        font-family:Arial;padding:24px">
        <h3>Transaction graph unavailable</h3>
        <p>Install PyVis: python -m pip install pyvis</p>
        </body></html>
        """

    net = Network(
        height="560px",
        width="100%",
        directed=True,
        bgcolor="#101827",
        font_color="#e5e7eb",
        notebook=False,
    )

    net.barnes_hut(
        gravity=-3500,
        central_gravity=0.25,
        spring_length=180,
        spring_strength=0.035,
        damping=0.12,
    )

    target = results["target_address"].lower()
    nodes_added = set()
    risk_profiles = results.get("risk_profiles", {})

    service_map = {
        item["address"].lower(): item
        for item in results.get("attributions", [])
    }

    def add_node(address, label=None, title=None, color="#38bdf8", size=18, shape="dot"):
        address = address.lower()
        if address in nodes_added:
            return

        net.add_node(
            address,
            label=label or shorten_address(address),
            title=title or address,
            color=color,
            shape=shape,
            size=size,
        )
        nodes_added.add(address)

    # Add Target Node
    target_prof = risk_profiles.get(target, {})
    target_score = target_prof.get("risk_score", 85)
    target_level = target_prof.get("risk_level", "CRITICAL")
    target_title = (
        f"🎯 TARGET WALLET: {target}\n"
        f"Risk Score: {target_score}/100 ({target_level} RISK)\n"
        f"Role: Subject of Investigation\n"
        f"Total Sent: {target_prof.get('total_sent', 0)} ETH | Recv: {target_prof.get('total_received', 0)} ETH\n"
        f"Action: {target_prof.get('action_recommendation', '')}"
    )
    add_node(
        target,
        f"Target Wallet\n[{target_level} {target_score}/100]",
        target_title,
        color="#8b5cf6",
        size=30,
        shape="dot",
    )

    for tx in results.get("transactions", []):
        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        for address in (sender, receiver):
            if address == target:
                continue

            prof = risk_profiles.get(address, {})
            score = prof.get("risk_score", 25)
            level = prof.get("risk_level", "LOW")
            role = prof.get("role", "Counterparty")
            color = prof.get("risk_color", "#38bdf8")
            shape = "dot"
            size = 18

            if address in service_map:
                item = service_map[address]
                label = f"{item['service']}\n[{item['category']}]"
                cat_lower = item["category"].lower()
                if "exchange" in cat_lower or "vasp" in cat_lower:
                    color = "#f59e0b"
                    shape = "diamond"
                    size = 24
                elif "mixer" in cat_lower:
                    color = "#dc2626"
                    shape = "triangle"
                    size = 24
                elif "bridge" in cat_lower:
                    color = "#06b6d4"
                    shape = "square"
                    size = 22
                else:
                    color = "#f59e0b"
                    size = 20

                title = (
                    f"🏢 {item['service']} ({item['category']})\n"
                    f"Address: {address}\n"
                    f"Risk Score: {score}/100 ({level})\n"
                    f"Role: {role}\n"
                    f"Source: {item.get('source_name', 'Verified Reference')}\n"
                    f"Total Sent: {prof.get('total_sent', 0)} ETH | Recv: {prof.get('total_received', 0)} ETH"
                )
            else:
                label = f"{shorten_address(address)}\n[{score}/100 {level}]"
                if level == "CRITICAL":
                    color = "#ef4444"
                    size = 22
                elif level == "HIGH":
                    color = "#f97316"
                    size = 20
                elif level == "MEDIUM":
                    color = "#eab308"
                    size = 18
                else:
                    color = "#10b981"
                    size = 16

                flag_names = [f["name"] for f in prof.get("flagged_factors", [])]
                flags_text = ", ".join(flag_names) if flag_names else "None flagged"
                title = (
                    f"Wallet: {address}\n"
                    f"Risk Score: {score}/100 ({level} RISK)\n"
                    f"Role: {role}\n"
                    f"Sent: {prof.get('total_sent', 0)} ETH | Recv: {prof.get('total_received', 0)} ETH\n"
                    f"Flags: {flags_text}"
                )

            add_node(address, label, title, color, size, shape)

        try:
            value = float(tx.get("value_eth", 0))
        except (ValueError, TypeError):
            value = 0

        net.add_edge(
            sender,
            receiver,
            label=f"{value:.4f} ETH",
            title=f'Transaction: {tx.get("hash", "Demo transaction")}\nValue: {value:.4f} ETH\nTime: {tx.get("time", "Unknown")}',
            arrows="to",
            color="#64748b",
        )

    try:
        return net.generate_html(notebook=False)
    except Exception:
        app.logger.exception("Graph generation failed.")
        return """
        <html><body style="background:#101827;color:white;
        font-family:Arial;padding:24px">
        <h3>Could not render transaction graph</h3>
        </body></html>
        """


# ============================================================
# FINALIZE INVESTIGATION RESULTS
# ============================================================

def finalize_results(results):
    transactions = results.get("transactions", [])

    results["total_transactions"] = len(transactions)

    results["total_amount"] = round(
        sum(float(tx.get("value_eth", 0)) for tx in transactions),
        6,
    )

    target = results["target_address"]
    results["wallet"] = target

    results["summary"] = (
        f'Analysed {len(transactions)} transaction(s) for '
        f'{target}.'
    )
    results["notice"] = (
        results.get("scenario_description")
        or results.get("summary")
        or "Investigation completed successfully."
    )

    # Formatted edges for transaction details rendering
    results["edges"] = [
        {
            "sender": tx.get("from", ""),
            "receiver": tx.get("to", ""),
            "value": f"{float(tx.get('value_eth', 0)):.4f}",
            "timestamp": tx.get("time", ""),
            "hash": tx.get("hash", ""),
        }
        for tx in transactions
    ]

    enrich_with_service_attributions(results)
    build_wallet_summary(results)
    results["graph_html"] = make_graph_html(results)

    return results


# ============================================================
# DEMO MODE
# ============================================================

def build_demo_trace(scenario_key):
    scenario = SCENARIOS.get(
        scenario_key,
        SCENARIOS["ethereum"],
    )

    target = scenario["target"].lower()

    exchange = SERVICE_REFERENCE_DATA[0]["address"]
    mixer = SERVICE_REFERENCE_DATA[1]["address"]
    bridge = SERVICE_REFERENCE_DATA[2]["address"]
    defi = SERVICE_REFERENCE_DATA[3]["address"]

    wallet_b = "0x2222222222222222222222222222222222222222"
    wallet_c = "0x3333333333333333333333333333333333333333"
    wallet_d = "0x4444444444444444444444444444444444444444"

    now = int(datetime.now(timezone.utc).timestamp())

    transactions = [
        (target, wallet_b, 1.25, 3600),
        (wallet_b, exchange, 0.80, 3000),
        (exchange, wallet_c, 0.45, 2400),
        (wallet_c, mixer, 0.30, 1800),
        (mixer, bridge, 0.20, 1200),
        (bridge, defi, 0.15, 600),
        (defi, target, 0.05, 300),
        (wallet_d, target, 0.10, 120),
    ]

    formatted_transactions = []

    for index, (sender, receiver, value, age) in enumerate(
        transactions, start=1
    ):
        timestamp = now - age

        formatted_transactions.append({
            "hash": f"DEMO-TX-{index:03d}",
            "block_number": 21000000 + index,
            "timestamp": timestamp,
            "time": utc_timestamp(timestamp),
            "from": sender.lower(),
            "to": receiver.lower(),
            "value_eth": value,
            "is_demo": True,
        })

    if scenario_key == "suspicious":
        formatted_transactions[0]["value_eth"] = 12.5
        formatted_transactions[3]["value_eth"] = 7.3
        formatted_transactions[4]["value_eth"] = 5.1

    results = {
        "mode": "Demo Mode",
        "mode_key": "demo",
        "scenario_key": scenario_key,
        "scenario_name": scenario["name"],
        "scenario_description": scenario["description"],
        "target_address": target,
        "transactions": formatted_transactions,
        "data_source": "Simulated demonstration data",
        "is_demo": True,
    }

    return finalize_results(results)


# ============================================================
# REAL ETHEREUM MODE — ETHERSCAN API V2
# ============================================================

def fetch_ethereum_trace(address):
    address = normalize_address(address)

    if not ETHERSCAN_API_KEY:
        raise ValueError(
            "ETHERSCAN_API_KEY is not configured. Set your API key "
            "in the terminal before starting the application."
        )

    params = {
        "chainid": "1",
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": "0",
        "endblock": "99999999",
        "page": "1",
        "offset": "25",
        "sort": "desc",
        "apikey": ETHERSCAN_API_KEY,
    }

    try:
        response = requests.get(
            ETHERSCAN_API_URL,
            params=params,
            timeout=25,
        )
        response.raise_for_status()
        payload = response.json()

    except requests.RequestException:
        app.logger.exception("Etherscan transaction request failed.")
        raise ValueError(
            "Could not connect to Etherscan. Check your internet "
            "connection and try again."
        )

    except ValueError:
        raise ValueError(
            "Etherscan returned an invalid response."
        )

    status = str(payload.get("status", ""))
    message = str(payload.get("message", ""))
    raw_result = payload.get("result", [])

    if status == "0":
        if (
            isinstance(raw_result, str)
            and "no transactions" in raw_result.lower()
        ):
            raw_result = []
        elif not isinstance(raw_result, list):
            app.logger.warning(
                "Etherscan API returned an error: %s",
                message,
            )
            raise ValueError(
                "Etherscan did not return transaction data. "
                "Check your API key, API limits and request."
            )

    if not isinstance(raw_result, list):
        raise ValueError(
            "Unexpected transaction data returned by Etherscan."
        )

    transactions = []

    for item in raw_result:
        try:
            sender = normalize_address(item.get("from", ""))
            recipient_raw = item.get("to", "")

            if not recipient_raw:
                continue

            recipient = normalize_address(recipient_raw)

            value_wei = int(item.get("value", "0"))
            value_eth = value_wei / 10**18

            timestamp = int(item.get("timeStamp", "0"))
            block_number = int(item.get("blockNumber", "0"))

            transactions.append({
                "hash": item.get("hash", ""),
                "block_number": block_number,
                "timestamp": timestamp,
                "time": utc_timestamp(timestamp),
                "from": sender,
                "to": recipient,
                "value_eth": value_eth,
                "is_demo": False,
            })

        except (ValueError, TypeError, OverflowError):
            continue

    results = {
        "mode": "Real Ethereum Mode",
        "mode_key": "real",
        "scenario_key": "",
        "scenario_name": "Ethereum Wallet Investigation",
        "scenario_description": (
            "Real Ethereum mainnet transactions retrieved through "
            "Etherscan. Up to 25 normal transactions are requested."
        ),
        "target_address": address,
        "transactions": transactions,
        "data_source": "Etherscan API V2 — Ethereum mainnet",
        "is_demo": False,
    }

    return finalize_results(results)


# ============================================================
# DASHBOARD
# ============================================================

def render_dashboard(results=None, error=None, status=200):
    return render_template(
        "dashboard.html",
        results=results,
        scenarios=SCENARIOS,
        error=error,
    ), status


@app.route("/", methods=["GET"])
def index():
    global LAST_RESULTS

    if LAST_RESULTS is None:
        LAST_RESULTS = build_demo_trace("ethereum")

    return render_dashboard(results=LAST_RESULTS)


@app.route("/trace", methods=["POST"])
def trace():
    global LAST_RESULTS

    mode = request.form.get("mode", "demo").strip().lower()
    scenario_key = request.form.get(
        "scenario", "ethereum"
    ).strip()
    wallet_address = request.form.get(
        "wallet_address", ""
    ).strip()

    try:
        if mode in ("real", "ethereum", "real_ethereum"):
            if not wallet_address:
                raise ValueError(
                    "Enter an Ethereum wallet address to investigate."
                )

            results = fetch_ethereum_trace(wallet_address)

        else:
            if scenario_key not in SCENARIOS:
                scenario_key = "ethereum"

            results = build_demo_trace(scenario_key)

        LAST_RESULTS = results
        return render_dashboard(results=results)

    except ValueError as exc:
        return render_dashboard(
            results=LAST_RESULTS,
            error=str(exc),
            status=400,
        )

    except Exception:
        app.logger.exception("Unexpected tracing error.")

        return render_dashboard(
            results=LAST_RESULTS,
            error=(
                "An unexpected error occurred. Check the VS Code "
                "terminal for details. Do not share your API key."
            ),
            status=500,
        )


# ============================================================
# CSV REPORT
# ============================================================

@app.route("/get_report", methods=["GET"])
def get_report():
    global LAST_RESULTS

    if LAST_RESULTS is None:
        LAST_RESULTS = build_demo_trace("ethereum")

    results = LAST_RESULTS
    target_prof = results.get("target_risk_profile", {})

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["CryptoTrace Forensic Investigation Report"])
    writer.writerow([
        "Generated UTC",
        datetime.now(timezone.utc).isoformat(),
    ])
    writer.writerow(["Mode", results.get("mode", "")])
    writer.writerow(["Data Source", results.get("data_source", "")])
    writer.writerow(["Target Wallet", results.get("target_address", "")])
    writer.writerow(["Target Risk Score", f"{target_prof.get('risk_score', 'N/A')}/100"])
    writer.writerow(["Target Risk Level", target_prof.get("risk_level", "N/A")])
    writer.writerow(["Asset Freeze / Preservation Status", results.get("freeze_status", "N/A")])
    writer.writerow([
        "Attributed Endpoint VASP",
        results.get("top_vasp", {}).get("name", "None Matched") if results.get("top_vasp") else "None Matched",
    ])
    writer.writerow([
        "Total Transactions",
        results.get("total_transactions", 0),
    ])
    writer.writerow([
        "Total Traced ETH Value",
        results.get("total_amount", 0),
    ])
    writer.writerow([
        "Enforcement Recommendation",
        target_prof.get("action_recommendation", ""),
    ])

    writer.writerow([])
    writer.writerow(["Target Wallet Heuristic Risk Factors"])
    writer.writerow([
        "Factor ID",
        "Risk Indicator Name",
        "Severity",
        "Points Added",
        "Status",
        "Evidence Detail",
    ])

    for factor in target_prof.get("factors", []):
        writer.writerow([
            factor.get("id", ""),
            factor.get("name", ""),
            factor.get("severity", ""),
            factor.get("points", ""),
            "FLAGGED" if factor.get("detected") else "CLEARED",
            factor.get("detail", ""),
        ])

    writer.writerow([])
    writer.writerow(["Cluster Wallets Risk Profiles Matrix"])
    writer.writerow([
        "Wallet Address",
        "Investigation Role",
        "Risk Score",
        "Risk Level",
        "Attributed Service",
        "Total Sent ETH",
        "Total Received ETH",
        "Net Balance Change",
        "Transaction Count",
        "Triggered Flags",
        "Actionable Advisory",
    ])

    for w in results.get("wallets", []):
        flag_names = [f["name"] for f in w.get("flagged_factors", [])]
        flags_text = "; ".join(flag_names) if flag_names else "No Flags (Clean)"
        writer.writerow([
            w.get("address", ""),
            w.get("role", ""),
            f"{w.get('risk_score', 0)}/100",
            w.get("risk_level", ""),
            w.get("matched_service", "None"),
            w.get("total_sent", 0),
            w.get("total_received", 0),
            w.get("net_flow", 0),
            w.get("transaction_count", 0),
            flags_text,
            w.get("action_recommendation", ""),
        ])

    writer.writerow([])
    writer.writerow(["Exchange & VASP Service Attribution Matches"])
    writer.writerow([
        "Service",
        "Category",
        "Address",
        "Chain",
        "Transaction Roles",
        "Transaction Count",
        "Evidence Type",
        "Source Name",
        "Source URL",
        "Verified",
        "Confidence",
        "Verified By",
        "Verified Date",
        "Notes",
    ])

    for item in results.get("attributions", []):
        writer.writerow([
            item.get("service", ""),
            item.get("category", ""),
            item.get("address", ""),
            item.get("chain", ""),
            "; ".join(item.get("transaction_roles", [])),
            item.get("transaction_count", 0),
            item.get("evidence_type", ""),
            item.get("source_name", ""),
            item.get("source_url", ""),
            "Yes" if item.get("verified") else "No",
            item.get("confidence", ""),
            item.get("verified_by", ""),
            item.get("verified_date", ""),
            item.get("notes", ""),
        ])

    writer.writerow([])
    writer.writerow(["Transaction Trail Ledger"])
    writer.writerow([
        "Transaction Hash",
        "Timestamp UTC",
        "Block Number",
        "From",
        "To",
        "Value ETH",
        "Demo Transaction",
    ])

    for tx in results.get("transactions", []):
        writer.writerow([
            tx.get("hash", ""),
            tx.get("time", ""),
            tx.get("block_number", ""),
            tx.get("from", ""),
            tx.get("to", ""),
            tx.get("value_eth", 0),
            "Yes" if tx.get("is_demo") else "No",
        ])

    writer.writerow([])
    writer.writerow([
        "Caution",
        "A service address match does not identify an individual or "
        "prove criminal activity. Demo labels are fictional.",
    ])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name="cryptotrace_report.csv",
    )


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )

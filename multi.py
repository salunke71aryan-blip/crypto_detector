import time
from pyvis.network import Network

# --- EXPANDED SIMULATED DATA FOR TESTING SCENARIOS ---
blockchain_ledger = [
    # Scenario A: Standard multi-hop scam trail ending in Binance
    {"from": "victim_wallet_1", "to": "scammer_wallet_A", "amount": 5.0, "txid": "0xfa719...3b1"},
    {"from": "scammer_wallet_A", "to": "burner_wallet_B", "amount": 4.8, "txid": "0xbc882...9e2"},
    {"from": "burner_wallet_B", "to": "burner_wallet_C", "amount": 4.5, "txid": "0xde431...1a6"},
    {"from": "burner_wallet_C", "to": "Binance_Deposit", "amount": 4.4, "txid": "0x3310a...7c9"},
    
    # Scenario B: High velocity task-scam trail ending in WazirX
    {"from": "victim_wallet_2", "to": "phishing_hub_X", "amount": 12.5, "txid": "0xaa112...8d1"},
    {"from": "phishing_hub_X", "to": "mixer_input_Y", "amount": 12.1, "txid": "0xff432...4b9"},
    {"from": "mixer_input_Y", "to": "WazirX_Deposit", "amount": 11.9, "txid": "0xcc991...2e4"}
]

known_vasps = {
    "Binance_Deposit": "Binance International",
    "WazirX_Deposit": "WazirX India"
}

wallet_profiles = {
    "victim_wallet_1": {"tx_count": 2, "hours_active": 720, "mixers_touched": False, "peeling_detected": False},
    "scammer_wallet_A": {"tx_count": 45, "hours_active": 4, "mixers_touched": False, "peeling_detected": True},
    "burner_wallet_B": {"tx_count": 112, "hours_active": 1, "mixers_touched": True, "peeling_detected": True},
    "burner_wallet_C": {"tx_count": 89, "hours_active": 2, "mixers_touched": False, "peeling_detected": True},
    "Binance_Deposit": {"tx_count": 150000, "hours_active": 43200, "mixers_touched": False, "peeling_detected": False},
    
    "victim_wallet_2": {"tx_count": 1, "hours_active": 500, "mixers_touched": False, "peeling_detected": False},
    "phishing_hub_X": {"tx_count": 410, "hours_active": 3, "mixers_touched": False, "peeling_detected": True},
    "mixer_input_Y": {"tx_count": 921, "hours_active": 1, "mixers_touched": True, "peeling_detected": False},
    "WazirX_Deposit": {"tx_count": 98000, "hours_active": 20000, "mixers_touched": False, "peeling_detected": False}
}

# --- RISK SCORING ENGINE ---
def calculate_wallet_risk(wallet_id):
    profile = wallet_profiles.get(wallet_id, {"tx_count": 1, "hours_active": 24, "mixers_touched": False, "peeling_detected": False})
    score = 10
    factors = []

    if profile["tx_count"] > 30 and profile["hours_active"] < 12:
        score += 30
        factors.append("High Transaction Velocity in short lifespan (+30%)")
    if profile["mixers_touched"]:
        score += 40
        factors.append("Direct/Indirect Mixer Protocol connection (+40%)")
    if profile["peeling_detected"]:
        score += 20
        factors.append("Active Fund-Peeling pattern identified (+20%)")

    score = min(score, 100)
    category = "CRITICAL RISK" if score >= 80 else "HIGH RISK" if score >= 50 else "MEDIUM RISK" if score >= 25 else "LOW RISK"
    return {"score": score, "category": category, "factors": factors}

# --- AUTOMATED BLOCKCHAIN TRACING ---
def trace_stolen_funds(starting_wallet, max_hops=5):
    print(f"\n🕵️‍♂️ [Tech Titans Engine] Initiating automated trace for target...")
    time.sleep(0.4)
    current_wallet = starting_wallet
    path = [current_wallet]
    visual_edges = []
    
    for hop in range(1, max_hops + 1):
        found_next_tx = False
        for tx in blockchain_ledger:
            if tx["from"] == current_wallet:
                visual_edges.append(tx)
                path.append(tx["to"])
                current_wallet = tx["to"]
                found_next_tx = True
                break 
        
        if current_wallet in known_vasps:
            exchange_name = known_vasps[current_wallet]
            print(f"🚨 TARGET ATTAINED: Extracted attribution link to VASP [{exchange_name}]")
            return {"status": "SUCCESS", "exchange": exchange_name, "target_wallet": current_wallet, "path": path, "edges": visual_edges}
            
        if not found_next_tx:
            print(f"🛑 Money trail went cold at: {current_wallet}")
            return {"status": "COLD_TRAIL", "last_known_wallet": current_wallet, "path": path, "edges": visual_edges}

    return {"status": "MAX_HOPS_EXCEEDED", "path": path, "edges": visual_edges}

# --- INTERACTIVE WEB GRAPH VISUALIZER ---
def generate_interactive_graph(trace_results):
    net = Network(height="650px", width="100%", heading="Tech Titans - Crypto Intelligence Dashboard", directed=True)
    all_nodes = set([e["from"] for e in trace_results["edges"]] + [e["to"] for e in trace_results["edges"]])

    for node in all_nodes:
        display_label = node.replace("_wallet_", "\n").replace("_Deposit", "\nExchange")
        risk_data = calculate_wallet_risk(node)
        
        hover_info = f"Wallet: {node}\nRisk Status: {risk_data['category']} ({risk_data['score']}%)\n"
        hover_info += "Flagged: " + ", ".join(risk_data['factors']) if risk_data['factors'] else "Flagged: None"

        if "victim" in node:
            net.add_node(node, label=display_label, title=hover_info, color="#2ecc71", size=25)
        elif node == trace_results.get("target_wallet"):
            net.add_node(node, label=display_label, title=hover_info, color="#9b59b6", size=32, shape="diamond")
        else:
            node_color = "#e74c3c" if risk_data['score'] >= 80 else "#e67e22" if risk_data['score'] >= 50 else "#3498db"
            net.add_node(node, label=display_label, title=hover_info, color=node_color, size=20)

    for edge in trace_results["edges"]:
        net.add_edge(edge["from"], edge["to"], title=f"TxID: {edge['txid']}", label=f"{edge['amount']} Crypto")

    net.write_html("crypto_map.html")

# --- AUTOMATED REPORT GENERATOR ---
def generate_investigation_report(trace_results):
    filename = "investigation_report.md"
    current_date = "2026-10-10"
    
    report_content = f"# ⚖️ CRYPTO FRAUD FORENSIC INTELLIGENCE REPORT\n**Generated By:** Tech Titans Automated Platform\n**Status:** EVIDENCE COMPILED\n\n## Summary\n* **Source:** `{trace_results['path'][0]}`\n* **Destination VASP:** **{trace_results['exchange']}**\n* **Endpoint Wallet:** `{trace_results['target_wallet']}`\n"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_content)

# --- NEW: LIVE USER COMMAND LOOP ---
def run_cli_console():
    print("=" * 60)
    print("🛡️  TECH TITANS - REAL-TIME CRYPTO FRAUD ATTRIBUTION CONSOLE 🛡️")
    print("=" * 60)
    print("💡 Available test wallet options:")
    print("  1) Type 'victim_wallet_1' (Traces scam loop -> Binance)")
    print("  2) Type 'victim_wallet_2' (Traces high-velocity loop -> WazirX)")
    print("  3) Type 'exit' to terminate engine console.")
    print("-" * 60)

    while True:
        user_input = input("\n🔍 Enter suspect wallet address to analyze: ").strip()
        
        if user_input.lower() == 'exit':
            print("👋 Shutting down intelligence core. Goodbye!")
            break
            
        if user_input not in ["victim_wallet_1", "victim_wallet_2"]:
            print("❌ Wallet not found in local index ledger data. Please enter 'victim_wallet_1' or 'victim_wallet_2'.")
            continue
            
        # Execute the pipeline on the user's specific input
        trace_output = trace_stolen_funds(user_input)
        
        if trace_output["status"] == "SUCCESS":
            generate_interactive_graph(trace_output)
            generate_investigation_report(trace_output)
            print("✅ Core processing complete!")
            print("👉 Open 'crypto_map.html' to see this specific tracking map visual.")
            print("👉 Open 'investigation_report.md' for the refreshed evidence log documentation.")
        else:
            print("⚠️ Trace finished without matching any known exchange destination terminal.")

if __name__ == "__main__":
    run_cli_console()

import json
import sys

incidents_path = "data/processed/dashboard/incidents.json"
chains_path = "data/processed/attack_chains_v4/reconstructed_attack_chains.json"

target_chain_id = sys.argv[1] if len(sys.argv) > 1 else "GATV2_CHAIN_000001"

with open(incidents_path, "r") as f:
    incidents = json.load(f)

with open(chains_path, "r") as f:
    raw_chains = json.load(f)

incident = next((x for x in incidents if x["chain_id"] == target_chain_id), None)
raw_chain = next((x for x in raw_chains if x["chain_id"] == target_chain_id), None)

if not incident or not raw_chain:
    print(f"Chain {target_chain_id} not found.")
    sys.exit(1)

print("\n" + "=" * 70)
print(f"ATTACK CHAIN NODE TRACE: {target_chain_id}")
print("=" * 70)

print(f"Severity             : {incident.get('severity')}")
print(f"Total Correlated Events: {incident.get('num_events')} events")
print(f"Unique Techniques    : {incident.get('num_unique_techniques')}")
print(f"Average GAT Confidence: {incident.get('average_confidence') * 100:.2f}%\n")

print("--- ATT&CK Representations ---")
print("DETAILED EVENT CHAIN:")
print(f"  {incident.get('original_event_chain')}\n")

print("SIMPLIFIED ATT&CK NARRATIVE:")
print(f"  {incident.get('simplified_technique_sequence')}\n")

print("--- Entity Information ---")
print("Affected Hosts :", incident.get("hosts", []))
print("User Accounts  :", incident.get("users", []))
print("Processes      :", incident.get("processes", [])[:5])

print("\n" + "=" * 70)
print("EXPLICIT EVENT NODE TRACE (Graph Node Indices -> Predicted Technique)")
print("=" * 70)

events = raw_chain.get("events", [])
techniques = raw_chain.get("techniques", [])

for i, (node_id, tech) in enumerate(zip(events, techniques), start=1):
    print(f"  Step {i:2d} | Event Node ID: {node_id:6d} | MITRE Technique: {tech}")

print("=" * 70)
print(f"End of trace for {target_chain_id}.")
print("=" * 70)

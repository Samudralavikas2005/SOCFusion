import json
import csv
import os
from src.attack_chain.simplifier import simplify_technique_chain

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data/processed/attack_chains_v4/reconstructed_attack_chains.json"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "data/processed/dashboard"
)

JSON_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "incidents.json"
)

CSV_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "incidents.csv"
)


def calculate_severity(chain):
    """
    Assign dashboard severity using:
    - number of unique MITRE techniques
    - chain length
    - prediction confidence

    This is a SOCFusion presentation score,
    not ground-truth severity.
    """

    unique = chain["num_unique_techniques"]
    events = chain["num_events"]
    confidence = chain["average_confidence"]

    score = 0

    if unique >= 5:
        score += 4
    elif unique >= 3:
        score += 3
    elif unique >= 2:
        score += 2
    else:
        score += 1

    if events >= 20:
        score += 3
    elif events >= 10:
        score += 2
    elif events >= 5:
        score += 1

    if confidence >= 0.75:
        score += 2
    elif confidence >= 0.50:
        score += 1

    if score >= 7:
        return "CRITICAL"
    elif score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


class EntityResolver:
    """
    Resolves numerical entity IDs (Hosts, Users, Processes) into human-readable string names
    using event feature telemetry and master node mappings.
    """
    def __init__(self, base_dir):
        features_path = os.path.join(base_dir, "data/processed/features_v4/features.csv")
        self.rows = []
        if os.path.exists(features_path):
            with open(features_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    self.rows.append(r)

        self.proc_map = {}
        for gdir in ["graphs_v4", "graphs_v3", "graphs_v2", "graphs_v1"]:
            for part in ["test", "val", "train"]:
                path = os.path.join(base_dir, f"data/processed/{gdir}/node_mappings/{part}_process_map.json")
                if os.path.exists(path):
                    with open(path) as f:
                        for k, v in json.load(f).items():
                            if v not in self.proc_map:
                                self.proc_map[v] = k

    def resolve(self, events, raw_hosts, raw_users, raw_procs):
        # 1. Hosts from event telemetry
        hosts = set()
        for e in events:
            if e < len(self.rows):
                h = self.rows[e].get("host", "").strip()
                if h:
                    hosts.add(h)
        if not hosts:
            hosts = set(f"Host-{h}" for h in raw_hosts)

        # 2. Users from event telemetry
        users = set()
        for e in events:
            if e < len(self.rows):
                u = self.rows[e].get("user", "").strip()
                if u and u not in ["-", "NOT_TRANSLATED"]:
                    users.add(u)
        if not users:
            for e in events:
                if e < len(self.rows):
                    u = self.rows[e].get("user", "").strip()
                    if u:
                        users.add(u)
        if not users:
            users = set(f"User-{u}" for u in raw_users)

        # 3. Processes from event telemetry or process node map
        procs = set()
        for e in events:
            if e < len(self.rows):
                p = (
                    self.rows[e].get("process_name", "")
                    or self.rows[e].get("process_path", "")
                    or self.rows[e].get("command_line", "")
                ).strip()
                if p and p != "-":
                    procs.add(p)
        if not procs:
            for p_id in raw_procs:
                if p_id in self.proc_map:
                    procs.add(self.proc_map[p_id])
                else:
                    procs.add(f"Process-{p_id}")

        return sorted(list(hosts)), sorted(list(users)), sorted(list(procs))


def create_incident(chain, resolver=None):
    raw_techniques = chain.get("techniques", [])
    collapsed_techniques = chain.get("collapsed_techniques", raw_techniques)

    simplified_techniques = chain.get("simplified_techniques")
    if simplified_techniques is None:
        simplified_techniques = simplify_technique_chain(
            raw_techniques or collapsed_techniques
        )

    if resolver:
        host_names, user_names, proc_names = resolver.resolve(
            chain.get("events", []),
            chain.get("hosts", []),
            chain.get("users", []),
            chain.get("processes", [])
        )
    else:
        host_names = [f"Host-{h}" for h in chain["hosts"]]
        user_names = [f"User-{u}" for u in chain["users"]]
        proc_names = [f"Process-{p}" for p in chain["processes"]]

    return {
        "chain_id": chain["chain_id"],

        "severity": calculate_severity(chain),

        "num_events": chain["num_events"],

        "num_unique_techniques":
            chain["num_unique_techniques"],

        "num_simplified_techniques":
            len(simplified_techniques),

        "techniques": collapsed_techniques,

        "technique_sequence":
            " -> ".join(collapsed_techniques),

        "original_event_chain":
            " -> ".join(collapsed_techniques),

        "simplified_techniques":
            simplified_techniques,

        "simplified_technique_sequence":
            " -> ".join(simplified_techniques),

        "unique_techniques":
            chain["unique_techniques"],

        "average_confidence":
            round(chain["average_confidence"], 4),

        "hosts": host_names,

        "host_ids": chain["hosts"],

        "users": user_names,

        "user_ids": chain["users"],

        "processes": proc_names,

        "process_ids": chain["processes"],

        "first_event":
            chain["events"][0] if chain["events"] else None,

        "last_event":
            chain["events"][-1] if chain["events"] else None
    }


def main():

    print("=" * 70)
    print("SOCFusion DASHBOARD INCIDENT GENERATOR")
    print("=" * 70)

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Input file not found:\n{INPUT_FILE}"
        )

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"\nLoading:")
    print(INPUT_FILE)

    with open(INPUT_FILE, "r") as f:
        chains = json.load(f)

    print("Building entity resolver for Hosts, Users, and Processes...")
    resolver = EntityResolver(BASE_DIR)

    incidents = [
        create_incident(chain, resolver)
        for chain in chains
    ]

    # --------------------------------------------------
    # JSON
    # --------------------------------------------------

    with open(JSON_OUTPUT, "w") as f:
        json.dump(
            incidents,
            f,
            indent=2
        )

    # --------------------------------------------------
    # CSV
    # --------------------------------------------------

    fieldnames = [
        "chain_id",
        "severity",
        "num_events",
        "num_unique_techniques",
        "num_simplified_techniques",
        "technique_sequence",
        "simplified_technique_sequence",
        "average_confidence",
        "hosts",
        "users",
        "processes",
        "first_event",
        "last_event"
    ]

    with open(
        CSV_OUTPUT,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for incident in incidents:

            row = {
                "chain_id":
                    incident["chain_id"],

                "severity":
                    incident["severity"],

                "num_events":
                    incident["num_events"],

                "num_unique_techniques":
                    incident["num_unique_techniques"],

                "num_simplified_techniques":
                    incident["num_simplified_techniques"],

                "technique_sequence":
                    incident["technique_sequence"],

                "simplified_technique_sequence":
                    incident["simplified_technique_sequence"],

                "average_confidence":
                    incident["average_confidence"],

                "hosts":
                    ",".join(
                        map(str, incident["hosts"])
                    ),

                "users":
                    ",".join(
                        map(str, incident["users"])
                    ),

                "processes":
                    ",".join(
                        map(str, incident["processes"])
                    ),

                "first_event":
                    incident["first_event"],

                "last_event":
                    incident["last_event"]
            }

            writer.writerow(row)

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    severity_counts = {}

    for incident in incidents:

        severity = incident["severity"]

        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

    print("\n" + "=" * 70)
    print("DASHBOARD DATASET CREATED")
    print("=" * 70)

    print(f"\nTotal incidents: {len(incidents)}")

    print("\nSeverity distribution:")

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:

        print(
            f"{severity:8s}: "
            f"{severity_counts.get(severity, 0)}"
        )

    print("\nOutput files:")
    print("-" * 70)
    print(JSON_OUTPUT)
    print(CSV_OUTPUT)

    print("\nSOCFusion dashboard incident dataset ready.")


if __name__ == "__main__":
    main()

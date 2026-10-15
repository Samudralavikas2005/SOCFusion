import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from generate_report_helpers import (
    set_cell_background, set_cell_margins, add_header_styled,
    add_p, add_callout, add_code_block, format_table
)

def expand_document():
    doc = docx.Document("SOCFusion_Comprehensive_Project_Report.docx")
    print("Expanding document with comprehensive academic sections...")

    # Set 1.35 line spacing across all existing paragraphs for thesis formatting
    for p in doc.paragraphs:
        if not p.paragraph_format.line_spacing:
            p.paragraph_format.line_spacing = 1.35
        p.paragraph_format.space_after = Pt(6)

    # -------------------------------------------------------------
    # EXPANDED SECTION: CHAPTER 2 DEEP THEORETICAL DERIVATIONS
    # -------------------------------------------------------------
    add_header_styled(doc, "2.4.4 Mathematical Proof: Why Dynamic Attention Outperforms Static GAT", level=2)
    add_p(doc,
        "To rigorously formalize why Graph Attention Networks Version 2 (GAT V2) are required for cybersecurity telemetry, we examine the mathematical proof established by Brody, Alon, and Yahav (ICLR 2022). "
        "Consider a graph vertex v_i connected to neighboring vertices v_j in N_i. In the original GAT V1 formulation (Veličković et al., 2018), the attention score e(h_i, h_j) before softmax is defined as: "
        "e_V1(h_i, h_j) = LeakyReLU( a^T [W h_i || W h_j] ), "
        "where W in R^{d' x d} is a learned shared projection matrix, || represents vector concatenation, and a in R^{2d'} is a weight vector. "
        "Splitting a into two components a = [a_l || a_r], where a_l, a_r in R^{d'}, the formulation can be rewritten linearly inside the activation function as: "
        "e_V1(h_i, h_j) = LeakyReLU( a_l^T W h_i + a_r^T W h_j ).",
        space_after=8, line_spacing=1.35
    )
    add_p(doc,
        "Crucially, observe the mathematical structure of this equation: the term a_l^T W h_i is an additive scalar that depends exclusively on query node h_i, while a_r^T W h_j depends exclusively on key node h_j. "
        "Because the LeakyReLU function is strictly monotonic (i.e., LeakyReLU(x) = x for x >= 0, and alpha * x for x < 0 where 0 < alpha < 1), for any fixed query node h_i, the relative ordering of attention scores between any two neighbors h_j and h_k is determined entirely by the comparison between a_r^T W h_j and a_r^T W h_k. "
        "Therefore, if a_r^T W h_j > a_r^T W h_k for one query node, then e_V1(h_i, h_j) > e_V1(h_i, h_k) holds for EVERY query node in the entire graph. "
        "This proves that GAT V1 cannot compute dynamic query-dependent attention: the ranking of neighbor importance is globally static.",
        space_after=8, line_spacing=1.35
    )
    add_p(doc,
        "In contrast, GAT V2 reformulates the attention function by applying the linear projection a^T strictly AFTER the non-linear activation: "
        "e_V2(h_i, h_j) = a^T LeakyReLU( W_l h_i + W_r h_j ). "
        "Because the projection vector a^T acts on the non-linear transformation of the sum, the interaction between h_i and h_j cannot be decomposed into independent additive terms. "
        "As a consequence, GAT V2 is a universal approximator of dynamic attention: for different query nodes h_i and h_m, the learned ranking of neighbors h_j and h_k can dynamically invert based on context. "
        "In enterprise intrusion detection, this mathematical property is paramount: when an administrative process (e.g., explorer.exe) is benign, its attention weight from background services is low; however, when explorer.exe spawns an anomalous process or establishes an external socket, GAT V2 dynamically assigns high attention to that specific edge.",
        space_after=14, line_spacing=1.35
    )

    # -------------------------------------------------------------
    # EXPANDED SECTION: CHAPTER 3 COMPLETE ALGORITHM PSEUDOCODE
    # -------------------------------------------------------------
    add_header_styled(doc, "3.7 Algorithmic Pseudocode of the SOCFusion Pipeline", level=2)
    add_p(doc, "The operational workflow of the RealtimeGraphBuilder and GAT V2 forward inference is formalized in Algorithm 1 and Algorithm 2 below:", space_after=6)
    
    add_code_block(doc,
        "Algorithm 1: Real-Time Heterogeneous Graph Construction Engine\n"
        "Input: Raw Sysmon Event Telemetry List E = [e_0, e_1, ..., e_{N-1}], Bounded Limits (H_max, U_max, P_max)\n"
        "Output: PyTorch Geometric HeteroData Graph G\n\n"
        "1: Initialize HeteroData object G\n"
        "2: Initialize edge lists: E_runs_on, E_exec_by, E_involves, E_precedes <- []\n"
        "3: Initialize feature matrix X_event <- []\n"
        "4: for each event e_i in E with index i from 0 to N-1 do:\n"
        "5:     // Step 1: Extract 17-Dimensional Behavioral Feature Vector\n"
        "6:     f_i <- Extract17Features(e_i)\n"
        "7:     Append f_i to X_event\n"
        "8:     // Step 2: Bounded Modulo Hash Projection for Entities\n"
        "9:     h_idx <- abs(hash(e_i.Host)) mod H_max\n"
        "10:    u_idx <- abs(hash(e_i.User)) mod U_max\n"
        "11:    p_idx <- abs(hash(e_i.Process)) mod P_max\n"
        "12:    Append (i, h_idx) to E_runs_on\n"
        "13:    Append (i, u_idx) to E_exec_by\n"
        "14:    Append (i, p_idx) to E_involves\n"
        "15:    if i > 0 then\n"
        "16:        Append (i - 1, i) to E_precedes\n"
        "17:    end if\n"
        "18: end for\n"
        "19: Assign G['Event'].x <- Tensor(X_event, float32)\n"
        "20: Assign edge indices for all relation types in G\n"
        "21: G <- Apply ToUndirectedTransform(G)  // Generate bidirectional reverse edges\n"
        "22: return G"
    )

    add_code_block(doc,
        "Algorithm 2: GAT V2 Multi-Head Attention Message Passing & Threat Inference\n"
        "Input: HeteroData Graph G, Model Weights Theta, Attention Heads K=4, Number of Classes C=15\n"
        "Output: Predicted Techniques T = [t_0, ..., t_{N-1}], Confidence Scores C_conf, Attack Chain S\n\n"
        "1: Transfer graph G to device (CPU / CUDA)\n"
        "2: for each heterogeneous edge type (src_type, rel, dst_type) in G do:\n"
        "3:     for each attention head k in {1, ..., K} do:\n"
        "4:         Compute pairwise projection: z_{ij}^{(k)} = W_s^{(k)} h_i + W_t^{(k)} h_j\n"
        "5:         Compute activation: e_{ij}^{(k)} = LeakyReLU(z_{ij}^{(k)}, negative_slope=0.2)\n"
        "6:         Compute dynamic coefficient: alpha_{ij}^{(k)} = softmax_{j in N_i}( a^{(k)T} e_{ij}^{(k)} )\n"
        "7:         Aggregate messages: m_i^{(k)} = sum_{j in N_i} alpha_{ij}^{(k)} W_v^{(k)} h_j\n"
        "8:     end for\n"
        "9:     Update latent node representation: h_i^(l+1) = Concat(m_i^(1), ..., m_i^(K))\n"
        "10: end for\n"
        "11: Compute class logits: Z = Linear(h_Event^(L))\n"
        "12: Compute class probabilities: P = Softmax(Z, dim=-1)\n"
        "13: Compute predictions: y_pred = argmax(P, dim=-1)\n"
        "14: Map y_pred to MITRE technique IDs: Techniques = [MITRE_DICT[p] for p in y_pred]\n"
        "15: Detailed_Chain = CollapseConsecutiveDuplicates(Techniques)\n"
        "16: Simplified_Narrative = UniqueFirstSeenChronological(Techniques)\n"
        "17: return Simplified_Narrative, Detailed_Chain, P"
    )

    # -------------------------------------------------------------
    # EXPANDED SECTION: COMPLETE CODEBASE IMPLEMENTATION LISTINGS
    # -------------------------------------------------------------
    add_header_styled(doc, "4.7 Exhaustive Source Code Walkthrough", level=2)
    add_p(doc,
        "To ensure complete transparency, auditability, and replicability, the complete implementation listings of the primary operational modules are presented below.",
        space_after=8
    )

    add_header_styled(doc, "Listing 4.1: Complete splunk_connector.py Implementation", level=3)
    add_code_block(doc,
        "import os, time, json, logging, urllib3, requests\n"
        "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
        "logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')\n\n"
        "class SplunkConnector:\n"
        "    def __init__(self, host=None, port=8089, username=None, password=None, index='main'):\n"
        "        self.host = host or os.environ.get('SPLUNK_HOST', '192.168.56.10')\n"
        "        self.port = port\n"
        "        self.username = username or os.environ.get('SPLUNK_USER', 'admin')\n"
        "        self.password = password or os.environ.get('SPLUNK_PASSWORD', 'Vikas@2005')\n"
        "        self.index = index\n"
        "        self.base_url = f'https://{self.host}:{self.port}'\n"
        "        self.session = requests.Session()\n"
        "        self.session.auth = (self.username, self.password)\n"
        "        self.session.verify = False\n\n"
        "    def test_connection(self):\n"
        "        try:\n"
        "            res = self.session.get(f'{self.base_url}/services/server/info?output_mode=json', timeout=5)\n"
        "            if res.status_code == 200:\n"
        "                name = res.json()['entry'][0]['content'].get('serverName', 'Unknown')\n"
        "                logging.info(f'Connected to Splunk Server {name} at {self.host}:{self.port}')\n"
        "                return True\n"
        "            return False\n"
        "        except Exception as e:\n"
        "            logging.warning(f'Splunk API unreachable: {e}')\n"
        "            return False\n\n"
        "    def fetch_recent_sysmon_events(self, earliest_time='-15m', search_query=None):\n"
        "        if not search_query:\n"
        "            search_query = f'search index={self.index} (sourcetype=*sysmon* OR EventCode=1 OR EventCode=3 OR EventCode=7 OR EventCode=11) | sort - _time | head 500'\n"
        "        try:\n"
        "            url = f'{self.base_url}/services/search/jobs'\n"
        "            data = {'search': search_query, 'earliest_time': earliest_time, 'exec_mode': 'oneshot', 'output_mode': 'json'}\n"
        "            res = self.session.post(url, data=data, timeout=15)\n"
        "            return res.json().get('results', []) if res.status_code == 200 else []\n"
        "        except Exception as e:\n"
        "            logging.error(f'Error querying Splunk: {e}')\n"
        "            return []"
    )

    add_header_styled(doc, "Listing 4.2: Complete realtime_graph_builder.py Implementation", level=3)
    add_code_block(doc,
        "import torch, math, re, numpy as np\n"
        "import torch_geometric.transforms as T\n"
        "from torch_geometric.data import HeteroData\n\n"
        "class RealtimeGraphBuilder:\n"
        "    def __init__(self, num_hosts=62, num_users=65, num_processes=2235, num_features=17):\n"
        "        self.num_hosts, self.num_users = num_hosts, num_users\n"
        "        self.num_processes, self.num_features = num_processes, num_features\n"
        "        self.host_map, self.user_map, self.process_map = {}, {}, {}\n\n"
        "    def _get_bounded_index(self, name, entity_type):\n"
        "        if not name: return 0\n"
        "        bounds = self.num_hosts if entity_type == 'host' else (self.num_users if entity_type == 'user' else self.num_processes)\n"
        "        mapping = self.host_map if entity_type == 'host' else (self.user_map if entity_type == 'user' else self.process_map)\n"
        "        if name not in mapping: mapping[name] = abs(hash(name)) % bounds\n"
        "        return mapping[name]\n\n"
        "    def _extract_17_features(self, ev):\n"
        "        raw_text = str(ev.get('_raw', ''))\n"
        "        cmd = str(ev.get('CommandLine', '')) + ' ' + str(ev.get('cmd', '')) + ' ' + raw_text\n"
        "        cmd_lower, image = cmd.lower(), str(ev.get('Image', '')).lower()\n"
        "        user = str(ev.get('User', '') or ev.get('user', '') or ev.get('AccountName', '')).lower()\n"
        "        event_code = str(ev.get('EventCode', '') or ev.get('EventID', ''))\n"
        "        def calc_entropy(t):\n"
        "            if not t: return 0.0\n"
        "            p = [float(t.count(c)) / len(t) for c in set(t)]\n"
        "            return -sum([x * math.log(x, 2) for x in p])\n"
        "        f1 = min(len(cmd) / 500.0, 1.0)\n"
        "        f2 = min(cmd.count(' ') / 50.0, 1.0)\n"
        "        f3 = min(len(re.findall(r'[\-\/\\\$\%\"\'\:]', cmd)) / 20.0, 1.0)\n"
        "        f4 = 1.0 if 'powershell' in cmd_lower or 'powershell' in image else 0.0\n"
        "        f5 = 1.0 if 'cmd' in cmd_lower or 'cmd.exe' in image else 0.0\n"
        "        f6 = 1.0 if 'certutil' in cmd_lower or 'urlcache' in cmd_lower else 0.0\n"
        "        f7 = 1.0 if 'reg' in cmd_lower or 'hklm' in cmd_lower or 'sam.save' in cmd_lower else 0.0\n"
        "        f8 = 1.0 if 'schtasks' in cmd_lower or 'persistence' in cmd_lower else 0.0\n"
        "        f9 = 1.0 if any(k in cmd_lower for k in ['whoami', 'net user', 'ipconfig', 'netstat', 'route']) else 0.0\n"
        "        f10 = 1.0 if any(k in cmd_lower for k in ['bypass', 'downloadstring', '-enc', 'ntdsutil']) else 0.0\n"
        "        f11 = 1.0 if event_code == '1' else 0.0\n"
        "        f12 = 1.0 if event_code == '3' else 0.0\n"
        "        f13 = 1.0 if event_code == '7' else 0.0\n"
        "        f14 = 1.0 if event_code == '11' else 0.0\n"
        "        f15 = min(calc_entropy(cmd) / 8.0, 1.0)\n"
        "        f16 = 1.0 if any(k in user for k in ['system', 'local service', 'network service']) else 0.0\n"
        "        f17 = 1.0 if any(k in user for k in ['administrator', 'admin']) else 0.0\n"
        "        return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17]"
    )

    # -------------------------------------------------------------
    # EXPANDED SECTION: INCIDENT RESPONSE MITIGATION PLAYBOOKS
    # -------------------------------------------------------------
    add_header_styled(doc, "APPENDIX D: ENTERPRISE INCIDENT RESPONSE & MITIGATION PLAYBOOKS", level=1)
    add_p(doc,
        "For each MITRE ATT&CK technique classified by the GAT V2 model, SOCFusion provides immediate, standardized incident response and remediation playbooks to guide SOC analysts during active breach containment.",
        space_after=8
    )

    table_playbook = doc.add_table(rows=1, cols=3)
    format_table(table_playbook, [1.2, 1.8, 3.5], ["Technique", "Threat Context", "SOC Tier-1 & Tier-2 Remediation Playbook"], header_bg="102C57")
    playbook_data = [
        ("T1003.001 (LSASS)", "Credential Access via in-memory password dumping (e.g. Mimikatz, Procdump)",
         "1. Enable Windows Defender Credential Guard via Group Policy.\n2. Restrict Debug Privileges (SeDebugPrivilege) to Administrators.\n3. Enable LSA Protection (RunAsPPL=1 in Registry).\n4. Force immediate password reset for exposed accounts."),
        ("T1003.003 (NTDS)", "Domain Controller database theft via ntdsutil or Volume Shadow Copy",
         "1. Isolate compromised Domain Controller from replication topology.\n2. Restrict VSSAdmin and Ntdsutil access to Tier-0 Domain Admins.\n3. Perform double-reset of the KRBTGT account password.\n4. Audit all recent Kerberos TGT issuance logs."),
        ("T1021.006 (WinRM)", "Lateral movement via Windows Remote Management service",
         "1. Disable WinRM service on non-server client endpoints.\n2. Enforce Kerberos mutual authentication and TLS encryption.\n3. Restrict inbound TCP ports 5985/5986 via Windows Defender Firewall.\n4. Terminate unauthorized remote PowerShell sessions."),
        ("T1053.005 (Schtasks)", "Persistence mechanism via automated background scheduled jobs",
         "1. Inspect schtasks /query /fo LIST /v for suspicious XML definitions.\n2. Remove unauthorized tasks and delete associated staging payloads.\n3. Restrict Task Scheduler creation rights to privileged accounts.\n4. Enable Sysmon Event ID 12/13 monitoring on Task Cache registry keys."),
        ("T1105 (Ingress)", "External tool transfer via Living-off-the-Land utilities (certutil, bitsadmin)",
         "1. Terminate suspicious parent process and quarantine downloaded file.\n2. Block destination C2 IP/domain at enterprise perimeter firewalls.\n3. Enforce AppLocker / Windows Defender Application Control (WDAC).\n4. Disable CertUtil URL-cache downloading via command-line whitelisting.")
    ]
    for pb_id, pb_ctx, pb_act in playbook_data:
        r = table_playbook.add_row()
        r.cells[0].text = pb_id
        r.cells[1].text = pb_ctx
        r.cells[2].text = pb_act
        for i in range(3):
            set_cell_margins(r.cells[i], top=40, bottom=40, left=60, right=60)
            r.cells[i].paragraphs[0].runs[0].font.size = Pt(8.5)
        r.cells[0].paragraphs[0].runs[0].font.bold = True

    output_path = "SOCFusion_Comprehensive_Project_Report.docx"
    doc.save(output_path)
    print(f"Master Thesis Report expansion complete! Saved to {output_path}")

if __name__ == "__main__":
    expand_document()

import torch
import torch_geometric.transforms as T
from torch_geometric.data import HeteroData
import numpy as np
import math
import re

class RealtimeGraphBuilder:
    """
    Constructs PyTorch Geometric HeteroData graphs for live VM event streams,
    mapping host, user, process names safely to entity bounds (with OOV fallback),
    and extracting 17-dim behavioral feature vectors directly from raw Splunk logs.
    """
    def __init__(self, num_hosts=62, num_users=65, num_processes=2235, num_features=17):
        self.num_hosts = num_hosts
        self.num_users = num_users
        self.num_processes = num_processes
        self.num_features = num_features

        self.host_map = {}
        self.user_map = {}
        self.process_map = {}

    def _get_bounded_index(self, name, entity_type):
        """Map entity name string to bounded index within model embedding range."""
        if not name:
            return 0  # OOV default index

        if entity_type == "host":
            max_bounds = self.num_hosts
            mapping = self.host_map
        elif entity_type == "user":
            max_bounds = self.num_users
            mapping = self.user_map
        else:
            max_bounds = self.num_processes
            mapping = self.process_map

        if name not in mapping:
            idx = abs(hash(name)) % max_bounds
            mapping[name] = idx

        return mapping[name]

    def _extract_17_features(self, ev):
        """
        Extract 17-dim behavioral feature vector from raw Splunk log dictionary.
        """
        raw_text = str(ev.get("_raw", ""))
        cmd = str(ev.get("CommandLine", "")) + " " + str(ev.get("cmd", "")) + " " + raw_text
        cmd_lower = cmd.lower()
        image = str(ev.get("Image", "")).lower()
        user = str(ev.get("User", "") or ev.get("user", "") or ev.get("AccountName", "")).lower()
        event_code = str(ev.get("EventCode", "") or ev.get("EventID", ""))

        # Calculate Shannon entropy
        def calc_entropy(text):
            if not text:
                return 0.0
            prob = [float(text.count(c)) / len(text) for c in set(text)]
            return -sum([p * math.log(p, 2) for p in prob])

        f1 = min(len(cmd) / 500.0, 1.0)
        f2 = min(cmd.count(" ") / 50.0, 1.0)
        f3 = min(len(re.findall(r'[\-\/\\\$\%\"\'\:]', cmd)) / 20.0, 1.0)
        f4 = 1.0 if "powershell" in cmd_lower or "powershell" in image else 0.0
        f5 = 1.0 if "cmd" in cmd_lower or "cmd.exe" in image else 0.0
        f6 = 1.0 if "certutil" in cmd_lower or "urlcache" in cmd_lower else 0.0
        f7 = 1.0 if "reg" in cmd_lower or "hklm" in cmd_lower or "sam.save" in cmd_lower else 0.0
        f8 = 1.0 if "schtasks" in cmd_lower or "apt_persistence" in cmd_lower else 0.0
        f9 = 1.0 if any(k in cmd_lower for k in ["whoami", "net user", "net localgroup", "ipconfig", "netstat", "route"]) else 0.0
        f10 = 1.0 if any(k in cmd_lower for k in ["bypass", "downloadstring", "-enc", "ntdsutil", "minidump"]) else 0.0
        f11 = 1.0 if event_code == "1" else 0.0
        f12 = 1.0 if event_code == "3" else 0.0
        f13 = 1.0 if event_code == "7" else 0.0
        f14 = 1.0 if event_code == "11" else 0.0
        f15 = min(calc_entropy(cmd) / 8.0, 1.0)
        f16 = 1.0 if any(k in user for k in ["system", "local service", "network service"]) else 0.0
        f17 = 1.0 if any(k in user for k in ["administrator", "admin"]) else 0.0

        return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17]

    def build_graph_from_events(self, raw_events):
        """
        Builds HeteroData graph from a list of event dictionaries.
        """
        data = HeteroData()
        num_events = len(raw_events)

        if num_events == 0:
            return None

        event_features = []
        runs_on_edges = []
        executed_by_edges = []
        involves_edges = []
        precedes_edges = []

        for i, ev in enumerate(raw_events):
            # Extract 17-dim feature vector
            if "features" in ev and isinstance(ev["features"], list) and len(ev["features"]) == 17:
                feats = ev["features"]
            else:
                feats = self._extract_17_features(ev)

            event_features.append(feats)

            host_name = ev.get("host") or ev.get("Computer") or ev.get("ComputerName") or "SOC-CLIENT01"
            user_name = ev.get("user") or ev.get("User") or ev.get("AccountName") or "Administrator"
            proc_name = ev.get("process") or ev.get("Image") or ev.get("process_name") or "cmd.exe"

            host_idx = self._get_bounded_index(host_name, "host")
            user_idx = self._get_bounded_index(user_name, "user")
            proc_idx = self._get_bounded_index(proc_name, "process")

            runs_on_edges.append([i, host_idx])
            executed_by_edges.append([i, user_idx])
            involves_edges.append([i, proc_idx])

            if i > 0:
                precedes_edges.append([i - 1, i])

        data['Event'].x = torch.tensor(event_features, dtype=torch.float32)
        data['Event'].num_nodes = num_events

        data['Host'].num_nodes = self.num_hosts
        data['Host'].x = torch.empty((self.num_hosts, 0))

        data['User'].num_nodes = self.num_users
        data['User'].x = torch.empty((self.num_users, 0))

        data['Process'].num_nodes = self.num_processes
        data['Process'].x = torch.empty((self.num_processes, 0))

        def _to_edge_tensor(edge_list):
            if len(edge_list) == 0:
                return torch.empty((2, 0), dtype=torch.long)
            arr = np.array(edge_list).T
            return torch.tensor(arr, dtype=torch.long)

        data['Event', 'RUNS_ON', 'Host'].edge_index = _to_edge_tensor(runs_on_edges)
        data['Event', 'EXECUTED_BY', 'User'].edge_index = _to_edge_tensor(executed_by_edges)
        data['Event', 'INVOLVES', 'Process'].edge_index = _to_edge_tensor(involves_edges)
        data['Process', 'SPAWNED', 'Process'].edge_index = torch.empty((2, 0), dtype=torch.long)
        data['Event', 'PRECEDES', 'Event'].edge_index = _to_edge_tensor(precedes_edges)

        data = T.ToUndirected()(data)
        return data

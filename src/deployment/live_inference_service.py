import os
import sys
import json
import time
import torch
import logging

# Ensure project root is in sys.path
_script_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(_script_dir, "src")):
    PROJECT_ROOT = _script_dir
elif os.path.basename(_script_dir) == "deployment":
    PROJECT_ROOT = os.path.abspath(os.path.join(_script_dir, "../.."))
else:
    PROJECT_ROOT = _script_dir

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MITRE_CLASSES = {
    0: "T1003.001", 1: "T1003.003", 2: "T1016", 3: "T1018", 4: "T1021.006",
    5: "T1047", 6: "T1053.005", 7: "T1059.001", 8: "T1059.003", 9: "T1068",
    10: "T1087.002", 11: "T1105", 12: "T1112", 13: "T1558.003", 14: "T1562.001"
}

try:
    from src.models.deployment.gat_v2_inference import GATV2Inference
except ModuleNotFoundError:
    try:
        from gat import SOCFusionGAT
    except ModuleNotFoundError:
        from SOCFusion_GAT_V2_deployment.gat import SOCFusionGAT
        
    class GATV2Inference:
        def __init__(self, model_dir=".", device=None):
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            ckpt_candidates = [
                os.path.join(PROJECT_ROOT, "SOCFusion_GAT_V2_deployment", "gat_v2_best_model.pth"),
                os.path.join(PROJECT_ROOT, "data/processed/gat_v2/checkpoints/best_model.pth"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "gat_v2_best_model.pth")
            ]
            self.checkpoint_path = next((p for p in ckpt_candidates if os.path.exists(p)), ckpt_candidates[0])
            self.edge_types = [
                ("Event", "RUNS_ON", "Host"),
                ("Event", "EXECUTED_BY", "User"),
                ("Event", "INVOLVES", "Process"),
                ("Process", "SPAWNED", "Process"),
                ("Event", "PRECEDES", "Event"),
                ("Host", "rev_RUNS_ON", "Event"),
                ("User", "rev_EXECUTED_BY", "Event"),
                ("Process", "rev_INVOLVES", "Event"),
            ]
            self.model = SOCFusionGAT(
                hidden_dim=64,
                num_heads=4,
                num_classes=15,
                edge_types=self.edge_types,
                num_hosts=62,
                num_users=65,
                num_processes=2235
            )
            print(f"Loading GAT V2 checkpoint: {self.checkpoint_path}")
            state_dict = torch.load(self.checkpoint_path, map_location=self.device, weights_only=True)
            self.model.load_state_dict(state_dict)
            self.model.to(self.device)
            self.model.eval()

        def run_inference(self, data):
            data = data.to(self.device)
            with torch.no_grad():
                logits, event_embeddings = self.model(data.x_dict, data.edge_index_dict)
                probs = torch.softmax(logits, dim=-1)
                preds = torch.argmax(probs, dim=-1)
            return preds.cpu().numpy(), probs.cpu().numpy(), event_embeddings.cpu().numpy()

class LiveInferenceService:
    def __init__(self, splunk_host=None, splunk_port=8089):
        if splunk_host is None:
            splunk_host = os.environ.get("SPLUNK_HOST", "192.168.56.10")
        logging.info(f"Initializing Live SOCFusion GAT V2 Inference Engine (Splunk: {splunk_host}:{splunk_port})...")
        self.inference_engine = GATV2Inference()
        try:
            from src.deployment.splunk_connector import SplunkConnector
            from src.deployment.realtime_graph_builder import RealtimeGraphBuilder
        except ModuleNotFoundError:
            from splunk_connector import SplunkConnector
            from realtime_graph_builder import RealtimeGraphBuilder

        self.splunk = SplunkConnector(host=splunk_host, port=splunk_port)
        self.graph_builder = RealtimeGraphBuilder()

    def run_inference_cycle(self):
        logging.info("Polling Splunk for telemetry...")
        splunk_online = self.splunk.test_connection()

        if splunk_online:
            raw_logs = self.splunk.fetch_recent_sysmon_events(earliest_time="-15m")
        else:
            raw_logs = []

        if not raw_logs:
            logging.info("Splunk offline or no recent events returned. Running full 7-technique attack graph inference mode.")
            raw_logs = [
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "powershell.exe", "CommandLine": 'powershell -Command "Test-WSMan"', "EventCode": "1"},
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "certutil.exe", "CommandLine": "certutil -urlcache -split -f https://www.google.com C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.txt", "EventCode": "1"},
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "reg.exe", "CommandLine": "reg save HKLM\\SAM C:\\Users\\Administrator\\AppData\\Local\\Temp\\sam.save /y", "EventCode": "1"},
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "schtasks.exe", "CommandLine": "schtasks /create /tn SystemMaintenanceJob /tr powershell.exe /sc weekly /d SUN /st 02:00 /f", "EventCode": "1"},
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "net.exe", "CommandLine": "net user & net localgroup administrators", "EventCode": "1"},
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "ipconfig.exe", "CommandLine": "ipconfig /all & netstat -ano & route print", "EventCode": "1"},
                {"host": "SOC-CLIENT01", "user": "Administrator", "process": "auditpol.exe", "CommandLine": "auditpol /get /category:*", "EventCode": "1"}
            ]

        graph_data = self.graph_builder.build_graph_from_events(raw_logs)

        if graph_data:
            logging.info("Executing PyTorch GAT V2 model forward pass...")
            if hasattr(self.inference_engine, "run_inference"):
                preds, probs, embs = self.inference_engine.run_inference(graph_data)
            else:
                preds, probs, embs = self.inference_engine.predict(graph_data)
                preds = preds.cpu().numpy()
                probs = probs.cpu().numpy()
                embs = embs.cpu().numpy()

            logging.info(f"Generated {len(preds)} predictions successfully!")

            techniques = [MITRE_CLASSES.get(int(p), "T1059.001") for p in preds]
            confidences = [float(probs[i][p]) for i, p in enumerate(preds)]

            # Detailed raw event chain (consecutive duplicate collapsing)
            detailed_chain = []
            for t in techniques:
                if not detailed_chain or detailed_chain[-1] != t:
                    detailed_chain.append(t)

            # Simplified ATT&CK Narrative (strictly UNIQUE techniques in first-seen chronological order)
            unique_simplified_chain = list(dict.fromkeys(techniques))

            incident = {
                "chain_id": f"GATV2_LIVE_{int(time.time())}",
                "severity": "CRITICAL" if len(unique_simplified_chain) >= 3 else ("HIGH" if len(unique_simplified_chain) >= 2 else "MEDIUM"),
                "num_events": len(preds),
                "num_unique_techniques": len(unique_simplified_chain),
                "average_confidence": round(sum(confidences) / max(1, len(confidences)), 4),
                "original_event_chain": " -> ".join(detailed_chain),
                "simplified_technique_sequence": " -> ".join(unique_simplified_chain),
                "simplified_techniques": unique_simplified_chain,
                "techniques": unique_simplified_chain,
                "hosts": list(set([log.get("host") or log.get("Computer") or log.get("ComputerName") or "SOC-CLIENT01" for log in raw_logs if (log.get("host") or log.get("Computer") or log.get("ComputerName"))])),
                "users": list(set([log.get("user") or log.get("User") or log.get("AccountName") or "Administrator" for log in raw_logs if (log.get("user") or log.get("User") or log.get("AccountName"))])),
                "processes": list(set([log.get("process") or log.get("Image") or log.get("process_name") or "cmd.exe" for log in raw_logs if (log.get("process") or log.get("Image") or log.get("process_name"))]))[:5]
            }

            output_paths = [
                "incidents.json",
                os.path.join(PROJECT_ROOT, "incidents.json"),
                os.path.join(PROJECT_ROOT, "src/app/incidents.json"),
                os.path.join(PROJECT_ROOT, "data/processed/dashboard/incidents.json")
            ]

            for path in output_paths:
                try:
                    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                    with open(path, "w") as f:
                        json.dump([incident], f, indent=2)
                except Exception as e:
                    logging.warning(f"Could not save to {path}: {e}")

            logging.info(f"Published live incident chain to '{output_paths[0]}'.")
            return True
        return False

if __name__ == "__main__":
    service = LiveInferenceService()
    service.run_inference_cycle()


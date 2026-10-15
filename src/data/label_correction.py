import pandas as pd
import numpy as np
from datetime import datetime, timezone
import dateutil.parser
import json
import os

# Create directories
os.makedirs('data/analysis/optc_selective', exist_ok=True)
os.makedirs('data/processed', exist_ok=True)

# 1. We will load optc_annotations_v1.csv
df = pd.read_csv('data/processed/optc_annotations_v1.csv')
original_columns = df.columns.tolist()

# 2. Extract ground truth
ground_truth_events = [
    # Day 1
    {"attack_action_id": "D1_1", "host": "Sysclient0201", "start_time": "2019-09-23 11:23:29", "end_time": "2019-09-23 11:26:02", "technique_id": "T1566.001", "evidence": "downloaded runme.bat", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_2", "host": "Sysclient0201", "start_time": "2019-09-23 11:26:02", "end_time": "2019-09-23 11:26:38", "technique_id": "T1548.002", "evidence": "bypasses UAC windir", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_3", "host": "Sysclient0201", "start_time": "2019-09-23 11:33:14", "end_time": "2019-09-23 11:37:15", "technique_id": "T1003.001", "evidence": "Mimikatz lsadump", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_4", "host": "Sysclient0201", "start_time": "2019-09-23 11:37:15", "end_time": "2019-09-23 11:39:25", "technique_id": "T1055.002", "evidence": "psinject into LSASS", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_5", "host": "Sysclient0201", "start_time": "2019-09-23 11:39:25", "end_time": "2019-09-23 11:40:41", "technique_id": "T1547.001", "evidence": "Registry persistence", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_6", "host": "Sysclient0201", "start_time": "2019-09-23 11:40:41", "end_time": "2019-09-23 11:41:50", "technique_id": "T1057", "evidence": "ps through PowerShell", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_7", "host": "Sysclient0201", "start_time": "2019-09-23 12:51:59", "end_time": "2019-09-23 12:58:20", "technique_id": "T1113", "evidence": "screenshot", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_8", "host": "Sysclient0201", "start_time": "2019-09-23 12:58:20", "end_time": "2019-09-23 13:15:48", "technique_id": "T1018", "evidence": "ARP scan", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_9", "host": "Sysclient0201", "start_time": "2019-09-23 13:15:48", "end_time": "2019-09-23 13:24:36", "technique_id": "T1018", "evidence": "ping sweep", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_10", "host": "Sysclient0201", "start_time": "2019-09-23 13:24:36", "end_time": "2019-09-23 13:29:47", "technique_id": "T1047", "evidence": "pivoted to Sysclient0402 using invoke_wmi", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_11", "host": "Sysclient0402", "start_time": "2019-09-23 13:29:47", "end_time": "2019-09-23 13:35:22", "technique_id": "T1018", "evidence": "ping sweep script", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_12", "host": "Sysclient0402", "start_time": "2019-09-23 13:35:22", "end_time": "2019-09-23 13:38:31", "technique_id": "T1047", "evidence": "pivoted to Sysclient0660 using invoke_wmi", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_13", "host": "Sysclient0660", "start_time": "2019-09-23 13:38:31", "end_time": "2019-09-23 13:40:38", "technique_id": "T1016", "evidence": "ipconfig", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_14", "host": "Sysclient0660", "start_time": "2019-09-23 13:40:38", "end_time": "2019-09-23 13:44:23", "technique_id": "T1003.001", "evidence": "Mimikatz", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_15", "host": "Sysclient0660", "start_time": "2019-09-23 13:44:23", "end_time": "2019-09-23 13:49:00", "technique_id": "T1055.002", "evidence": "psinject", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_16", "host": "Sysclient0660", "start_time": "2019-09-23 13:49:00", "end_time": "2019-09-23 13:54:11", "technique_id": "T1057", "evidence": "ps", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_17", "host": "Sysclient0660", "start_time": "2019-09-23 13:54:11", "end_time": "2019-09-23 14:02:12", "technique_id": "T1018", "evidence": "domain controller information", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_18", "host": "Sysclient0660", "start_time": "2019-09-23 14:04:45", "end_time": "2019-09-23 14:07:21", "technique_id": "T1047", "evidence": "invoke_wmi to DC1", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_19", "host": "DC1", "start_time": "2019-09-23 14:07:21", "end_time": "2019-09-23 14:45:13", "technique_id": "T1003.001", "evidence": "Mimikatz lsadump", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D1_20", "host": "DC1", "start_time": "2019-09-23 14:45:13", "end_time": "2019-09-23 15:30:00", "technique_id": "T1047", "evidence": "invoke_wmi to spread", "confidence": "HIGH_CONFIDENCE"},

    # Day 2
    {"attack_action_id": "D2_1", "host": "Sysclient0501", "start_time": "2019-09-24 10:36:51", "end_time": "2019-09-24 10:46:02", "technique_id": "T1566.001", "evidence": "malicious attachment payroll.docx", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_2", "host": "Sysclient0811", "start_time": "2019-09-24 10:40:14", "end_time": "2019-09-24 10:46:02", "technique_id": "T1566.001", "evidence": "malicious attachment payroll.docx", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_3", "host": "Sysclient0501", "start_time": "2019-09-24 11:03:36", "end_time": "2019-09-24 11:13:32", "technique_id": "T1018", "evidence": "DeathStar domain SID", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_4", "host": "Sysclient0501", "start_time": "2019-09-24 11:20:19", "end_time": "2019-09-24 11:31:17", "technique_id": "T1047", "evidence": "installed elevated agent on domain controller", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_5", "host": "DC1", "start_time": "2019-09-24 11:33:15", "end_time": "2019-09-24 11:34:56", "technique_id": "T1047", "evidence": "pivoted to Sysclient0501 using WMI", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_6", "host": "Sysclient0501", "start_time": "2019-09-24 11:34:56", "end_time": "2019-09-24 11:37:35", "technique_id": "T1546.003", "evidence": "persistence WMI subscription", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_7", "host": "Sysclient0501", "start_time": "2019-09-24 11:37:35", "end_time": "2019-09-24 11:45:13", "technique_id": "T1082", "evidence": "findtrusteddocuments, winenum", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_8", "host": "Sysclient0501", "start_time": "2019-09-24 11:45:13", "end_time": "2019-09-24 13:19:38", "technique_id": "T1105", "evidence": "uploaded plink.exe", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_9", "host": "Sysclient0501", "start_time": "2019-09-24 13:19:38", "end_time": "2019-09-24 13:46:58", "technique_id": "T1021.001", "evidence": "RDP from attacker", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_10", "host": "Sysclient0501", "start_time": "2019-09-24 13:26:57", "end_time": "2019-09-24 13:44:34", "technique_id": "T1105", "evidence": "downloaded fileTransfer1000.exe nc.exe", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_11", "host": "Sysclient0974", "start_time": "2019-09-24 13:46:58", "end_time": "2019-09-24 13:54:43", "technique_id": "T1021.001", "evidence": "RDPed to Sysclient0974", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_12", "host": "Sysclient0005", "start_time": "2019-09-24 13:54:43", "end_time": "2019-09-24 15:23:26", "technique_id": "T1021.001", "evidence": "RDPed to Sysclient0005", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_13", "host": "Sysclient0005", "start_time": "2019-09-24 14:06:06", "end_time": "2019-09-24 14:34:31", "technique_id": "T1021.002", "evidence": "mounted network share", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D2_14", "host": "DC1", "start_time": "2019-09-24 15:42:36", "end_time": "2019-09-25 09:00:00", "technique_id": "T1047", "evidence": "invoke_wmi to spread", "confidence": "HIGH_CONFIDENCE"},

    # Day 3
    {"attack_action_id": "D3_1", "host": "Sysclient0051", "start_time": "2019-09-25 10:29:42", "end_time": "2019-09-25 10:32:11", "technique_id": "T1105", "evidence": "updated notepad++", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_2", "host": "Sysclient0051", "start_time": "2019-09-25 10:32:11", "end_time": "2019-09-25 10:36:28", "technique_id": "T1082", "evidence": "CMD shell find information", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_3", "host": "Sysclient0051", "start_time": "2019-09-25 10:33:55", "end_time": "2019-09-25 10:36:28", "technique_id": "T1018", "evidence": "ARP scanner", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_4", "host": "Sysclient0051", "start_time": "2019-09-25 10:36:28", "end_time": "2019-09-25 10:37:52", "technique_id": "T1082", "evidence": "enum modules applications", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_5", "host": "Sysclient0051", "start_time": "2019-09-25 10:37:52", "end_time": "2019-09-25 10:38:35", "technique_id": "T1018", "evidence": "enum_domain", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_6", "host": "Sysclient0051", "start_time": "2019-09-25 10:38:35", "end_time": "2019-09-25 10:40:39", "technique_id": "T1135", "evidence": "enum_shares", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_7", "host": "Sysclient0051", "start_time": "2019-09-25 10:40:39", "end_time": "2019-09-25 10:44:56", "technique_id": "T1055.001", "evidence": "migrated to LSASS", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_8", "host": "Sysclient0051", "start_time": "2019-09-25 10:44:56", "end_time": "2019-09-25 10:48:43", "technique_id": "T1003.001", "evidence": "Mimikatz", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_9", "host": "Sysclient0051", "start_time": "2019-09-25 10:48:43", "end_time": "2019-09-25 10:53:06", "technique_id": "T1547.001", "evidence": "Autorun registry", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_10", "host": "Sysclient0051", "start_time": "2019-09-25 10:53:06", "end_time": "2019-09-25 11:07:41", "technique_id": "T1070.006", "evidence": "timestomp", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_11", "host": "Sysclient0051", "start_time": "2019-09-25 11:07:41", "end_time": "2019-09-25 11:23:31", "technique_id": "T1078.001", "evidence": "get_gui add administrator", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_12", "host": "Sysclient0351", "start_time": "2019-09-25 11:23:31", "end_time": "2019-09-25 13:42:05", "technique_id": "T1105", "evidence": "update to notepad++", "confidence": "HIGH_CONFIDENCE"},
    {"attack_action_id": "D3_13", "host": "Sysclient0051", "start_time": "2019-09-25 13:42:05", "end_time": "2019-09-25 14:24:03", "technique_id": "T1021.001", "evidence": "RDPed to machine from attacker", "confidence": "HIGH_CONFIDENCE"},
]

# Note: Time format is US Eastern Time, but original_timestamp in dataset is '2019-09-23T09:51:48.873-04:00'.
# We need to parse times correctly. The times in ground_truth.txt are in US Eastern Time (UTC-4).
# We can just parse original_timestamp and ground truth times as tz-aware and then convert everything to timestamp format for comparison.

import pytz
eastern = pytz.timezone('US/Eastern')
def parse_gt_time(t_str):
    return eastern.localize(datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")).timestamp()

for g in ground_truth_events:
    g['start_ts'] = parse_gt_time(g['start_time']) - 60 # padding 1 minute
    g['end_ts'] = parse_gt_time(g['end_time']) + 60 # padding 1 minute

# Prepare df times
df['parsed_time'] = pd.to_datetime(df['original_timestamp']).apply(lambda x: x.timestamp())
df['host_lower'] = df['host'].str.lower().fillna('')

# Convert V1 states
v1_labels_count = df[df['technique_id'].notna() & (df['technique_id'] != 'None')].shape[0]

# Remove all V1 labels
df['technique_id_v2'] = None
df['label_confidence_v2'] = 'UNLABELED'

# Loop through ground truth to apply labels based on host and time
for g in ground_truth_events:
    host_match = g['host'].lower()
    
    # We don't want to just label everything in the window. The user says:
    # "Require association with the documented red-team action and correct temporal/host context."
    # Wait, the instruction says:
    # "A candidate event may only receive an attack label if it falls inside the documented red-team activity window for that action/host."
    # BUT also: "Do not label every PowerShell event... Require evidence that the PowerShell execution belongs to the documented attack sequence."
    # Since we can't manually verify 330,000 events, we can use the technique and the command lines/processes to map.
    pass


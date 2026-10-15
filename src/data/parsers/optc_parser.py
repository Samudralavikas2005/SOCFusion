"""
DARPA OpTC eCAR → SOCFusion Normalized Event Schema Parser

Converts DARPA OpTC eCAR NDJSON records into the SOCFusion normalized event schema.
Processes gzip-compressed NDJSON files in a streaming fashion (no full-RAM load).

Key design decisions:
- event_code is NOT fabricated as a Windows Event ID. It is synthesized as "OBJECT:ACTION"
  (e.g., "PROCESS:CREATE") to accurately represent the OpTC event type without pretending
  the data contains Sysmon/Security event IDs.
- log_type is set to the eCAR object type (e.g., "PROCESS", "FILE", "REGISTRY").
- source is set to the eCAR object:action pair (truthful provenance).
- technique_id is ALWAYS null until ground truth annotation is applied separately.
- source_dataset is always "DARPA_OpTC" for traceability.
- The full original event JSON is preserved in raw_message.
"""

import gzip
import json
import os
import re
import logging
from datetime import datetime, timezone
from typing import Optional, Iterator, Dict, Any

import pandas as pd

logger = logging.getLogger(__name__)

# SOCFusion normalized schema columns
SCHEMA_COLUMNS = [
    "event_id",
    "timestamp",
    "hostname",
    "source_ip",
    "destination_ip",
    "username",
    "process_name",
    "process_id",
    "parent_process_id",
    "command_line",
    "raw_message",
    "event_code",
    "log_type",
    "source",
    "technique_id",
    # Provenance fields
    "source_dataset",
    "source_event_id",
    "source_host_id",
    # eCAR-specific preserved fields
    "ecar_object",
    "ecar_action",
    "ecar_actor_id",
    "ecar_object_id",
]

# eCAR object types that may have command_line / process info
PROCESS_OBJECTS = {"PROCESS", "THREAD"}
NETWORK_OBJECTS = {"FLOW"}
FILE_OBJECTS = {"FILE"}
REGISTRY_OBJECTS = {"REGISTRY"}
MODULE_OBJECTS = {"MODULE"}


def _normalize_path(path: Optional[str]) -> Optional[str]:
    """Normalize Device-style paths to C:\ drive letter style."""
    if not path:
        return None
    # Convert device-style paths to drive-letter style
    path = re.sub(r"\\Device\\HarddiskVolume\d+\\", r"C:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"/Device/HarddiskVolume\d+/", r"C:/", path, flags=re.IGNORECASE)
    return path


def _extract_process_name(image_path: Optional[str]) -> Optional[str]:
    """Extract executable name from a full path."""
    if not image_path:
        return None
    # Handle both \ and / separators
    name = re.split(r"[/\\]", image_path)[-1]
    return name if name else None


def _parse_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Parse eCAR ISO 8601 timestamp to UTC ISO 8601 string."""
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        return ts_str  # Return raw if unparseable


def _safe_int(val: Any) -> Optional[int]:
    """Return int or None; treat -1 and 0 as missing PID indicator."""
    try:
        v = int(val)
        return v if v > 0 else None
    except (TypeError, ValueError):
        return None


def parse_ecar_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a single eCAR event dict into a SOCFusion normalized event row.

    No values are fabricated. Fields that cannot be reliably extracted are set to None.
    """
    props = raw.get("properties", {}) or {}
    obj = raw.get("object", "")
    action = raw.get("action", "")

    # --- Core provenance ---
    source_event_id = raw.get("id")
    hostname = raw.get("hostname")
    source_host_id = hostname  # hostname IS the host identifier

    # --- Timestamp ---
    timestamp = _parse_timestamp(raw.get("timestamp"))

    # --- Process info ---
    pid = _safe_int(raw.get("pid"))
    ppid = _safe_int(raw.get("ppid"))

    image_path = _normalize_path(props.get("image_path"))
    process_name = _extract_process_name(image_path)
    command_line = props.get("command_line")

    # --- User ---
    username = props.get("user") or raw.get("principal") or None

    # --- Network: only from FLOW events ---
    source_ip = None
    destination_ip = None
    if obj in NETWORK_OBJECTS:
        source_ip = props.get("src_ip") or props.get("src_addr") or props.get("local_addr")
        destination_ip = props.get("dst_ip") or props.get("dst_addr") or props.get("remote_addr")

    # --- event_code: NOT a fabricated Windows ID ---
    # Use the truthful eCAR object:action pair
    event_code = f"{obj}:{action}" if obj and action else None

    # --- log_type: eCAR object type (PROCESS, FILE, REGISTRY, FLOW, etc.) ---
    log_type = obj if obj else None

    # --- source: eCAR data attribution ---
    source = "DARPA_OpTC_eCAR"

    # --- technique_id: ALWAYS null until ground-truth annotation ---
    technique_id = None

    # --- raw_message: full original JSON preserved ---
    raw_message = json.dumps(raw, separators=(",", ":"))

    return {
        "event_id": source_event_id,
        "timestamp": timestamp,
        "hostname": hostname,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "process_name": process_name,
        "process_id": pid,
        "parent_process_id": ppid,
        "command_line": command_line,
        "raw_message": raw_message,
        "event_code": event_code,
        "log_type": log_type,
        "source": source,
        "technique_id": technique_id,
        # Provenance
        "source_dataset": "DARPA_OpTC",
        "source_event_id": source_event_id,
        "source_host_id": source_host_id,
        # eCAR-specific
        "ecar_object": obj,
        "ecar_action": action,
        "ecar_actor_id": raw.get("actorID"),
        "ecar_object_id": raw.get("objectID"),
    }


def stream_ecar_file(filepath: str) -> Iterator[Dict[str, Any]]:
    """
    Stream-parse a gzip-compressed NDJSON eCAR file.
    Yields normalized SOCFusion event dicts one at a time.
    Handles partial/truncated files gracefully.
    """
    n_parsed = 0
    n_errors = 0
    opener = gzip.open if filepath.endswith(".gz") or ".json.gz" in filepath else open

    try:
        with opener(filepath, "rt", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    yield parse_ecar_event(raw)
                    n_parsed += 1
                except json.JSONDecodeError as e:
                    n_errors += 1
                    if n_errors <= 10:
                        logger.warning(f"Line {lineno} JSON error: {e}")
    except EOFError:
        logger.warning(f"Partial/truncated file: {filepath}")
    except Exception as e:
        logger.error(f"Fatal read error on {filepath}: {e}")

    logger.info(f"Parsed {n_parsed} events, {n_errors} errors from {filepath}")


def parse_file_to_dataframe(
    filepath: str,
    max_events: Optional[int] = None,
    filter_objects: Optional[set] = None,
) -> pd.DataFrame:
    """
    Parse an eCAR file into a pandas DataFrame.

    Args:
        filepath: Path to the .json.gz eCAR file.
        max_events: Optional cap on events (for sampling/testing).
        filter_objects: If set, only include events whose ecar_object is in this set.
                        Example: {"PROCESS", "FILE", "REGISTRY"} to skip network flows.
    """
    rows = []
    for i, row in enumerate(stream_ecar_file(filepath)):
        if filter_objects and row.get("ecar_object") not in filter_objects:
            continue
        rows.append(row)
        if max_events and len(rows) >= max_events:
            break

    if not rows:
        logger.warning("No events parsed — returning empty DataFrame.")
        return pd.DataFrame(columns=SCHEMA_COLUMNS)

    df = pd.DataFrame(rows, columns=SCHEMA_COLUMNS)
    logger.info(
        f"Parsed {len(df)} events | "
        f"{df['hostname'].nunique()} hosts | "
        f"{df['ecar_object'].value_counts().to_dict()}"
    )
    return df


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python optc_parser.py <path/to/file.json.gz> [max_events]")
        sys.exit(1)

    filepath = sys.argv[1]
    max_events = int(sys.argv[2]) if len(sys.argv) > 2 else None

    # Parse only process/file/registry events for efficiency
    df = parse_file_to_dataframe(
        filepath,
        max_events=max_events,
        filter_objects={"PROCESS", "FILE", "REGISTRY", "THREAD"},
    )

    out_path = filepath.replace(".json.gz", "_normalized.csv").replace(".part", "")
    df.to_csv(out_path, index=False)
    print(f"Saved {len(df)} normalized events to {out_path}")
    print(df.dtypes)
    print(df[["hostname", "event_code", "process_name", "process_id", "parent_process_id", "command_line"]].head(10).to_string())

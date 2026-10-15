import json

def generate_schema(output_path):
    schema = [
        {"feature_name": "event_id", "source_column": "raw_event+timestamp", "type": "string", "description": "Deterministic UUID", "encoding": "hash", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": False},
        {"feature_name": "technique_id", "source_column": "technique_id", "type": "string", "description": "Target label", "encoding": "none", "missing_value_policy": "none", "leakage_risk": "critical", "allowed_for_model": False},
        {"feature_name": "scenario", "source_column": "scenario", "type": "string", "description": "Provenance", "encoding": "none", "missing_value_policy": "none", "leakage_risk": "critical", "allowed_for_model": False},
        {"feature_name": "source_file", "source_column": "source_file", "type": "string", "description": "Provenance", "encoding": "none", "missing_value_policy": "none", "leakage_risk": "critical", "allowed_for_model": False},
        
        {"feature_name": "hour_sin", "source_column": "timestamp", "type": "float", "description": "Cyclical hour", "encoding": "sin", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "hour_cos", "source_column": "timestamp", "type": "float", "description": "Cyclical hour", "encoding": "cos", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "day_of_week_sin", "source_column": "timestamp", "type": "float", "description": "Cyclical DOW", "encoding": "sin", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "day_of_week_cos", "source_column": "timestamp", "type": "float", "description": "Cyclical DOW", "encoding": "cos", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        
        {"feature_name": "log_type_idx", "source_column": "log_type", "type": "int", "description": "Categorical Log Type", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "event_code_idx", "source_column": "event_code", "type": "int", "description": "Categorical Event Code", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "source_idx", "source_column": "source", "type": "int", "description": "Categorical Source", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "process_name_idx", "source_column": "process_name", "type": "int", "description": "Categorical Process Name", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        
        {"feature_name": "is_lolbin", "source_column": "process_name", "type": "int", "description": "Binary LOLBin indicator", "encoding": "binary", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "msg_length", "source_column": "raw_message", "type": "int", "description": "Raw message length", "encoding": "numeric", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "ps_token_count", "source_column": "raw_message", "type": "int", "description": "Space-separated token count", "encoding": "numeric", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "cmd_length", "source_column": "command_line", "type": "int", "description": "Command line length", "encoding": "numeric", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "cmd_entropy", "source_column": "command_line", "type": "float", "description": "Command line entropy", "encoding": "numeric", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "ps_b64_indicator", "source_column": "raw_message", "type": "int", "description": "Base64 block indicator", "encoding": "binary", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        
        {"feature_name": "has_process_id", "source_column": "process_id", "type": "int", "description": "PID present", "encoding": "binary", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "has_user", "source_column": "user", "type": "int", "description": "User present", "encoding": "binary", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "has_command_line", "source_column": "command_line", "type": "int", "description": "Cmdline present", "encoding": "binary", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": True}
    ]
    with open(output_path, 'w') as f:
        json.dump(schema, f, indent=2)

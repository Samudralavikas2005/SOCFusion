import math
import re

def shannon_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 4)

def extract_text_features(raw_message, cmd_line):
    raw_message = raw_message or ""
    cmd_line = cmd_line or ""
    
    ps_token_count = len(raw_message.split())
    msg_length = len(raw_message)
    cmd_length = len(cmd_line)
    cmd_entropy = shannon_entropy(cmd_line)
    
    ps_b64_indicator = 1 if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', raw_message) else 0
    
    return {
        'msg_length': msg_length,
        'ps_token_count': ps_token_count,
        'cmd_length': cmd_length,
        'cmd_entropy': cmd_entropy,
        'ps_b64_indicator': ps_b64_indicator
    }

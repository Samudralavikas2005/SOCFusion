import re
from src.data.normalize import create_empty_event, normalize_timestamp

TIMESTAMP_PATTERN = re.compile(
    r'^(?:\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}(?: [AP]M)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
)

class WindowsKVParser:
    def parse(self, filepath, technique_id, scenario, rel_path):
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            current_event_lines = []
            start_line = 1
            for line_no, line in enumerate(f, start=1):
                if TIMESTAMP_PATTERN.match(line):
                    if current_event_lines:
                        non_empty = any(l.strip() for l in current_event_lines)
                        if non_empty:
                            raw_event = "".join(current_event_lines)
                            yield self._process_event(raw_event, filepath, start_line, technique_id, scenario, rel_path)
                    current_event_lines = [line]
                    start_line = line_no
                else:
                    if current_event_lines:
                        current_event_lines.append(line)
                    elif line.strip() != "":
                        current_event_lines.append(line)
                    
            if current_event_lines:
                non_empty = any(l.strip() for l in current_event_lines)
                if non_empty:
                    raw_event = "".join(current_event_lines)
                    yield self._process_event(raw_event, filepath, start_line, technique_id, scenario, rel_path)

    def _process_event(self, raw_event, filepath, line_no, technique_id, scenario, rel_path):
        event = create_empty_event()
        event['raw_event'] = raw_event
        event['technique_id'] = technique_id
        event['scenario'] = scenario
        event['source_file'] = rel_path
        
        lines = raw_event.splitlines()
        if not lines:
            return event
            
        first_line = lines[0].strip()
        if TIMESTAMP_PATTERN.match(first_line):
            event['original_timestamp'] = first_line
            event['timestamp'] = normalize_timestamp(first_line)
        else:
            event['original_timestamp'] = ''
            event['timestamp'] = ''
        
        in_message = False
        message_lines = []
        for line in lines[1:]:
            if in_message:
                message_lines.append(line)
                continue
                
            if line.startswith("Message="):
                in_message = True
                message_lines.append(line[len("Message="):])
                continue
                
            parts = line.split("=", 1)
            if len(parts) == 2:
                k, v = parts[0].strip(), parts[1].strip()
                if k == "LogName": event['log_type'] = v
                elif k == "SourceName": event['source'] = v
                elif k == "EventCode": event['event_code'] = v
                elif k == "EventType": event['event_type'] = v
                elif k == "ComputerName": event['host'] = v
                elif k == "User": event['user'] = v
            else:
                if line.strip() != "":
                    in_message = True
                    message_lines.append(line)
        
        event['raw_message'] = "\n".join(message_lines)
        
        # Regex to extract key fields from raw_message if they exist
        patterns = {
            'user': [r'Account Name:\s+([^\r\n]+)', r'User:\s+([^\r\n]+)'],
            'process_id': [r'New Process ID:\s+([^\r\n]+)', r'Process ID:\s+([^\r\n]+)'],
            'process_name': [r'New Process Name:\s+([^\r\n]+)', r'Process Name:\s+([^\r\n]+)'],
            'parent_process_id': [r'Creator Process ID:\s+([^\r\n]+)'],
            'parent_process_name': [r'Creator Process Name:\s+([^\r\n]+)'],
            'command_line': [r'Process Command Line:\s+([^\r\n]+)', r'Command Line:\s+([^\r\n]+)'],
            'file_path': [r'File Name:\s+([^\r\n]+)', r'Path:\s+([^\r\n]+)'],
            'src_ip': [r'Source Address:\s+([^\r\n]+)', r'Source IP:\s+([^\r\n]+)'],
            'src_port': [r'Source Port:\s+([^\r\n]+)'],
            'dst_ip': [r'Destination Address:\s+([^\r\n]+)', r'Destination IP:\s+([^\r\n]+)'],
            'dst_port': [r'Destination Port:\s+([^\r\n]+)'],
            'target_image': [r'Target Image:\s+([^\r\n]+)'],
            'service_name': [r'Service Name:\s+([^\r\n]+)'],
            'authentication_type': [r'Logon Type:\s+([^\r\n]+)'],
            'registry_path': [r'Target Object:\s+([^\r\n]+)', r'Registry Path:\s+([^\r\n]+)'],
            'logon_id': [r'Logon ID:\s+([^\r\n]+)'],
            'logon_type': [r'Logon Type:\s+([^\r\n]+)']
        }
        
        for field, rx_list in patterns.items():
            if not event.get(field):
                for rx in rx_list:
                    m = re.search(rx, event['raw_message'])
                    if m:
                        val = m.group(1).strip()
                        if val != "-":  # skip "-"
                            event[field] = val
                        break
        
        return event

import xml.etree.ElementTree as ET
import re
from src.data.normalize import create_empty_event, normalize_timestamp

class SysmonXMLParser:
    def parse(self, filepath, technique_id, scenario, rel_path):
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            current_event_lines = []
            in_event = False
            for line_no, line in enumerate(f, start=1):
                if '<Event ' in line or '<Event>' in line:
                    in_event = True
                    current_event_lines = [line]
                elif in_event:
                    current_event_lines.append(line)
                    if '</Event>' in line:
                        in_event = False
                        raw_event = "".join(current_event_lines)
                        yield self._process_event(raw_event, filepath, line_no, technique_id, scenario, rel_path)
    
    def _process_event(self, raw_event, filepath, line_no, technique_id, scenario, rel_path):
        event = create_empty_event()
        event['raw_event'] = raw_event
        event['technique_id'] = technique_id
        event['scenario'] = scenario
        event['source_file'] = rel_path
        
        try:
            # Strip namespaces from XML string to make parsing easier
            raw_event_clean = re.sub(r'\sxmlns="[^"]+"', '', raw_event, count=1)
            raw_event_clean = re.sub(r"\sxmlns='[^']+'", '', raw_event_clean, count=1)
            root = ET.fromstring(raw_event_clean)
            system = root.find('.//System')
            if system is not None:
                event_id_elem = system.find('EventID')
                if event_id_elem is not None:
                    event['event_code'] = event_id_elem.text
                
                time_elem = system.find('TimeCreated')
                if time_elem is not None:
                    orig_ts = time_elem.get('SystemTime', '')
                    event['original_timestamp'] = orig_ts
                    event['timestamp'] = normalize_timestamp(orig_ts)
                
                comp_elem = system.find('Computer')
                if comp_elem is not None:
                    event['host'] = comp_elem.text
            
            event_data = root.find('.//EventData')
            if event_data is not None:
                for data in event_data.findall('Data'):
                    name = data.get('Name')
                    val = data.text or ""
                    if name == 'ProcessGuid': event['process_guid'] = val
                    elif name == 'ProcessId': event['process_id'] = val
                    elif name == 'ParentProcessGuid': event['parent_process_guid'] = val
                    elif name == 'ParentProcessId': event['parent_process_id'] = val
                    elif name == 'Image': event['image'] = val
                    elif name == 'CommandLine': event['command_line'] = val
                    elif name == 'TargetImage': event['target_image'] = val
                    elif name == 'SourceProcessGUID': event['process_guid'] = val
                    elif name == 'SourceProcessId': event['process_id'] = val
                    elif name == 'SourceImage': event['image'] = val
                    elif name == 'User': event['user'] = val
                    elif name == 'SourceIp': event['src_ip'] = val
                    elif name == 'DestinationIp': event['dst_ip'] = val
                    elif name == 'SourcePort': event['src_port'] = val
                    elif name == 'DestinationPort': event['dst_port'] = val
                    elif name == 'LogonId': event['logon_id'] = val
                    elif name == 'LogonType': event['logon_type'] = val
            
            event['log_type'] = 'sysmon'
        except Exception as e:
            return {'error': str(e), 'line_no': line_no, 'source_file': filepath, 'raw_event': raw_event}
        
        return event

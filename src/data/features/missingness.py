def extract_missingness(row):
    return {
        'has_process_id': 1 if row.get('process_id') else 0,
        'has_user': 1 if row.get('user') else 0,
        'has_command_line': 1 if row.get('command_line') else 0
    }

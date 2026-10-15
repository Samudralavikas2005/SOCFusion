import math
from dateutil import parser as dt_parser

def extract_temporal(ts_str):
    if not ts_str:
        return {'hour_sin': 0.0, 'hour_cos': 0.0, 'day_of_week_sin': 0.0, 'day_of_week_cos': 0.0}
    try:
        dt = dt_parser.parse(ts_str)
        hour = dt.hour + dt.minute / 60.0
        dow = dt.weekday() # 0-6
        return {
            'hour_sin': round(math.sin(2 * math.pi * hour / 24.0), 4),
            'hour_cos': round(math.cos(2 * math.pi * hour / 24.0), 4),
            'day_of_week_sin': round(math.sin(2 * math.pi * dow / 7.0), 4),
            'day_of_week_cos': round(math.cos(2 * math.pi * dow / 7.0), 4)
        }
    except Exception:
        return {'hour_sin': 0.0, 'hour_cos': 0.0, 'day_of_week_sin': 0.0, 'day_of_week_cos': 0.0}

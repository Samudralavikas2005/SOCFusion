import csv
import sys
import os
from collections import defaultdict, Counter

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT_FILE = "data/processed/normalized_events_v4.csv"
    
    total = 0
    missing = Counter()
    unique = defaultdict(set)
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames
        for row in reader:
            total += 1
            for k, v in row.items():
                if not v:
                    missing[k] += 1
                else:
                    if len(unique[k]) < 5000:
                        unique[k].add(v)
                        
    for f_name in fields:
        m = missing[f_name]
        p = (m/total)*100
        u = len(unique[f_name]) if f_name in unique else "High"
        if u == 5000: u = "High (>5000)"
        print(f"{f_name} | Missing: {p:.2f}% | Unique: {u}")

if __name__ == "__main__":
    main()

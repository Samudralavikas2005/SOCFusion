import csv
from collections import Counter
c = Counter()
hosts = Counter()
with open('/home/vikas/SOCFusion/data/processed/optc_parsed_enriched.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if row['technique_id']:
            c[row['technique_id']] += 1
            hosts[row['technique_id']] += 1 # wait, this is just count. I will use a simple logic
        if i % 1000000 == 0:
            print(f"Processed {i} rows")
            break # Just testing speed
print(c)

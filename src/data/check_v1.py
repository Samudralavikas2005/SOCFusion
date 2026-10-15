import csv
import sys
csv.field_size_limit(sys.maxsize)

v1_counts = {}
with open('data/processed/optc_annotations_v1.csv', 'r') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        tech = row.get('technique_id')
        conf = row.get('label_confidence')
        if tech and tech != 'None' and tech != 'UNLABELED':
            v1_counts[(tech, conf)] = v1_counts.get((tech, conf), 0) + 1
        if i % 1000000 == 0 and i > 0:
            print(f"Processed {i} rows")

for k, v in v1_counts.items():
    print(f"{k}: {v}")

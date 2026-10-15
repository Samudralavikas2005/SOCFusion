import duckdb

conn = duckdb.connect()
df = conn.execute("""
    SELECT technique_id, COUNT(*) as cnt, COUNT(DISTINCT host) as hosts, COUNT(DISTINCT image) as images
    FROM read_csv_auto('/home/vikas/SOCFusion/data/processed/optc_parsed_enriched.csv', ignore_errors=True)
    WHERE technique_id IS NOT NULL AND technique_id != ''
    GROUP BY technique_id
    ORDER BY cnt DESC
""").df()
print(df)

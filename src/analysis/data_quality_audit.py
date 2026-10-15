import pandas as pd
import os

def main():
    OUT_DIR = "data/analysis/data_quality_v4"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    csv_file = "data/processed/normalized_events_v4.csv"
    print(f"Loading {csv_file}...")
    df = pd.read_csv(csv_file, low_memory=False)
    
    total_rows = len(df)
    missing_stats = []
    
    print("Computing missing statistics...")
    for col in df.columns:
        missing_count = df[col].isna().sum() + (df[col] == "").sum()
        missing_pct = missing_count / total_rows * 100
        missing_stats.append({
            "field": col,
            "missing_count": missing_count,
            "missing_percent": missing_pct
        })
        
    stats_df = pd.DataFrame(missing_stats)
    stats_df = stats_df.sort_values(by="missing_percent", ascending=False)
    
    stats_df.to_csv(os.path.join(OUT_DIR, "missing_statistics.csv"), index=False)
    
    report = f"# Data Quality Report (Normalized Events V4)\n\n"
    report += f"Total Rows: {total_rows}\n"
    report += f"Total Columns: {len(df.columns)}\n\n"
    report += "## Missingness Breakdown\n\n"
    
    for _, row in stats_df.iterrows():
        report += f"- **{row['field']}**: {row['missing_count']} missing ({row['missing_percent']:.2f}%)\n"
        
    with open(os.path.join(OUT_DIR, "data_quality_report.md"), "w") as f:
        f.write(report)
        
    print("Data quality audit complete.")

if __name__ == "__main__":
    main()

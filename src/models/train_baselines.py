import os
import json
import pandas as pd
import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, accuracy_score, balanced_accuracy_score, precision_score, recall_score
import pickle

def main():
    FEAT_CSV = "data/processed/features_v3/features.csv"
    SCHEMA = "data/processed/features_v3/feature_schema.json"
    HOST_PART = "data/analysis/split_v2/host_partition.csv"
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    
    OUT_DIR = "data/processed/baselines_v3"
    ANALYSIS_DIR = "data/analysis/baselines_v3"
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    print("Loading schema and mapping...")
    with open(SCHEMA, 'r') as f:
        schema = json.load(f)
    feature_cols = schema["feature_fields"] + schema["ohe_fields"]
    
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    
    # We need a reverse map or continuous mapping for sklearn models if we drop Track B
    # To keep it simple, we will map Track A labels to 0-11
    track_a_mapped.sort()
    a_to_idx = {orig: i for i, orig in enumerate(track_a_mapped)}
    idx_to_a = {i: orig for i, orig in enumerate(track_a_mapped)}
    
    print("Loading features...")
    # Load in chunks or use specific types to save memory
    df = pd.read_csv(FEAT_CSV, dtype={col: 'float32' for col in feature_cols}, low_memory=False)
    host_part = pd.read_csv(HOST_PART)
    df = df.merge(host_part, on="host", how="left")
    
    # Filter for Track A only
    df = df[df["technique_id"].isin(TRACK_A_CLASSES)].copy()
    
    # Map labels to 0-11
    df['y'] = df['technique_id'].map(lambda x: a_to_idx[label_map[x]])
    
    train_df = df[df["partition"] == "train"]
    val_df = df[df["partition"] == "val"]
    test_df = df[df["partition"] == "test"]
    
    X_train = train_df[feature_cols].values
    y_train = train_df['y'].values
    
    X_val = val_df[feature_cols].values
    y_val = val_df['y'].values
    
    X_test = test_df[feature_cols].values
    y_test = test_df['y'].values
    
    print(f"Train size: {len(X_train)}, Val size: {len(X_val)}, Test size: {len(X_test)}")
    
    results = []
    
    def evaluate(model_name, model):
        print(f"Training {model_name}...")
        model.fit(X_train, y_train)
        
        y_val_pred = model.predict(X_val)
        y_test_pred = model.predict(X_test)
        
        val_f1 = f1_score(y_val, y_val_pred, average='macro', zero_division=0)
        test_f1 = f1_score(y_test, y_test_pred, average='macro', zero_division=0)
        test_acc = accuracy_score(y_test, y_test_pred)
        
        print(f"{model_name} - Val F1: {val_f1:.4f} | Test F1: {test_f1:.4f}")
        
        results.append({
            'Model': model_name,
            'Val_Macro_F1': val_f1,
            'Test_Macro_F1': test_f1,
            'Test_Accuracy': test_acc
        })
        
        with open(os.path.join(OUT_DIR, f"{model_name.replace(' ', '_')}.pkl"), "wb") as f:
            pickle.dump(model, f)
            
    # A. Majority Class
    evaluate("Majority Baseline", DummyClassifier(strategy="most_frequent"))
    
    # B. Logistic Regression
    evaluate("Logistic Regression", LogisticRegression(class_weight='balanced', max_iter=500, n_jobs=-1))
    
    # C. Random Forest
    evaluate("Random Forest", RandomForestClassifier(n_estimators=100, class_weight='balanced', n_jobs=-1, random_state=42, max_depth=15))
    
    # Removed XGBoost as it is not installed
    results_df = pd.DataFrame(results)
    results_df.to_csv(os.path.join(ANALYSIS_DIR, "baseline_results.csv"), index=False)
    print("Baselines evaluation complete.")

if __name__ == "__main__":
    main()

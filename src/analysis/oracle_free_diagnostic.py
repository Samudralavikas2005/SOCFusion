import os
import csv
import json
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, balanced_accuracy_score
from sklearn.neural_network import MLPClassifier

def main():
    OUT_DIR = "data/analysis/performance_recovery"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    FEAT_CSV = "data/processed/features_v4/features.csv"
    LABEL_MAP = "data/processed/graphs_v1/label_mapping.json"
    
    with open(LABEL_MAP, 'r') as f:
        label_map = json.load(f)
        
    track_a_classes = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in track_a_classes]
    track_a_mapped.sort()
    a_to_idx = {orig: i for i, orig in enumerate(track_a_mapped)}
    
    print("Loading features...")
    df = pd.read_csv(FEAT_CSV, low_memory=False)
    
    # Filter for Track A
    df['tid_mapped'] = df['technique_id'].map(lambda x: label_map.get(x, -1))
    df = df[df['tid_mapped'].isin(track_a_mapped)].copy()
    df['label'] = df['tid_mapped'].map(a_to_idx)
    
    train_df = df[df['partition'] == 'train']
    val_df = df[df['partition'] == 'val']
    
    SCHEMA = "data/processed/features_v4/feature_schema.json"
    with open(SCHEMA, 'r') as f:
        schema = json.load(f)
        
    feats = schema['feature_fields'] + schema['ohe_fields']
    
    X_train = train_df[feats].values
    y_train = train_df['label'].values
    
    X_val = val_df[feats].values
    y_val = val_df['label'].values
    
    results = []
    
    print("Evaluating Majority Baseline...")
    maj_class = int(pd.Series(y_train).mode()[0])
    y_pred_maj = np.full_like(y_val, maj_class)
    results.append({
        'Model': 'Majority',
        'Val_Accuracy': accuracy_score(y_val, y_pred_maj),
        'Val_Macro_F1': f1_score(y_val, y_pred_maj, average='macro', zero_division=0),
        'Val_Bal_Acc': balanced_accuracy_score(y_val, y_pred_maj)
    })
    
    print("Evaluating Logistic Regression...")
    lr = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
    lr.fit(X_train, y_train)
    y_pred_lr = lr.predict(X_val)
    results.append({
        'Model': 'Logistic Regression',
        'Val_Accuracy': accuracy_score(y_val, y_pred_lr),
        'Val_Macro_F1': f1_score(y_val, y_pred_lr, average='macro', zero_division=0),
        'Val_Bal_Acc': balanced_accuracy_score(y_val, y_pred_lr)
    })
    
    print("Evaluating Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_val)
    results.append({
        'Model': 'Random Forest',
        'Val_Accuracy': accuracy_score(y_val, y_pred_rf),
        'Val_Macro_F1': f1_score(y_val, y_pred_rf, average='macro', zero_division=0),
        'Val_Bal_Acc': balanced_accuracy_score(y_val, y_pred_rf)
    })
    
    print("Evaluating Event MLP...")
    mlp = MLPClassifier(hidden_layer_sizes=(128, 128), random_state=42, max_iter=200, early_stopping=True)
    mlp.fit(X_train, y_train)
    y_pred_mlp = mlp.predict(X_val)
    results.append({
        'Model': 'Event MLP',
        'Val_Accuracy': accuracy_score(y_val, y_pred_mlp),
        'Val_Macro_F1': f1_score(y_val, y_pred_mlp, average='macro', zero_division=0),
        'Val_Bal_Acc': balanced_accuracy_score(y_val, y_pred_mlp)
    })
    
    pd.DataFrame(results).to_csv(os.path.join(OUT_DIR, "baseline_comparison.csv"), index=False)
    print("Oracle-free diagnostic complete.")
    for r in results:
        print(f"{r['Model']} - Acc: {r['Val_Accuracy']:.4f}, Macro-F1: {r['Val_Macro_F1']:.4f}")
        
if __name__ == "__main__":
    main()

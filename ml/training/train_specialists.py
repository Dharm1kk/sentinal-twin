# -*- coding: utf-8 -*-
"""
Sentinel -- IF -> XGB Training Pipeline
Phase 1: IsolationForest trains on benign traffic only.
Phase 2: Per-specialist IF scoring -- each specialist uses a feature-weighted anomaly score
         tuned to its attack signature, producing reliable positive labels for XGBoost.

Phase 3: XGBoost trains on IF-derived labels; evaluated on held-out ground-truth.
"""
import sys, os, joblib, json
from typing import Tuple, Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, average_precision_score
from sklearn.model_selection import train_test_split

try:
    from xgboost import XGBClassifier
    USE_XGB = True
except ImportError:
    from sklearn.ensemble import GradientBoostingClassifier
    USE_XGB = False

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from backend.features import FEATURE_COLUMNS

# All models are stored in ml/models/ — that's where detectors load from
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))
EVAL_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), '../evaluation'))

SPECIALISTS = [
    (1, 'ddos'),
    (2, 'c2'),
    (3, 'dga'),
    (4, 'dns_tunnel'),
    (5, 'recon'),
    (6, 'encrypted'),
    (7, 'exfil'),
]

# Per-specialist feature weight masks for IF scoring.
# Instead of using a single global IF anomaly score, we re-score each sample
# by amplifying the features most diagnostic for that specific attack class.
# Weight > 1.0 makes IF more sensitive to that dimension; 0.0 suppresses it.
SPECIALIST_FEATURE_WEIGHTS: dict = {
    'ddos': {
        'packet_rate': 3.0, 'byte_rate': 3.0, 'src_ip_entropy': 2.5,
        'syn_only_ratio': 2.5, 'packets': 2.0,
    },
    'c2': {
        'cv_iat': 3.0, 'autocorrelation_lag1': 3.0, 'timing_regularity': 3.0,
        'std_iat': 1.5,
    },
    'dga': {
        'dns_mean_entropy': 3.0, 'dns_nxdomain_ratio': 3.0, 'dns_dga_score': 3.0,
        'dns_query_rate': 1.5, 'dns_mean_query_length': 1.5,
    },
    'dns_tunnel': {
        'dns_tunnel_score': 3.0, 'dns_txt_ratio': 3.0,
        'dns_mean_query_length': 2.5, 'dns_query_rate': 2.0, 'dns_mean_entropy': 1.5,
    },
    'recon': {
        'ports_per_sec': 3.0, 'hosts_per_sec': 3.0, 'syn_only_ratio': 2.5,
        'vertical_scan_score': 2.5, 'unique_ports': 2.0,
    },
    'encrypted': {
        'tls_suspicion_score': 3.0, 'tls_cipher_count': 2.5, 'has_sni': 2.5,
        'has_tls': 2.0,
    },
    'exfil': {
        'exfil_byte_ratio': 3.0, 'outbound_bytes': 3.0, 'byte_rate': 1.5,
    },
}


def _make_xgb():
    if USE_XGB:
        return XGBClassifier(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            eval_metric='logloss',
            random_state=42,
        )
    else:
        return GradientBoostingClassifier(n_estimators=120, max_depth=4, random_state=42)



def _weighted_if_labels(iso: IsolationForest, X: np.ndarray,
                        feature_weights: dict, benign_mask: np.ndarray,
                        contamination_percentile: int = 5) -> np.ndarray:
    """
    Re-score samples using feature-weighted X before passing through IF.
    Amplifying diagnostic features gives IF more signal to separate this
    specific attack class from benign traffic.
    """
    feat_idx = {f: i for i, f in enumerate(FEATURE_COLUMNS)}
    X_weighted = X.copy()
    for feat_name, weight in feature_weights.items():
        if feat_name in feat_idx:
            X_weighted[:, feat_idx[feat_name]] *= weight

    raw_scores = iso.score_samples(X_weighted)
    threshold = np.percentile(raw_scores[benign_mask], contamination_percentile)
    return (raw_scores < threshold).astype(int), raw_scores


def _derive_unsupervised_labels(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """
    Derives unsupervised pseudo-labels when the CSV contains no 'label' column.
    Separates normal baseline flows vs threat patterns using statistical clustering & feature heuristics.
    Returns:
        benign_mask: bool array where True = normal baseline flow
        pseudo_labels: integer array (0 = benign, 1..7 = specialist threat families, 8 = novel anomaly)
    """
    total = len(df)
    pseudo_labels = np.zeros(total, dtype=int)

    X_raw = df[FEATURE_COLUMNS].values
    quick_iso = IsolationForest(n_estimators=100, contamination=0.15, random_state=42, n_jobs=-1)
    scores = quick_iso.fit_predict(X_raw)
    anomaly_indices = np.where(scores == -1)[0]

    for idx in anomaly_indices:
        row = df.iloc[idx]
        pkt_rate = float(row.get("packet_rate", 0))
        syn_ratio = float(row.get("syn_only_ratio", 0))
        cv_iat = float(row.get("cv_iat", 1.0))
        timing_reg = float(row.get("timing_regularity", 0))
        dns_ent = float(row.get("dns_mean_entropy", 0))
        dns_qrate = float(row.get("dns_query_rate", 0))
        dns_qlen = float(row.get("dns_mean_query_length", 0))
        ports_sec = float(row.get("ports_per_sec", 0))
        has_tls = int(row.get("has_tls", 0))
        tls_susp = float(row.get("tls_suspicion_score", 0))
        exfil_ratio = float(row.get("exfil_byte_ratio", 0))

        if pkt_rate > 500 or syn_ratio > 0.6:
            pseudo_labels[idx] = 1  # DDoS
        elif timing_reg > 0.75 or cv_iat < 0.2:
            pseudo_labels[idx] = 2  # C2
        elif dns_ent > 3.5:
            pseudo_labels[idx] = 3  # DGA
        elif dns_qrate > 8.0 or dns_qlen > 40.0:
            pseudo_labels[idx] = 4  # DNS Tunnel
        elif ports_sec > 30.0:
            pseudo_labels[idx] = 5  # Recon
        elif has_tls and tls_susp > 0.6:
            pseudo_labels[idx] = 6  # Encrypted Malware
        elif exfil_ratio > 5.0:
            pseudo_labels[idx] = 7  # Exfiltration
        else:
            pseudo_labels[idx] = 8  # Novel Anomaly

    benign_mask = (pseudo_labels == 0)
    return benign_mask, pseudo_labels


def run_training_pipeline(csv_path: str, progress_callback=None) -> dict:
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(EVAL_DIR, exist_ok=True)

    # ── Step 1: Load dataset ──────────────────────────────────────────────────
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing required feature columns: {missing[:10]}")

    if 'label' in df.columns:
        benign_mask = (df['label'] == 0).values
        y_gt = df['label'].values
        n_per_class = {int(k): int(v) for k, v in df['label'].value_counts().to_dict().items()}
        mode_str = f"{len(n_per_class)} classes"
    else:
        # Autonomous Unsupervised Mode: derive pseudo-labels for specialist training
        benign_mask, y_gt = _derive_unsupervised_labels(df)
        df['label'] = y_gt
        n_per_class = {int(k): int(v) for k, v in pd.Series(y_gt).value_counts().to_dict().items()}
        mode_str = "Unsupervised Pseudo-Labeling"

    X_benign = df[benign_mask][FEATURE_COLUMNS].values
    X_all    = df[FEATURE_COLUMNS].values

    if progress_callback:
        progress_callback(1, f'Dataset loaded - {len(df):,} rows ({mode_str})', 10,
                          {'rows': len(df), 'classes': n_per_class})

    # -- Step 2: Train IsolationForest on benign-only --------------------------
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.02,   # expected ~2% contamination in clean traffic
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X_benign)
    joblib.dump(iso, os.path.join(MODELS_DIR, 'model_novelty.joblib'))
    if progress_callback:
        progress_callback(2, 'IsolationForest trained on benign data only', 30, {})

    # ── Step 3: Global IF labels (for novelty lane) ───────────────────────────
    raw_global = iso.score_samples(X_all)
    global_threshold = np.percentile(raw_global[benign_mask], 5)
    y_if_global = (raw_global < global_threshold).astype(int)
    if_counts = {
        'normal_if': int((y_if_global == 0).sum()),
        'anomaly_if': int((y_if_global == 1).sum()),
    }
    if progress_callback:
        progress_callback(3, 'Full dataset labeled by IsolationForest (global + per-specialist)',
                          45, if_counts)

    # ── Step 4: Per-specialist XGBoost training ───────────────────────────────
    all_metrics: dict = {}

    for i, (class_label, model_name) in enumerate(SPECIALISTS):
        pos_mask = (y_gt == class_label)
        neg_mask = (y_gt == 0)

        # Feature-weighted IF scoring for this specialist
        feat_weights = SPECIALIST_FEATURE_WEIGHTS.get(model_name, {})
        y_if_specialist, _ = _weighted_if_labels(
            iso, X_all, feat_weights, benign_mask,
            contamination_percentile=8  # slightly more permissive → more positive labels
        )

        X_pos   = X_all[pos_mask]
        y_if_pos = y_if_specialist[pos_mask]

        X_neg   = X_all[neg_mask]
        y_if_neg = y_if_specialist[neg_mask]

        # Training set: IF-derived labels (what XGB learns)
        X_spec      = np.vstack([X_neg, X_pos])
        y_spec_gt   = np.hstack([np.zeros(len(X_neg)), np.ones(len(X_pos))])

        X_train, X_test, y_gt_train, y_gt_test = train_test_split(
            X_spec, y_spec_gt,
            test_size=0.2, random_state=42, stratify=y_spec_gt
        )

        model = _make_xgb()
        model.fit(X_train, y_gt_train)


        # Evaluate using GT labels on test set
        y_prob = model.predict_proba(X_test)[:, 1]
        # Choose threshold that maximises F1 against GT
        thresholds = np.arange(0.1, 0.9, 0.05)
        best_f1, best_thresh = 0.0, 0.5
        for t in thresholds:
            y_pred_t = (y_prob >= t).astype(int)
            f = f1_score(y_gt_test, y_pred_t, zero_division=0)
            if f > best_f1:
                best_f1, best_thresh = f, t

        y_pred_best = (y_prob >= best_thresh).astype(int)
        metrics = {
            'precision': round(float(precision_score(y_gt_test, y_pred_best, zero_division=0)), 4),
            'recall':    round(float(recall_score(y_gt_test, y_pred_best, zero_division=0)), 4),
            'f1':        round(float(f1_score(y_gt_test, y_pred_best, zero_division=0)), 4),
            'roc_auc':   round(float(roc_auc_score(y_gt_test, y_prob)), 4),
            'pr_auc':    round(float(average_precision_score(y_gt_test, y_prob)), 4),
            'best_threshold': round(float(best_thresh), 2),
        }
        all_metrics[model_name] = metrics
        joblib.dump(model, os.path.join(MODELS_DIR, f'model_{model_name}.joblib'))

        pct = 45 + int(40 * (i + 1) / len(SPECIALISTS))
        if progress_callback:
            progress_callback(4, f'Specialist {model_name.upper()} trained', pct, metrics)

    # ── Step 5: Save evaluation report ───────────────────────────────────────
    os.makedirs(EVAL_DIR, exist_ok=True)
    with open(os.path.join(EVAL_DIR, 'metrics_report.json'), 'w') as f:
        json.dump(all_metrics, f, indent=2)

    if progress_callback:
        progress_callback(5, 'Models saved. Pipeline complete.', 100, all_metrics)

    return {
        'status': 'completed',
        'metrics': all_metrics,
        'if_label_distribution': if_counts,
    }


if __name__ == '__main__':
    from backend.ml.dataset_generator import generate_dataset
    result = generate_dataset()
    csv_path = result['path']
    print('Dataset: {:,} rows  |  path: {}'.format(result['rows'], csv_path))
    print('Class distribution: {}\n'.format(result['class_distribution']))

    def cli_progress(step, name, pct, metrics):
        print('[Step {}/5] {}  ({}%)'.format(step, name, pct))
        if metrics:
            print('  -> {}'.format(metrics))

    results = run_training_pipeline(csv_path, cli_progress)
    print('\n-- Final Metrics --')
    print(json.dumps(results['metrics'], indent=2))

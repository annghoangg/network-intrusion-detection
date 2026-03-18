## Slide 1 — Title Page

- **Title:** Network Intrusion Detection System Using Machine Learning on CICIDS2017
- **Subtitle:** DAP391m — Group 1
- **Names:** Nguyen Hoang An (Leader), Vu Ngoc Hai Dang, Le Trung Kien, Le Trung Hieu, Do Anh Thu
- **Visual:** University logo, date (2026)

---

## Slide 2 — Problem Statement

- Cyberattacks growing in frequency and sophistication
- Traditional signature-based IDS cannot detect **novel/zero-day attacks**
- ML can learn complex traffic patterns directly from data
- **Our Goal:** Build an ML-based NIDS that classifies traffic as benign or 1 of 7 attack types
- **Visual:** A network security illustration or simple IDS diagram

---

## Slide 3 — Project Overview

- **Dataset:** CICIDS2017 — 2.83M flows, 78 features
- **Input:** Network flow features (packet lengths, IAT, flags...)
- **Output:** Classification label (BENIGN or attack type)
- **Models:** 6 algorithms compared
- **Deployment:** Streamlit dashboard + SHAP explanations
- **Visual:** Pipeline diagram → `Input CSVs → Ingestion → EDA → Preprocessing → Feature Eng. → Model Training → Deployment`

---

## Slide 4 — Dataset: CICIDS2017

- Published by Canadian Institute for Cybersecurity
- 5 days of network traffic (Mon–Fri)
- **8 CSV files** → **2,830,743 rows** × **79 columns**
- Features from CICFlowMeter: packet lengths, flow duration, IAT stats, TCP flags, window sizes
- **Visual:** Screenshot of `data.info()` or `data.shape` output

---

## Slide 5 — Data Cleaning Pipeline

Numbered list:
1. Column name standardisation (strip whitespace)
2. Duplicate removal → **308,381 rows** (10.89%) removed
3. Identical column detection → **12 redundant columns** dropped
4. Infinite values → replaced with NaN (Flow Bytes/s, Flow Packets/s)
5. Missing values → 1,358 rows dropped (0.05%)
6. Label standardisation → 15 labels grouped into 8 categories

**Result:** 2,830,743 → **2,522,362 rows** × **67 columns**

---

## Slide 6 — Attack Type Grouping

Show this table:

| Group | Original Labels | Count |
|-------|----------------|-------|
| BENIGN | BENIGN | 2,095,057 |
| DoS | Hulk, GoldenEye, slowloris, Slowhttptest | ≈197,000 |
| DDoS | DDoS | 128,027 |
| PortScan | PortScan | 90,694 |
| Brute Force | FTP/SSH-Patator | 13,835 |
| Web Attack | Brute Force, XSS, SQL Injection | 2,180 |
| Bot | Bot | 1,966 |
| Heartbleed | Heartbleed | 11 |
| *Removed* | Infiltration | 36 |

Key point: **Severe class imbalance — BENIGN = 83.1%**

- **Visual:** Screenshot of class distribution bar chart from notebook

---

## Slide 7 — Feature Selection

**Left side — text:**
- Correlation analysis → removed 5 features (|r| ≥ 0.95)
- Levene's test → confirmed unequal variances
- Kruskal-Wallis H-test (non-parametric ranking)
- Random Forest feature importance (model-based ranking)
- Removed 8 low-importance features
- **Final: 54 features + 1 target**

**Right side — visual:** Screenshot of correlation heatmap OR combined RF + Kruskal-Wallis chart

---

## Slide 8 — Experimental Setup

- **Train/Test Split:** 80/20 stratified
- **Primary Metric:** F1-macro (treats all classes equally)
- **Why F1-macro?** Accuracy alone is misleading — predicting only BENIGN gives 83%
- Additional metrics: Accuracy, F1-weighted, ROC-AUC, MCC
- **Formula (optional):** F1-macro = (1/C) × Σ F1_c

---

## Slide 9 — Models Overview

Show this table:

| Model | Type | Key Idea |
|-------|------|----------|
| Logistic Regression | Linear | Softmax probability (baseline) |
| Decision Tree | Non-linear | Gini impurity, max_depth=20 |
| Random Forest | Bagging | 300 trees, majority vote |
| XGBoost | Boosting | Sequential error correction + regularisation |
| LightGBM | Boosting | Leaf-wise growth, fastest training |
| Extra Trees | Bagging | Random thresholds (faster than RF) |

Optionally show: Bagging = parallel averaging vs. Boosting = sequential correction

---

## Slide 10 — Hyperparameter Tuning & Ensemble

**Left side — Tuning:**
- RandomizedSearchCV (3-fold) on top 3 models
- **Result: Tuning degraded performance!**
- LightGBM collapsed to F1-macro 0.097
- Cause: `class_weight='balanced'` over-amplified rare classes
- **Takeaway:** Aggressive rebalancing backfires with extreme minority classes

**Right side — Ensemble:**
- Soft Voting: XGBoost + LightGBM + RF
- Averages predicted probabilities
- Marginal improvement but 3× inference cost → not selected

- **Visual:** Screenshot of tuned vs baseline comparison table from `08_hyperparameter_tuning.ipynb`

---

## Slide 11 — Baseline Results

Show this table:

| Model | Accuracy | F1-macro | F1-weighted | Train Time |
|-------|----------|----------|-------------|------------|
| Logistic Regression | 97.62% | 0.567 | 0.976 | — |
| Decision Tree | 99.83% | 0.784 | 0.998 | — |
| Random Forest | 99.82% | 0.827 | 0.998 | 277.6s |
| **XGBoost** | **99.87%** | **0.859** | 0.999 | 112.8s |
| LightGBM | 99.89% | 0.830 | 0.999 | 69.6s |
| Extra Trees | 99.78% | 0.813 | 0.998 | 81.0s |

- **Visual:** Screenshot of F1-macro bar chart from `09_model_comparison.ipynb`

---

## Slide 12 — XGBoost Detailed Results

- Show side by side:
  - **Left:** Screenshot of XGBoost classification report from `05_xgboost.ipynb`
  - **Right:** Screenshot of XGBoost confusion matrix from `05_xgboost.ipynb`

---

## Slide 13 — Per-Class Performance

**Left side — key points:**
- ✅ High-volume (BENIGN, DoS, DDoS, Brute Force): F1 > 0.99
- ⚠️ Medium (PortScan, Bot): F1 ≈ 0.74–0.82
- ❌ Low-volume (Web Attacks): F1 ≈ 0.3
- ❓ Heartbleed: F1 = 1.0 but only 2 test samples

**Right side — visual:** Screenshot of Per-Class F1 Heatmap from `09_model_comparison.ipynb` (STEP 6)

---

## Slide 14 — Error Analysis

**Left side — key findings:**
- **Web Attack cross-confusion:** 62.3% of XSS → misclassified as Brute Force (same HTTP patterns, need payload features to distinguish)
- **BENIGN false positive rate:** Only 0.11% (≈1 false alert per 900 connections)
- **Overall error rate:** ≈700 / 504,153 = **0.13%**

**Right side — visual:** Screenshot of Top Misclassification Pairs bar chart from `09_model_comparison.ipynb` (STEP 7)

---

## Slide 15 — Model Selection: Why XGBoost?

**XGBoost vs LightGBM (tied rank 1.50):**

| Criterion | XGBoost | LightGBM |
|-----------|---------|----------|
| F1-macro | **0.859** | 0.830 |
| ROC-AUC | **1.0** | — |
| Train time | 112.8s | 69.6s |

**Why not Ensemble?**
- 3× model size & memory
- 3× inference latency (IDS needs real-time speed)
- Only marginal improvement

→ Saved as `models/xgboost_best_model.joblib`

---

## Slide 16 — Dashboard Demo

**Left side — features:**
- Upload CSV or use sample data
- Real-time classification with probabilities
- SHAP feature explanations
- Components: `app/app.py`, `xgboost_best_model.joblib`, `label_encoder.joblib`
- Run: `streamlit run app/app.py`

**Right side — visual:** Screenshot of the Streamlit dashboard interface

---

## Slide 17 — Key Findings

1. **Non-linear models essential** — LR (0.567) vs tree-based (>0.78)
2. **Boosting > Bagging** — XGBoost (0.859) > RF (0.827)
3. **Aggressive rebalancing backfires** — Tuned LightGBM collapsed to 0.097
4. **Data is the bottleneck** — Web Attack F1 ≈ 0.3 (needs more data, not better models)
5. **Best model:** XGBoost — 99.87% accuracy, 0.859 F1-macro

---

## Slide 18 — Limitations & Future Work

**Limitations:**
- CICIDS2017 is lab-generated (may not reflect real-world diversity)
- Network-flow features only (no payload/application-layer info)
- Extreme minority classes have too few samples

**Future work:**
- Deep learning (1D-CNN, LSTM) on raw packet sequences
- Augment with newer datasets (UNSW-NB15, CIC-IDS-2018)
- Online/incremental learning for evolving attacks
- Enhanced SHAP explainability for security analysts

---

## Slide 19 — Thank You / Q&A

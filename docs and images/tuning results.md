# Modelling Phase — Walkthrough & Conclusions

## Baseline Results (6 models)

| Model | F1 macro | F1 weighted | ROC-AUC macro | Training Time |
|-------|----------|-------------|---------------|---------------|
| **XGBoost** | **0.8585** | 0.9987 | **1.0** | 112.8s |
| LightGBM | 0.8297 | **0.9989** | 0.9981 | 69.6s |
| Random Forest | 0.8268 | 0.9982 | 0.9866 | 277.6s |
| Extra Trees | 0.813 | 0.9978 | 0.9963 | 81.0s |
| Decision Tree | 0.7842 | 0.9983 | 0.9552 | 72.7s |
| Logistic Regression | 0.567 | 0.9762 | 0.9762 | 113.9s |

> [!IMPORTANT]
> **XGBoost baseline** là model tốt nhất tổng thể (F1-macro cao nhất + ROC-AUC = 1.0).

---

## Tuning Results

| Model | F1 macro (baseline → tuned) | Δ | Verdict |
|-------|---------------------------|---|---------|
| Random Forest | 0.8268 → 0.8213 | -0.005 | ~Tương đương |
| XGBoost | 0.8585 → **0.5768** | **-0.282** | ⚠️ Tệ hơn |
| LightGBM | 0.8297 → **0.0971** | **-0.733** | ❌ Collapse |

> [!CAUTION]
> **XGBoost tuned và LightGBM tuned bị xuống nặng.** Nguyên nhân: khi thêm `class_weight='balanced'` / `sample_weight='balanced'`, model bị overcompensate cho minority classes (đặc biệt Heartbleed: 2 samples trong subsample!) → dự đoán sai nhiều ở majority class. Với chỉ 2-4 samples cho Heartbleed/SQL Injection trong subsample, `class_weight='balanced'` gán trọng số cực lớn cho chúng, phá vỡ balance tổng thể.

**Kết luận tuning:** Baseline XGBoost (không dùng `class_weight`) vẫn tốt hơn tất cả tuned versions. Random Forest tuned gần bằng baseline.

---

## Per-Class Analysis (Baseline)

| Class | LR | DT | RF | **XGB** | LightGBM | ET |
|-------|-----|-----|-----|---------|----------|-----|
| BENIGN | 0.986 | 0.999 | 0.999 | **0.999** | 0.999 | 0.999 |
| Bot | 0.045 | 0.736 | 0.819 | **0.803** | 0.824 | 0.796 |
| Brute Force | 0.856 | 0.998 | 0.997 | **0.999** | 0.999 | 0.996 |
| DDoS | 0.984 | 1.000 | 1.000 | **1.000** | 1.000 | 1.000 |
| DoS | 0.957 | 0.998 | 0.997 | **0.999** | 0.999 | 0.996 |
| Heartbleed | 1.000 | 0.667 | 1.000 | **1.000** | 1.000 | 1.000 |
| PortScan | 0.843 | 0.991 | 0.988 | **0.994** | 0.994 | 0.988 |
| Web Attack BF | 0.000 | 0.735 | 0.774 | **0.752** | 0.779 | 0.736 |
| Web Attack SQL | 0.000 | 0.400 | 0.333 | **0.667** | 0.333 | 0.333 |
| Web Attack XSS | 0.000 | 0.318 | 0.360 | **0.373** | 0.369 | 0.286 |

**Điểm yếu chung:** Web Attack XSS (F1 ~0.3), SQL Injection (F1 ~0.3-0.7), Bot (~0.8). Quá ít samples để cải thiện đáng kể.

---

## Error Analysis (XGBoost — best model)

Top 5 misclassification pairs:
1. **BENIGN → PortScan**: 198 cases (0.05% of BENIGN)
2. **BENIGN → Bot**: 186 cases (0.04%)
3. **Web Attack XSS → Web Attack BF**: 81 cases (**62.3%** of XSS!)
4. **BENIGN → DoS**: 78 cases (0.02%)
5. **Web Attack BF → Web Attack XSS**: 65 cases (**22.1%** of BF!)

> [!NOTE]
> Web Attack XSS và Web Attack Brute Force hay bị nhầm lẫn với nhau (62% XSS bị gán thành BF). Đây là vì 2 loại tấn công này có traffic pattern tương tự nhau.

---

## ★ Model Selection

| Rank | Model | Avg Rank (across 4 metrics) |
|------|-------|-----------------------------|
| 1 | **XGBoost** | **1.50** |
| 2 | LightGBM | 1.50 |
| 3 | Random Forest | 3.75 |
| 4 | Decision Tree | 4.25 |
| 5 | Extra Trees | 4.25 |
| 6 | Logistic Regression | 5.75 |

**★ Recommended: XGBoost (baseline)** — F1-macro 0.8585, F1-weighted 0.9987, ROC-AUC 1.0.

---

## Modelling Phase — Xong chưa?

| Bước | Status |
|------|--------|
| Baseline training (6 models) | ✅ Done |
| Hyperparameter tuning | ✅ Done (kết quả cho thấy baseline tốt hơn tuned) |
| Imbalance handling | ✅ Done (thử `class_weight='balanced'` — kết quả tiêu cực) |
| Metric comparison | ✅ Done |
| Per-class analysis | ✅ Done |
| Error analysis | ✅ Done |
| Model selection | ✅ Done → **XGBoost** |

> [!TIP]
> **Phần modelling đã hoàn tất.** Bước tiếp theo trong pipeline (nếu cần) sẽ là:
> - **Model saving** — export model cuối cùng (pickle/joblib)
> - **Inference pipeline** — code để predict trên dữ liệu mới
> - **Report/Presentation** — tổng hợp kết quả cho báo cáo

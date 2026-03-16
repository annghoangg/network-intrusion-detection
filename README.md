# CICIDS2017 — Network Intrusion Detection

A machine-learning pipeline for multi-class network intrusion detection using the [CICIDS2017](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset/) dataset. A DAP391m project - Group 1.

## Members

- Nguyen Hoang An
- Vu Ngoc Hai Dang
- Le Trung Kien
- Le Trung Hieu
- Do Anh Thu

## Project Structure

```
Project/
├── Input/ - Raw dataset files                  
├── app/ - Streamlit dashboard application
│   ├── app.py - Main Streamlit dashboard script
│   └── samples/ - Sample network flows for demo testing
│
├── docs/ - Project documentation, reports, and planning artifacts
│
├── models/ - Serialized models and encoders
│   ├── label_encoder.joblib
│   └── xgboost_best_model.joblib
│
├── scripts/ - Utility scripts
│   └── generate_samples.py - Script to extract sample network flows for testing
│
├── splits/ - Train/test split data                    
│   ├── X_train.pkl
│   ├── X_test.pkl
│   ├── y_train.pkl
│   └── y_test.pkl
│
├── src/ - Source code and pipeline scripts                                                
│   ├── __init__.py
│   ├── data_ingestion.py - Script to load raw data
│   ├── eda.py - Exploratory Data Analysis functions
│   ├── preprocessing.py - Data cleaning, correlation analysis, and feature selection
│   ├── feature_engineering.py - Feature extraction and transformation
│   └── model_training.py - Train/test split, evaluation, and model comparison
│
├── notebooks/ - Jupyter notebooks for experimentation and analysis
│   ├── 01_data_pipeline.ipynb
│   ├── 02_logistic_regression.ipynb
│   ├── 03_decision_tree.ipynb
│   ├── 04_random_forest.ipynb
│   ├── 05_xgboost.ipynb
│   ├── 06_lightgbm.ipynb
│   ├── 07_extra_trees.ipynb
│   ├── 08_hyperparameter_tuning.ipynb
│   ├── 09_model_comparison.ipynb
│   ├── 10_ensemble_model.ipynb
│   └── results/ - Directory storing notebook outputs
│
├── cicids2017_cleaned.csv - Processed dataset
├── README.md - Project documentation
└── requirements.txt - Python dependencies
```
## Installation

To install all the necessary libraries used in this project, run the following command to install them from the provided text file:

```bash
pip install -r requirements.txt
```

## ML Pipeline Overview

```
Input CSVs  →  data_ingestion  →  eda  →  preprocessing  →  feature_engineering  →  cicids2017_cleaned.csv  →  model training
                                                                                                                     ↓
                                                                                                          (split → train → evaluate)
                                           
                                                                         
```


Run **`notebooks/01_data_pipeline.ipynb`**
This will generate `cicids2017_cleaned.csv`.

**Importing Individual Modules**

```python
from src.data_ingestion     import load_raw_data
from src.preprocessing      import run_preprocessing_pipeline
from src.feature_engineering import run_feature_engineering_pipeline
from src.eda                 import analyze_feature_importance_kruskal
from src.model_training      import evaluate_model, compare_models
```

## Dashboard Demo

To launch the interactive dashboard for testing the trained model:

```bash
streamlit run app/app.py
```

Upload a CSV file containing network flow features, or click **Use Sample Data** to try the demo with pre-loaded test data.

## Target Classes (Attack Types)

| Label | Description |
|-------|-------------|
| BENIGN | Normal traffic |
| DoS | DoS Hulk / GoldenEye / slowloris / Slowhttptest |
| DDoS | Distributed Denial of Service |
| PortScan | Port scanning activity |
| Brute Force | FTP-Patator / SSH-Patator |
| Web Attack | Brute Force / XSS / SQL Injection |
| Bot | Botnet activity |
| Heartbleed | Heartbleed vulnerability exploit |

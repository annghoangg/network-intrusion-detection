"""
CICIDS2017 — Network Intrusion Detection Dashboard
Enhanced version with interactive Plotly charts, tabbed layout, and polished UI.
"""

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import shap
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# ── Paths ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "xgboost_best_model.joblib"
ENCODER_PATH = PROJECT_ROOT / "models" / "label_encoder.joblib"
SAMPLES_DIR = PROJECT_ROOT / "app" / "samples"

EXPECTED_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Bwd PSH Flags", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "PSH Flag Count",
    "ACK Flag Count", "Average Packet Size", "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
    "Active Max", "Active Min", "Idle Mean", "Idle Max", "Idle Min",
]

# ── Attack type color palette ──
ATTACK_COLORS = {
    "BENIGN":       "#10b981",
    "DoS":          "#f59e0b",
    "DDoS":         "#ef4444",
    "PortScan":     "#8b5cf6",
    "Brute Force":  "#f97316",
    "Web Attack":   "#ec4899",
    "Bot":          "#06b6d4",
    "Heartbleed":   "#dc2626",
}

DEFAULT_COLOR = "#6366f1"


def get_color(label):
    return ATTACK_COLORS.get(label, DEFAULT_COLOR)


# ── Cached loaders ──
@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)
    return model, le


@st.cache_resource
def get_explainer():
    model, _ = load_model()
    return shap.TreeExplainer(model)


# ── Custom CSS ──
def inject_css():
    st.markdown("""
    <style>
    /* ── Import font ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    /* ── Root variables ── */
    :root {
        --bg-primary: #0f172a;
        --bg-card: #1e293b;
        --bg-card-hover: #334155;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --accent: #6366f1;
        --accent-glow: rgba(99, 102, 241, 0.3);
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --critical: #dc2626;
        --border: #334155;
        --radius: 12px;
    }

    /* ── Global ── */
    .stApp {
        font-family: 'Inter', sans-serif !important;
    }

    /* ── Metric cards ── */
    .metric-card {
        background: linear-gradient(135deg, var(--bg-card) 0%, rgba(30, 41, 59, 0.8) 100%);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 1.25rem 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
        backdrop-filter: blur(10px);
    }
    .metric-card:hover {
        border-color: var(--accent);
        box-shadow: 0 0 20px var(--accent-glow);
        transform: translateY(-2px);
    }
    .metric-label {
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
        margin-bottom: 0.4rem;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 800;
        color: var(--text-primary);
        line-height: 1.1;
    }
    .metric-value.green  { color: var(--success); }
    .metric-value.yellow { color: var(--warning); }
    .metric-value.red    { color: var(--danger); }
    .metric-value.accent { color: var(--accent); }

    /* ── Threat badge ── */
    .threat-badge {
        display: inline-block;
        padding: 0.35rem 1rem;
        border-radius: 999px;
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-top: 0.5rem;
    }
    .badge-low      { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }
    .badge-medium   { background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }
    .badge-high     { background: rgba(239,68,68,0.15);  color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }
    .badge-critical { background: rgba(220,38,38,0.15);  color: #dc2626; border: 1px solid rgba(220,38,38,0.3); }

    /* ── Section headers ── */
    .section-header {
        font-size: 1.15rem;
        font-weight: 700;
        color: var(--text-primary);
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid var(--accent);
        display: inline-block;
    }

    /* ── Summary table ── */
    .breakdown-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        border-radius: var(--radius);
        overflow: hidden;
        border: 1px solid var(--border);
    }
    .breakdown-table th {
        background: var(--bg-card);
        color: var(--text-secondary);
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 0.75rem 1rem;
        text-align: left;
    }
    .breakdown-table td {
        padding: 0.65rem 1rem;
        border-top: 1px solid var(--border);
        color: var(--text-primary);
        font-size: 0.9rem;
    }
    .breakdown-table tr:hover td {
        background: rgba(99, 102, 241, 0.05);
    }
    .class-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 0.5rem;
        vertical-align: middle;
    }

    /* ── Model info cards ── */
    .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 0.75rem;
    }
    .info-item {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 0.75rem 1rem;
    }
    .info-item .label {
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
    }
    .info-item .value {
        font-size: 1rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-top: 0.15rem;
    }

    /* ── Hide default Streamlit metric ── */
    [data-testid="stMetric"] { display: none; }
    </style>
    """, unsafe_allow_html=True)


def render_metric_card(label, value, color_class=""):
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value {color_class}">{value}</div>
    </div>
    """, unsafe_allow_html=True)


def get_threat_level(attack_rate):
    if attack_rate < 5:
        return "low", "badge-low"
    elif attack_rate < 20:
        return "medium", "badge-medium"
    elif attack_rate < 50:
        return "high", "badge-high"
    else:
        return "critical", "badge-critical"


def render_threat_badge(attack_rate):
    level, badge_class = get_threat_level(attack_rate)
    icon = {"low": "", "medium": "", "high": "", "critical": ""}[level]
    st.markdown(
        f'<div style="text-align:center"><span class="threat-badge {badge_class}">'
        f'{icon} {level} threat</span></div>',
        unsafe_allow_html=True,
    )


# ── Plotly config ──
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color="#f1f5f9"),
    margin=dict(l=40, r=40, t=50, b=40),
    legend=dict(
        bgcolor="rgba(30,41,59,0.8)",
        bordercolor="#334155",
        borderwidth=1,
    ),
)


def styled_plotly(fig, height=400):
    fig.update_layout(**PLOTLY_LAYOUT, height=height)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


# ── Page config ──
st.set_page_config(page_title="NIDS Dashboard", layout="wide")
inject_css()

# ── Sidebar ──
with st.sidebar:
    st.markdown(
        '<h1 style="text-align:center; font-size:1.6rem;">NIDS Dashboard</h1>',
        unsafe_allow_html=True,
    )
    st.caption("CICIDS2017 · XGBoost Classifier")
    st.divider()

    # ── Data source selector ──
    st.markdown("**Data Source**")
    data_source = st.radio(
        "Choose input method:",
        ["Upload CSV", "Use Sample Data"],
        label_visibility="collapsed",
    )

    data = None
    if data_source == "Upload CSV":
        uploaded_file = st.file_uploader("Upload network traffic CSV", type=["csv"])
        if uploaded_file is not None:
            data = pd.read_csv(uploaded_file)

    else:  # Use Sample Data
        sample_files = sorted(SAMPLES_DIR.glob("*.csv"))
        if sample_files:
            selected_sample = st.selectbox(
                "Select sample file:",
                sample_files,
                format_func=lambda p: p.name,
            )
            if st.button("Load Sample", use_container_width=True, type="primary"):
                data = pd.read_csv(selected_sample)
                st.session_state["loaded_data"] = data
            # Persist across reruns
            if "loaded_data" in st.session_state and data is None:
                data = st.session_state["loaded_data"]
        else:
            st.warning("No sample files found in `app/samples/`.")

    st.divider()
    st.markdown(
        "**How to use:**\n"
        "1. Load data (upload or sample)\n"
        "2. Explore the **Overview** tab\n"
        "3. Dive into **Threat Analysis**\n"
        "4. Get AI explanations in **Explainability**"
    )

    # Model info in sidebar
    st.divider()
    with st.expander("Model Info"):
        model, le = load_model()
        st.markdown(f"**Model:** XGBoost")
        st.markdown(f"**Features:** {len(EXPECTED_FEATURES)}")
        st.markdown(f"**Classes:** {len(le.classes_)}")
        st.markdown(f"**Labels:** {', '.join(le.classes_)}")

# ── Main content ──
st.markdown(
    '<h1 style="text-align:center; margin-bottom:0;">Network Intrusion Detection System</h1>',
    unsafe_allow_html=True,
)
st.markdown(
    '<p style="text-align:center; color:#94a3b8; margin-top:0.25rem; margin-bottom:1.5rem;">'
    'Real-time classification of network flows using XGBoost · CICIDS2017</p>',
    unsafe_allow_html=True,
)

if data is None:
    # ── Empty state ──
    st.markdown("---")
    col_empty = st.columns([1, 2, 1])[1]
    with col_empty:
        st.markdown(
            '<div style="text-align:center; padding: 4rem 2rem;">'
            '<p style="font-size:2rem; margin-bottom:0.5rem; color:#6366f1; font-weight:800;">NO DATA</p>'
            '<h3 style="color:#f1f5f9;">No Data Loaded</h3>'
            '<p style="color:#94a3b8;">Upload a CSV file or use sample data from the sidebar to begin analysis.</p>'
            '</div>',
            unsafe_allow_html=True,
        )
    st.stop()

# ── Run predictions ──
model, le = load_model()

missing = [c for c in EXPECTED_FEATURES if c not in data.columns]
if missing:
    st.error(f"Missing {len(missing)} required column(s): {', '.join(missing[:5])}")
    st.stop()

X = data[EXPECTED_FEATURES].copy()
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

with st.spinner("Running predictions..."):
    y_pred = model.predict(X)
    y_labels = le.inverse_transform(y_pred)
    y_proba = model.predict_proba(X)
    confidence = np.max(y_proba, axis=1)

results = data.copy()
results["Prediction"] = y_labels
results["Confidence (%)"] = np.round(confidence * 100, 2)

total = len(results)
benign = int((results["Prediction"] == "BENIGN").sum())
attacks = total - benign
attack_rate = attacks / total * 100

# ══════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════
tab_overview, tab_threats, tab_explain = st.tabs([
    "Overview", "Threat Analysis", "AI Explainability"
])

# ──────────────────────────────────────────────
# TAB 1: OVERVIEW
# ──────────────────────────────────────────────
with tab_overview:
    # ── KPI row ──
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        render_metric_card("Total Flows", f"{total:,}", "accent")
    with k2:
        render_metric_card("Benign", f"{benign:,}", "green")
    with k3:
        render_metric_card("Attacks", f"{attacks:,}", "red")
    with k4:
        render_metric_card("Attack Rate", f"{attack_rate:.1f}%", "yellow")
    with k5:
        render_metric_card("Avg Confidence", f"{confidence.mean() * 100:.1f}%", "accent")

    # Threat level badge
    st.markdown("")
    render_threat_badge(attack_rate)
    st.markdown("")

    # ── Charts row ──
    chart_left, chart_right = st.columns(2)

    with chart_left:
        st.markdown('<div class="section-header">Attack Distribution</div>', unsafe_allow_html=True)
        dist = results["Prediction"].value_counts().reset_index()
        dist.columns = ["Class", "Count"]
        dist["Color"] = dist["Class"].map(get_color)

        fig_donut = go.Figure(go.Pie(
            labels=dist["Class"],
            values=dist["Count"],
            hole=0.55,
            marker=dict(colors=dist["Color"].tolist()),
            textinfo="label+percent",
            textfont=dict(size=12),
            hovertemplate="<b>%{label}</b><br>Count: %{value:,}<br>Share: %{percent}<extra></extra>",
        ))
        fig_donut.update_layout(
            title=None,
            showlegend=True,
            legend=dict(orientation="v", yanchor="middle", y=0.5),
        )
        styled_plotly(fig_donut, height=380)

    with chart_right:
        st.markdown('<div class="section-header">Confidence Distribution</div>', unsafe_allow_html=True)
        fig_hist = go.Figure()
        fig_hist.add_trace(go.Histogram(
            x=results["Confidence (%)"],
            nbinsx=30,
            marker=dict(
                color="#6366f1",
                line=dict(color="#818cf8", width=1),
            ),
            opacity=0.85,
            hovertemplate="Confidence: %{x:.1f}%<br>Count: %{y}<extra></extra>",
        ))
        fig_hist.update_layout(
            xaxis_title="Confidence (%)",
            yaxis_title="Number of Flows",
            bargap=0.05,
        )
        fig_hist.update_xaxes(gridcolor="#1e293b", zeroline=False)
        fig_hist.update_yaxes(gridcolor="#1e293b", zeroline=False)
        styled_plotly(fig_hist, height=380)

    # ── Per-class breakdown table ──
    st.markdown('<div class="section-header">Per-Class Breakdown</div>', unsafe_allow_html=True)

    breakdown = (
        results.groupby("Prediction")
        .agg(
            Count=("Prediction", "size"),
            Avg_Confidence=("Confidence (%)", "mean"),
            Min_Confidence=("Confidence (%)", "min"),
            Max_Confidence=("Confidence (%)", "max"),
        )
        .reset_index()
    )
    breakdown["Share (%)"] = (breakdown["Count"] / total * 100).round(2)
    breakdown = breakdown.sort_values("Count", ascending=False)

    # Build HTML table
    rows_html = ""
    for _, r in breakdown.iterrows():
        c = get_color(r["Prediction"])
        rows_html += (
            f'<tr>'
            f'<td><span class="class-dot" style="background:{c}"></span>{r["Prediction"]}</td>'
            f'<td>{int(r["Count"]):,}</td>'
            f'<td>{r["Share (%)"]:.2f}%</td>'
            f'<td>{r["Avg_Confidence"]:.1f}%</td>'
            f'<td>{r["Min_Confidence"]:.1f}%</td>'
            f'<td>{r["Max_Confidence"]:.1f}%</td>'
            f'</tr>'
        )

    st.markdown(
        f"""
        <table class="breakdown-table">
            <thead>
                <tr>
                    <th>Class</th><th>Count</th><th>Share</th>
                    <th>Avg Conf.</th><th>Min Conf.</th><th>Max Conf.</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )

    # ── Full results expander ──
    st.markdown("")
    with st.expander("View All Predictions"):
        st.dataframe(results, use_container_width=True)

    csv_out = results.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Predictions CSV", csv_out,
        file_name="nids_predictions.csv", mime="text/csv",
    )


# ──────────────────────────────────────────────
# TAB 2: THREAT ANALYSIS
# ──────────────────────────────────────────────
with tab_threats:
    attack_df = results[results["Prediction"] != "BENIGN"]

    if attack_df.empty:
        st.success("No threats detected — all flows are classified as **BENIGN**.")
    else:
        # ── Attack KPIs ──
        n_types = attack_df["Prediction"].nunique()
        avg_att_conf = attack_df["Confidence (%)"].mean()
        low_conf_attacks = int((attack_df["Confidence (%)"] < 80).sum())

        ak1, ak2, ak3 = st.columns(3)
        with ak1:
            render_metric_card("Attack Types Found", n_types, "red")
        with ak2:
            render_metric_card("Avg Attack Confidence", f"{avg_att_conf:.1f}%", "yellow")
        with ak3:
            render_metric_card("Low-Confidence Attacks", low_conf_attacks, "accent")

        st.markdown("")

        # ── Attack timeline ──
        st.markdown('<div class="section-header">Attack Timeline</div>', unsafe_allow_html=True)

        timeline_df = results.copy()
        timeline_df["Flow Index"] = range(len(timeline_df))
        timeline_df["Is Attack"] = timeline_df["Prediction"] != "BENIGN"
        timeline_attacks = timeline_df[timeline_df["Is Attack"]]

        fig_timeline = px.scatter(
            timeline_attacks,
            x="Flow Index",
            y="Confidence (%)",
            color="Prediction",
            color_discrete_map=ATTACK_COLORS,
            hover_data=["Destination Port", "Flow Duration"],
            opacity=0.8,
        )
        fig_timeline.update_traces(
            marker=dict(size=8, line=dict(width=1, color="#0f172a")),
        )
        fig_timeline.update_layout(
            xaxis_title="Flow Index (simulated time →)",
            yaxis_title="Confidence (%)",
            legend_title="Attack Type",
        )
        fig_timeline.update_xaxes(gridcolor="#1e293b", zeroline=False)
        fig_timeline.update_yaxes(gridcolor="#1e293b", zeroline=False)
        styled_plotly(fig_timeline, height=400)

        # ── Filter & table ──
        st.markdown('<div class="section-header">Detected Threats</div>', unsafe_allow_html=True)

        attack_types = sorted(attack_df["Prediction"].unique())
        selected = st.multiselect(
            "Filter by attack type:", attack_types, default=attack_types
        )
        filtered = attack_df[attack_df["Prediction"].isin(selected)]

        conf_range = st.slider(
            "Confidence range (%):", 0.0, 100.0, (0.0, 100.0), step=1.0
        )
        filtered = filtered[
            (filtered["Confidence (%)"] >= conf_range[0])
            & (filtered["Confidence (%)"] <= conf_range[1])
        ]

        st.caption(f"Showing {len(filtered):,} of {len(attack_df):,} detected attacks")

        show_cols = [
            "Prediction", "Confidence (%)", "Destination Port",
            "Flow Duration", "Flow Bytes/s", "Total Fwd Packets",
        ]
        display_df = filtered[show_cols].reset_index()
        display_df.rename(columns={"index": "Row Index"}, inplace=True)
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # ── Feature radar for selected flow ──
        st.markdown('<div class="section-header">Flow Feature Radar</div>', unsafe_allow_html=True)
        st.caption("Select a flow to visualise its top feature values as a radar chart.")

        radar_idx = st.number_input(
            "Row index for radar:", min_value=0, max_value=len(results) - 1, value=0, step=1,
            key="radar_idx",
        )

        radar_features = [
            "Flow Duration", "Total Fwd Packets", "Flow Bytes/s",
            "Fwd Packet Length Mean", "Bwd Packet Length Mean",
            "Flow IAT Mean", "Packet Length Mean", "Average Packet Size",
            "Init_Win_bytes_forward", "Active Mean",
        ]
        row_vals = X.iloc[radar_idx][[f for f in radar_features if f in X.columns]]

        # Normalise to 0-1 for radar
        maxes = X[[f for f in radar_features if f in X.columns]].max()
        maxes = maxes.replace(0, 1)
        norm_vals = (row_vals / maxes).clip(0, 1).tolist()
        cats = row_vals.index.tolist()

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=norm_vals + [norm_vals[0]],
            theta=cats + [cats[0]],
            fill="toself",
            fillcolor="rgba(99,102,241,0.15)",
            line=dict(color="#6366f1", width=2),
            marker=dict(size=6, color="#818cf8"),
            name=f"Flow #{radar_idx}",
            hovertemplate="%{theta}<br>Normalised: %{r:.3f}<extra></extra>",
        ))
        fig_radar.update_layout(
            polar=dict(
                bgcolor="rgba(0,0,0,0)",
                radialaxis=dict(visible=True, range=[0, 1], gridcolor="#334155", tickfont=dict(size=9)),
                angularaxis=dict(gridcolor="#334155", tickfont=dict(size=10, color="#94a3b8")),
            ),
            title=f"Flow #{radar_idx} — {results.iloc[radar_idx]['Prediction']} ({results.iloc[radar_idx]['Confidence (%)']:.1f}%)",
        )
        styled_plotly(fig_radar, height=450)


# ──────────────────────────────────────────────
# TAB 3: AI EXPLAINABILITY
# ──────────────────────────────────────────────
with tab_explain:
    st.markdown(
        '<div class="section-header">SHAP Explanation</div>',
        unsafe_allow_html=True,
    )
    st.write("Select a flow to understand **why** the model made its prediction using SHAP values.")

    explain_col1, explain_col2 = st.columns([1, 3])

    with explain_col1:
        row_idx = st.number_input(
            "Row index to explain",
            min_value=0,
            max_value=len(results) - 1,
            value=0,
            step=1,
            key="shap_row",
        )
        pred_label = results.iloc[row_idx]["Prediction"]
        pred_conf = results.iloc[row_idx]["Confidence (%)"]

        st.markdown(
            f'<div class="metric-card" style="margin-top:0.5rem">'
            f'<div class="metric-label">Predicted Class</div>'
            f'<div class="metric-value" style="font-size:1.4rem; color:{get_color(pred_label)}">{pred_label}</div>'
            f'<div style="color:#94a3b8; font-size:0.85rem; margin-top:0.25rem;">{pred_conf:.1f}% confidence</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        st.markdown("")
        run_shap = st.button("Explain This Prediction", use_container_width=True, type="primary")

    with explain_col2:
        if run_shap:
            row = X.iloc[[row_idx]]
            pred_class_idx = int(y_pred[row_idx])

            with st.spinner("Calculating SHAP values..."):
                explainer = get_explainer()
                shap_values = explainer.shap_values(row)

            # Handle different SHAP output formats
            if isinstance(shap_values, list):
                sv = shap_values[pred_class_idx][0]
                base = explainer.expected_value[pred_class_idx]
            elif shap_values.ndim == 3:
                sv = shap_values[0, :, pred_class_idx]
                base = explainer.expected_value[pred_class_idx]
            else:
                sv = shap_values[0]
                base = explainer.expected_value

            # Build SHAP Explanation object
            explanation = shap.Explanation(
                values=sv,
                base_values=float(base),
                data=row.values[0],
                feature_names=EXPECTED_FEATURES,
            )

            top_k = 15
            top_indices = np.argsort(np.abs(sv))[::-1][:top_k]

            # ── Waterfall plot ──
            fig_wf, ax_wf = plt.subplots(figsize=(10, 6))
            shap.plots.waterfall(explanation, max_display=top_k, show=False)
            plt.title(f"SHAP Waterfall — {pred_label}", fontsize=14, color="#f1f5f9")
            ax_wf = plt.gca()
            ax_wf.set_facecolor("#0f172a")
            fig_wf = plt.gcf()
            fig_wf.patch.set_facecolor("#0f172a")
            for spine in ax_wf.spines.values():
                spine.set_color("#334155")
            ax_wf.tick_params(colors="#94a3b8")
            ax_wf.xaxis.label.set_color("#94a3b8")
            ax_wf.yaxis.label.set_color("#94a3b8")
            plt.tight_layout()
            st.pyplot(fig_wf)
            plt.close()

            # ── SHAP feature importance bar chart (Plotly) ──
            st.markdown("")
            st.markdown('<div class="section-header">Feature Impact (Top 15)</div>', unsafe_allow_html=True)

            feat_names = [EXPECTED_FEATURES[i] for i in top_indices]
            feat_impacts = [float(sv[i]) for i in top_indices]
            feat_vals = [float(row.values[0][i]) for i in top_indices]
            colors = ["#10b981" if v > 0 else "#ef4444" for v in feat_impacts]

            fig_bar = go.Figure(go.Bar(
                x=feat_impacts[::-1],
                y=feat_names[::-1],
                orientation="h",
                marker=dict(color=colors[::-1]),
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "SHAP Impact: %{x:.4f}<br>"
                    "<extra></extra>"
                ),
            ))
            fig_bar.update_layout(
                xaxis_title="SHAP Value (impact on prediction)",
                yaxis_title="",
            )
            fig_bar.update_xaxes(gridcolor="#1e293b", zeroline=True, zerolinecolor="#475569")
            fig_bar.update_yaxes(gridcolor="#1e293b")
            styled_plotly(fig_bar, height=450)

            # ── Feature table ──
            st.markdown('<div class="section-header">Feature Details</div>', unsafe_allow_html=True)
            feat_df = pd.DataFrame({
                "Feature": feat_names,
                "Value": feat_vals,
                "SHAP Impact": [round(v, 4) for v in feat_impacts],
                "Direction": ["Pushes toward" if v > 0 else "Pushes away" for v in feat_impacts],
            })
            st.dataframe(feat_df, use_container_width=True, hide_index=True)

        else:
            st.markdown(
                '<div style="text-align:center; padding: 3rem 2rem; color:#94a3b8;">'
                '<p style="font-size:1.5rem; margin-bottom:0.5rem; color:#6366f1; font-weight:800;">SHAP</p>'
                '<p>Select a row index and click <b>Explain This Prediction</b> to see the SHAP analysis.</p>'
                '</div>',
                unsafe_allow_html=True,
            )

import sys
import os
import warnings
warnings.filterwarnings("ignore")

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import streamlit as st
import pandas as pd
import json
import plotly.express as px
from collections import Counter, defaultdict

try:
    from src.attack_chain.simplifier import simplify_technique_chain
except ModuleNotFoundError:
    try:
        from simplifier import simplify_technique_chain
    except ModuleNotFoundError:
        def simplify_technique_chain(techniques):
            if not techniques:
                return []
            res = [techniques[0]]
            for t in techniques[1:]:
                if t != res[-1]:
                    res.append(t)
            return res

# ============================================================
# MITRE ATT&CK TECHNIQUE EXPLANATIONS
# ============================================================
MITRE_EXPLANATIONS = {
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Attackers may access LSASS process memory to obtain credential material such as passwords or hashes."),
    "T1003.003": ("OS Credential Dumping: NTDS", "Attackers may access the Active Directory NTDS database to obtain credential information and domain account data."),
    "T1016": ("System Network Configuration Discovery", "Attackers may inspect network configuration such as interfaces, IP addresses, routes, and DNS information."),
    "T1018": ("Remote System Discovery", "Attackers may discover other systems on the network to identify potential targets."),
    "T1021.006": ("Windows Remote Management", "Attackers may use WinRM to interact with remote Windows systems and execute actions as the logged-on user."),
    "T1047": ("Windows Management Instrumentation", "Attackers may abuse WMI to execute commands or perform actions on Windows systems."),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Attackers may create or modify scheduled tasks to execute programs at a chosen time or trigger."),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Attackers may use PowerShell to execute commands and scripts on Windows systems."),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Attackers may use cmd.exe or Windows command-shell commands to execute actions."),
    "T1068": ("Exploitation for Privilege Escalation", "Attackers may exploit a weakness to obtain higher privileges on a compromised system."),
    "T1087.002": ("Account Discovery: Domain Account", "Attackers may enumerate domain accounts to understand available users and identify accounts of interest."),
    "T1056.001": ("Input Capture: Keylogging", "Attackers may log keystrokes to intercept user credentials, passwords, or confidential messages as they are typed."),
    "T1105": ("Ingress Tool Transfer", "Attackers may transfer tools, payloads, or other files from an external system into a compromised environment."),
    "T1112": ("Modify Registry", "Attackers may modify the Windows Registry to change configuration, support persistence, or alter security settings."),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", "Attackers may request service tickets for accounts with service principal names and attempt to crack the ticket material."),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Attackers may disable or modify security tools and defensive settings to reduce detection."),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Using the active Meterpreter session, the attacker ran the 'download' command to retrieve the password/credential file from the compromised machine. This collects NTLM hashes and credential material stored in LSASS memory or the SAM database, transferring the file directly to the attacker's Kali Linux machine over the established reverse TCP channel."),
}

# ============================================================
# SOCFusion V4 / GAT V2 DASHBOARD
# ============================================================

st.set_page_config(
    page_title="SOCFusion Dashboard",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS
# ============================================================

st.markdown("""
<style>

.stApp {
    background-color: #0F172A;
    color: #F8FAFC;
    font-family: 'Inter', sans-serif;
}

.glass-card {
    background: rgba(30, 41, 59, 0.72);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 16px;
    padding: 22px;
    margin-bottom: 18px;
}

.metric-value {
    font-size: 2.4rem;
    font-weight: 800;
    color: #00CEC9;
}

h1, h2, h3 {
    color: #00CEC9;
}

.section-title {
    color: #00CEC9;
    font-size: 1.65rem;
    font-weight: 750;
}

.small-muted {
    color: #94A3B8;
    font-size: 0.9rem;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INCIDENTS_PATH = (
    os.path.join(BASE_DIR, "incidents.json")
    if os.path.exists(os.path.join(BASE_DIR, "incidents.json"))
    else os.path.join(BASE_DIR, "data/processed/dashboard/incidents.json")
)

CHAINS_PATH = (
    os.path.join(BASE_DIR, "reconstructed_attack_chains.json")
    if os.path.exists(os.path.join(BASE_DIR, "reconstructed_attack_chains.json"))
    else os.path.join(BASE_DIR, "data/processed/attack_chains_v4/reconstructed_attack_chains.json")
)


# ============================================================
# LOAD V4 DATA
# ============================================================

def load_incidents():

    if not os.path.exists(INCIDENTS_PATH):
        return []

    with open(INCIDENTS_PATH, "r") as f:
        return json.load(f)


def load_chains():

    if not os.path.exists(CHAINS_PATH):
        return []

    with open(CHAINS_PATH, "r") as f:
        return json.load(f)


incidents = load_incidents()
chains = load_chains()


# ============================================================
# BUILD DATAFRAME
# ============================================================

if incidents:
    df = pd.DataFrame(incidents)
else:
    df = pd.DataFrame()


# ============================================================
# DERIVE MITRE DATA DIRECTLY FROM V4 CHAINS
# ============================================================

def build_mitre_dataframe(incidents):

    rows = []

    for incident in incidents:

        techniques = incident.get("techniques", [])

        unique = list(dict.fromkeys(techniques))

        for technique in unique:

            occurrence_count = techniques.count(technique)

            rows.append({
                "chain_id": incident.get("chain_id"),
                "severity": incident.get("severity"),
                "technique": technique,
                "occurrences": occurrence_count,
                "num_events": incident.get("num_events", 0),
                "chain_confidence": incident.get(
                    "average_confidence", 0
                ),
                "host_count": len(
                    incident.get("hosts", [])
                ),
                "first_event": incident.get(
                    "first_event"
                ),
                "last_event": incident.get(
                    "last_event"
                )
            })

    return pd.DataFrame(rows)


mitre_df = build_mitre_dataframe(incidents)


# ============================================================
# TECHNIQUE STATISTICS
# ============================================================

if not mitre_df.empty:

    technique_summary = (
        mitre_df
        .groupby("technique")
        .agg(
            chains=("chain_id", "nunique"),
            total_occurrences=("occurrences", "sum"),
            average_confidence=("chain_confidence", "mean"),
            critical_chains=(
                "severity",
                lambda x: (x == "CRITICAL").sum()
            ),
            high_chains=(
                "severity",
                lambda x: (x == "HIGH").sum()
            )
        )
        .reset_index()
    )

    technique_summary["average_confidence"] = (
        technique_summary["average_confidence"].round(4)
    )

else:
    technique_summary = pd.DataFrame()


# ============================================================
# DETECTION GAP ANALYSIS

# TRUE detection gaps are calculated from the frozen GAT test
# confusion matrix:
#
#     miss_rate = FN / (TP + FN)
#
# This is the actual false-negative rate against ground truth.
TRUE_GAPS_PATH = os.path.join(
    BASE_DIR,
    "data/analysis/detection_gaps/true_detection_gaps.csv"
)

try:
    gaps_df = pd.read_csv(TRUE_GAPS_PATH)

    # Ensure numerical columns are numeric.
    for col in [
        "support",
        "true_positive",
        "false_positive",
        "false_negative",
        "true_negative",
        "precision",
        "recall",
        "f1",
        "detection_rate",
        "false_negative_rate",
        "miss_rate",
        "gap_score",
    ]:
        if col in gaps_df.columns:
            gaps_df[col] = pd.to_numeric(
                gaps_df[col],
                errors="coerce"
            ).fillna(0)

except Exception as e:
    gaps_df = pd.DataFrame()
    print(f"WARNING: Could not load true detection gaps: {e}")

# ============================================================
#
# IMPORTANT:
# We do NOT call this a model miss-rate unless ground truth
# labels are available.
#
# Instead this is a V4 chain-derived detection-gap indicator:
#
# - prevalence = how often technique occurs in reconstructed chains
# - low-confidence chains = chains where model confidence < 0.5
# - uncertainty rate = low-confidence / total chains
#
# This keeps the dashboard scientifically honest.
# ============================================================

def build_detection_gap_dataframe(mitre_df):

    if mitre_df.empty:
        return pd.DataFrame()

    grouped = (
        mitre_df
        .groupby("technique")
        .agg(
            total_chains=("chain_id", "nunique"),
            total_occurrences=("occurrences", "sum"),
            average_confidence=("chain_confidence", "mean"),
            low_confidence_chains=(
                "chain_confidence",
                lambda x: (x < 0.50).sum()
            ),
            critical_chains=(
                "severity",
                lambda x: (x == "CRITICAL").sum()
            ),
            high_chains=(
                "severity",
                lambda x: (x == "HIGH").sum()
            )
        )
        .reset_index()
    )

    grouped["uncertainty_rate"] = (
        grouped["low_confidence_chains"]
        / grouped["total_chains"]
    )

    grouped["uncertainty_rate"] = (
        grouped["uncertainty_rate"].round(4)
    )

    grouped["average_confidence"] = (
        grouped["average_confidence"].round(4)
    )

    # Detection-gap indicator:
    #
    # High value means:
    # - technique appears frequently
    # - confidence is relatively low
    #
    grouped["gap_score"] = (
        grouped["uncertainty_rate"]
        * (1 - grouped["average_confidence"])
    )

    grouped["gap_score"] = (
        grouped["gap_score"].round(4)
    )

    grouped = grouped.sort_values(
        "gap_score",
        ascending=False
    )

    return grouped


confidence_gap_df = build_detection_gap_dataframe(mitre_df)


# ============================================================
# HEADER
# ============================================================

st.title("⚡ SOCFusion: Advanced Agentic Threat Detection")

st.markdown(
    "### GAT V2 Graph-Based Attack Detection & V4 Graph-Constrained Reconstruction"
)

st.markdown(
    '<div class="small-muted">'
    'Dashboard source: GAT V2 predictions → V4 attack-chain reconstruction'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# TOP METRICS
# ============================================================

total_incidents = len(incidents)

critical_count = (
    sum(1 for x in incidents
        if x.get("severity") == "CRITICAL")
)

high_count = (
    sum(1 for x in incidents
        if x.get("severity") == "HIGH")
)

medium_count = (
    sum(1 for x in incidents
        if x.get("severity") == "MEDIUM")
)

low_count = (
    sum(1 for x in incidents
        if x.get("severity") == "LOW")
)

multi_technique_count = (
    sum(
        1 for x in incidents
        if x.get("num_unique_techniques", 0) >= 2
    )
)


col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f"""
        <div class="glass-card">
            <h4>Total Incidents</h4>
            <div class="metric-value">{total_incidents}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        f"""
        <div class="glass-card">
            <h4>Critical</h4>
            <div class="metric-value">{critical_count}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:
    st.markdown(
        f"""
        <div class="glass-card">
            <h4>High</h4>
            <div class="metric-value">{high_count}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col4:
    st.markdown(
        f"""
        <div class="glass-card">
            <h4>Multi-Technique Chains</h4>
            <div class="metric-value">{multi_technique_count}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# SEVERITY SUMMARY
# ============================================================

st.markdown("---")

s1, s2, s3, s4 = st.columns(4)

with s1:
    st.metric("🔴 Critical", critical_count)

with s2:
    st.metric("🟠 High", high_count)

with s3:
    st.metric("🟡 Medium", medium_count)

with s4:
    st.metric("🟢 Low", low_count)


# ============================================================
# TABS
# ============================================================

tab1, tab2, tab3 = st.tabs(
    [
        "🔗 Attack Chains",
        "🗺️ MITRE ATT&CK",
        "⚠️ Detection Gaps"
    ]
)


# ============================================================
# TAB 1 — ATTACK CHAINS
# ============================================================

with tab1:

    st.markdown(
        '<div class="section-title">'
        '🔗 GAT V2 Graph-Constrained Attack Chains'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        "Generated directly from GAT V2 event predictions and "
        "V4 graph-constrained attack-chain reconstruction."
    )

    if not df.empty:

        f1, f2 = st.columns(2)

        with f1:

            severity_options = [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ]

            selected_severity = st.multiselect(
                "Severity",
                severity_options,
                default=severity_options
            )

        with f2:

            max_unique = int(
                df["num_unique_techniques"].max()
            )

            min_unique = st.slider(
                "Minimum unique techniques",
                min_value=1,
                max_value=max_unique,
                value=1
            )

        filtered = df[
            df["severity"].isin(selected_severity)
            &
            (
                df["num_unique_techniques"]
                >= min_unique
            )
        ]

        st.write(
            f"Showing **{len(filtered):,}** "
            f"of **{len(df):,}** incidents"
        )

        display_columns = [
            "chain_id",
            "severity",
            "num_events",
            "num_unique_techniques",
            "technique_sequence",
            "average_confidence",
            "hosts"
        ]

        display_columns = [
            c for c in display_columns
            if c in filtered.columns
        ]

        st.dataframe(
            filtered[display_columns],
            use_container_width=True,
            height=500
        )

        st.markdown("---")

        # ====================================================
        # INCIDENT INVESTIGATION
        # ====================================================

        st.markdown(
            '<div class="section-title">'
            '🔍 Incident Investigation'
            '</div>',
            unsafe_allow_html=True
        )

        chain_ids = filtered["chain_id"].tolist()

        if chain_ids:

            selected_chain = st.selectbox(
                "Select an attack chain",
                chain_ids
            )

            incident = next(
                x for x in incidents
                if x.get("chain_id") == selected_chain
            )

            a, b, c = st.columns(3)

            with a:
                st.metric(
                    "Severity",
                    incident.get("severity", "UNKNOWN")
                )

                st.metric(
                    "Events",
                    incident.get("num_events", 0)
                )

            with b:
                st.metric(
                    "Unique Techniques",
                    incident.get(
                        "num_unique_techniques",
                        0
                    )
                )

                st.metric(
                    "Confidence",
                    f'{incident.get("average_confidence", 0) * 100:.2f}%'
                )

            with c:
                st.metric(
                    "First Event",
                    incident.get("first_event", "-")
                )

                st.metric(
                    "Last Event",
                    incident.get("last_event", "-")
                )

            st.markdown("### 📊 ATT&CK Chain Representation")
            st.markdown(
                '<div class="small-muted" style="margin-bottom: 14px;">'
                'Detailed chain preserves every correlated event for forensic traceability. '
                'The simplified ATT&CK narrative removes repeated technique IDs while preserving their first-seen chronological order.'
                '</div>',
                unsafe_allow_html=True
            )

            st.markdown("#### DETAILED EVENT CHAIN")
            st.caption("Shows every event/technique for forensic investigation.")
            detailed_seq = (
                incident.get("original_event_chain")
                or incident.get("technique_sequence")
                or "N/A"
            )
            st.code(detailed_seq)

            st.markdown("#### SIMPLIFIED ATT&CK NARRATIVE")
            st.caption("Shows the unique technique progression in first-seen chronological order.")
            simplified_list = incident.get("simplified_techniques")
            if not simplified_list:
                raw_techs = incident.get("techniques", [])
                simplified_list = simplify_technique_chain(raw_techs)

            simplified_seq = " -> ".join(simplified_list) if simplified_list else "N/A"
            st.code(simplified_seq)

            # --------------------------------------------------------
            # Step-by-step MITRE narrative explanation
            # --------------------------------------------------------
            st.markdown("### 🔎 Step-by-Step ATT&CK Narrative Explanation")
            if simplified_list:
                st.caption(
                    "Detailed descriptive breakdown of each unique technique in this attack progression:"
                )

                for step_no, technique in enumerate(simplified_list, start=1):
                    technique = str(technique).strip()

                    name, explanation = MITRE_EXPLANATIONS.get(
                        technique,
                        (
                            "MITRE ATT&CK technique",
                            "This technique is present in the reconstructed "
                            "attack chain, but a local explanation has not "
                            "been configured yet."
                        )
                    )

                    with st.expander(
                        f"Step {step_no}: {technique} — {name}",
                        expanded=(step_no == 1)
                    ):
                        st.markdown(f"**What it means:** {explanation}")
                        st.markdown(f"**Technique ID:** `{technique}`")
                        st.markdown(
                            "**Role in this narrative:** Represents the first occurrence "
                            "of this technique in the reconstructed attack progression."
                        )
            else:
                st.info("No technique sequence is available for this chain.")

            st.markdown("### 🖥️ Affected Hosts")
            hosts_list = incident.get("hosts", [])
            if hosts_list:
                for h in hosts_list:
                    st.markdown(f"- **`{h}`**")
            else:
                st.info("No host information available.")

            st.markdown("### 👤 User Accounts")
            users_list = incident.get("users", [])
            if users_list:
                for u in users_list:
                    st.markdown(f"- **`{u}`**")
            else:
                st.info("No user information available.")

            st.markdown("### ⚙️ Involved Processes")
            procs_list = incident.get("processes", [])
            if procs_list:
                for p in procs_list:
                    st.markdown(f"- `{p}`")
            else:
                st.info("No process information available.")


# ============================================================
# TAB 2 — MITRE ATT&CK
# ============================================================

with tab2:

    st.markdown(
        '<div class="section-title">'
        '🗺️ GAT V2 MITRE ATT&CK Mapping'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        "MITRE ATT&CK techniques are derived directly from "
        "the techniques contained in the V4 reconstructed chains."
    )

    if not technique_summary.empty:

        st.info(
            "This view is chain-derived. "
            "It does not use the previous UUID-based MITRE mapping dataset."
        )

        st.markdown("### Technique Coverage")

        mitre_display = technique_summary.copy()

        mitre_display.columns = [
            "Technique",
            "Chains",
            "Occurrences",
            "Average Confidence",
            "Critical Chains",
            "High Chains"
        ]

        st.dataframe(
            mitre_display,
            use_container_width=True,
            height=450
        )

        st.markdown("### Technique Distribution")

        chart_df = technique_summary.sort_values(
            "chains",
            ascending=False
        )

        fig = px.bar(
            chart_df,
            x="technique",
            y="chains",
            title="Reconstructed Chains Containing Each MITRE Technique",
            labels={
                "technique": "MITRE Technique",
                "chains": "Number of Chains"
            },
            template="plotly_dark"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        st.markdown("### Technique Confidence")

        confidence_fig = px.bar(
            technique_summary.sort_values(
                "average_confidence",
                ascending=False
            ),
            x="technique",
            y="average_confidence",
            title="Average GAT Confidence by MITRE Technique",
            labels={
                "technique": "MITRE Technique",
                "average_confidence": "Average Confidence"
            },
            template="plotly_dark"
        )

        confidence_fig.update_yaxes(
            range=[0, 1]
        )

        st.plotly_chart(
            confidence_fig,
            use_container_width=True
        )

    else:

        st.warning(
            "No MITRE technique data found in V4 incidents."
        )


# ============================================================
# TAB 3 — DETECTION GAPS
# ============================================================

with tab3:
    st.markdown("### ⚠️ True Detection Gap Analysis")

    if not gaps_df.empty:

        st.info(
            "Detection gap is calculated from GAT test-set ground truth "
            "using the false-negative rate: "
            "FN / (TP + FN). It is not based on prediction confidence."
        )

        # --------------------------------------------------------
        # Summary metrics
        # --------------------------------------------------------

        total_techniques = len(gaps_df)

        critical_count = int(
            (gaps_df["priority"] == "CRITICAL").sum()
        )

        high_count = int(
            (gaps_df["priority"] == "HIGH").sum()
        )

        medium_count = int(
            (gaps_df["priority"] == "MEDIUM").sum()
        )

        low_count = int(
            (gaps_df["priority"] == "LOW").sum()
        )

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.metric(
                "Techniques Evaluated",
                total_techniques
            )

        with c2:
            st.metric(
                "Critical Gaps",
                critical_count
            )

        with c3:
            st.metric(
                "High Gaps",
                high_count
            )

        with c4:
            st.metric(
                "No/Low Gap",
                low_count
            )

        st.markdown("---")

        # --------------------------------------------------------
        # Detection-gap ranking
        # --------------------------------------------------------

        st.markdown("### 🚨 Detection Gap Ranking")

        display_df = gaps_df[
            [
                "technique",
                "support",
                "true_positive",
                "false_negative",
                "recall",
                "miss_rate",
                "f1",
                "priority",
            ]
        ].copy()

        display_df["recall"] = (
            display_df["recall"] * 100
        ).round(2)

        display_df["miss_rate"] = (
            display_df["miss_rate"] * 100
        ).round(2)

        display_df["f1"] = (
            display_df["f1"] * 100
        ).round(2)

        display_df = display_df.rename(
            columns={
                "technique": "MITRE Technique",
                "support": "Ground Truth Events",
                "true_positive": "Detected (TP)",
                "false_negative": "Missed (FN)",
                "recall": "Detection Rate (%)",
                "miss_rate": "Miss Rate (%)",
                "f1": "F1 (%)",
                "priority": "Priority",
            }
        )

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

        # --------------------------------------------------------
        # Main chart
        # --------------------------------------------------------

        st.markdown("### 📉 Technique Miss Rate")

        chart_df = gaps_df[
            [
                "technique",
                "miss_rate",
                "priority"
            ]
        ].copy()

        chart_df["miss_rate_percent"] = (
            chart_df["miss_rate"] * 100
        )

        chart_df = chart_df.sort_values(
            "miss_rate_percent",
            ascending=True
        )

        fig_gap = px.bar(
            chart_df,
            x="miss_rate_percent",
            y="technique",
            orientation="h",
            text="miss_rate_percent",
            title="False-Negative Rate by MITRE ATT&CK Technique",
            labels={
                "miss_rate_percent": "Miss Rate (%)",
                "technique": "MITRE Technique"
            },
            template="plotly_dark"
        )

        fig_gap.update_traces(
            texttemplate="%{text:.2f}%",
            textposition="outside"
        )

        fig_gap.update_xaxes(
            range=[0, 105]
        )

        st.plotly_chart(
            fig_gap,
            use_container_width=True
        )

        # --------------------------------------------------------
        # Explain the biggest gaps
        # --------------------------------------------------------

        st.markdown("### 🔎 Highest-Priority Detection Gaps")

        top_gaps = gaps_df.head(5)

        for _, row in top_gaps.iterrows():

            technique = row["technique"]
            miss = row["miss_rate"] * 100
            fn = int(row["false_negative"])
            support = int(row["support"])
            priority = row["priority"]

            st.markdown(
                f"**{technique} — {priority}**"
                f"Missed **{fn:,} of {support:,}** ground-truth "
                f"events (**{miss:.2f}% miss rate**)."
            )

    else:
        st.warning(
            "No true detection-gap data found."
        )

st.markdown("---")

st.markdown(
    """
    <p style='text-align:center;color:#00CEC9;'>
        SOCFusion | GAT V2 | V4 Graph-Constrained Attack Reconstruction
    </p>
    """,
    unsafe_allow_html=True
)

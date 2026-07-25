"""Minimal Streamlit UI for GuardScan."""

from __future__ import annotations

from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from src.scanner import scan_source

load_dotenv()

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"

st.set_page_config(page_title="GuardScan", layout="wide")
st.title("GuardScan")
st.caption(
    "Deterministic Solidity detectors + grounded LLM explanations. "
    "The LLM explains only detector findings — it does not invent new issues."
)

example = st.selectbox(
    "Load fixture (optional)",
    ["(none)", "VulnerableVault.sol", "VulnerableAMM.sol", "SaferAMM.sol"],
)
initial = ""
if example != "(none)":
    initial = (FIXTURES / example).read_text(encoding="utf-8")

source = st.text_area("Solidity source", value=initial, height=360)
col1, col2 = st.columns(2)
with col1:
    explain = st.checkbox("Include grounded explanation", value=True)
with col2:
    mock_llm = st.checkbox("Force mock LLM (no API call)", value=False)

if st.button("Scan", type="primary"):
    if not source.strip():
        st.warning("Paste Solidity source or load a fixture.")
    else:
        report = scan_source(
            source,
            file_label=example if example != "(none)" else "<paste>",
            explain=explain,
            use_mock_llm=True if mock_llm else None,
        )
        st.subheader(f"Findings ({report['finding_count']})")
        if report["finding_count"] == 0:
            st.success("No detector findings. GuardScan will not invent vulnerabilities.")
        else:
            for finding in report["findings"]:
                st.markdown(
                    f"**[{finding['severity']}] {finding['title']}**  \n"
                    f"Line {finding['line']} · detector `{finding['detector']}`  \n"
                    f"Evidence: `{finding['evidence']}`  \n"
                    f"Recommendation: {finding['recommendation']}"
                )
                st.divider()

        if explain and "explanation" in report:
            st.subheader("Grounded explanation")
            st.info(f"LLM mode: `{report['explanation'].get('llm_mode')}`")
            st.write(report["explanation"].get("summary", ""))

        with st.expander("Raw JSON report"):
            st.json(report)

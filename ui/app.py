"""Minimal Streamlit UI for GuardScan."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
# Streamlit puts this script's folder on sys.path, not the repo root.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.scanner import scan_source  # noqa: E402

load_dotenv()

FIXTURES = ROOT / "fixtures"

st.set_page_config(page_title="GuardScan", layout="wide")
st.title("GuardScan")
st.caption(
    "Deterministic Solidity detectors + grounded LLM explanations. "
    "The LLM explains only detector findings — it does not invent new issues."
)

EXAMPLE_CONTRACTS: dict[str, str | None] = {
    "Paste my own code": None,
    "Vulnerable vault — unsafe withdrawals & ownership": "VulnerableVault.sol",
    "Vulnerable AMM — unsafe token swap": "VulnerableAMM.sol",
    "Hardened AMM — same swap, issues fixed": "SaferAMM.sol",
}

choice = st.selectbox(
    "Start from an example contract",
    list(EXAMPLE_CONTRACTS),
    help="Loads a sample Solidity contract below. Choose 'Paste my own code' to scan your own.",
)
example = EXAMPLE_CONTRACTS[choice]
initial = (FIXTURES / example).read_text(encoding="utf-8") if example else ""

source = st.text_area("Solidity source", value=initial, height=360)
col1, col2 = st.columns(2)
with col1:
    explain = st.checkbox("Include grounded explanation", value=True)
with col2:
    mock_llm = st.checkbox("Force mock LLM (no API call)", value=False)

if st.button("Scan", type="primary"):
    if not source.strip():
        st.warning("Paste Solidity source or pick an example contract.")
    else:
        report = scan_source(
            source,
            file_label=example or "<pasted source>",
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

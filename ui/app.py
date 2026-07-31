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

from src.detectors import DETECTORS  # noqa: E402
from src.scanner import scan_source  # noqa: E402

load_dotenv()

FIXTURES = ROOT / "fixtures"
DETECTOR_COUNT = len(DETECTORS)

st.set_page_config(page_title="GuardScan", layout="wide")
st.title("GuardScan")
st.caption(
    f"{DETECTOR_COUNT} deterministic Solidity detectors, with grounded AI explanations. "
    "The model explains only what the detectors report — it does not invent new issues, "
    "and issues outside these detectors are not checked."
)

EXAMPLE_CONTRACTS: dict[str, str | None] = {
    "Paste my own code": None,
    "Vulnerable vault — unsafe withdrawals & ownership": "VulnerableVault.sol",
    "Vulnerable AMM — unsafe token swap": "VulnerableAMM.sol",
    "Hardened AMM — same swap, flagged issues fixed": "SaferAMM.sol",
}

choice = st.selectbox(
    "Start from an example contract",
    list(EXAMPLE_CONTRACTS),
    help="Loads a sample Solidity contract below. Choose 'Paste my own code' to scan your own.",
)
example = EXAMPLE_CONTRACTS[choice]
initial = (FIXTURES / example).read_text(encoding="utf-8") if example else ""

source = st.text_area("Solidity source", value=initial, height=360)

explain = st.toggle(
    "Explain findings with AI",
    value=True,
    help="The AI never finds issues on its own — it only explains what the detectors report.",
)
st.caption(
    "On: each finding is sent to a language model for plain-English risk and fix guidance "
    "(takes a few seconds). Off: the same detector findings, with no explanation layer."
    if explain
    else "Off: raw detector findings only, instantly. Turn this on to have a language model "
    "explain the same findings — it cannot add new ones."
)

if st.button("Scan", type="primary"):
    if not source.strip():
        st.warning("Paste Solidity source or pick an example contract.")
    else:
        report = scan_source(
            source,
            file_label=example or "<pasted source>",
            explain=explain,
        )
        explanation = report.get("explanation") or {}
        # Template mode attaches per-finding text; AI mode returns one combined narrative.
        per_finding = {
            f["id"]: f["explanation"]
            for f in explanation.get("findings", [])
            if f.get("explanation")
        }

        st.subheader(f"Findings ({report['finding_count']})")
        if report["finding_count"] == 0:
            st.info(
                f"**Nothing matched GuardScan's {DETECTOR_COUNT} detectors.** "
                "That means none of the specific patterns it checks for are present — "
                "it is not a proof that this contract is safe. Bug classes outside those "
                "detectors are not examined, and GuardScan never invents findings to fill the gap."
            )
        else:
            for finding in report["findings"]:
                st.markdown(
                    f"**[{finding['severity']}] {finding['title']}**  \n"
                    f"Line {finding['line']} · detector `{finding['detector']}`  \n"
                    f"Evidence: `{finding['evidence']}`  \n"
                    f"Recommendation: {finding['recommendation']}"
                )
                if finding["id"] in per_finding:
                    st.info(per_finding[finding["id"]])
                st.divider()

        mode = explanation.get("explanation_mode")
        # With zero findings there is nothing to explain; the success note above says it all.
        if explain and mode and mode != "none":
            if mode == "template":
                st.subheader("Template explanation")
                st.warning(
                    f"AI explanation unavailable ({explanation.get('template_reason')}). "
                    "Showing built-in template text instead — the findings above are unchanged."
                )
            else:
                st.subheader("AI explanation")
                if explanation.get("model"):
                    st.caption(f"Model: `{explanation['model']}`")
                st.write(explanation.get("summary", ""))

        with st.expander("Raw JSON report"):
            st.json(report)

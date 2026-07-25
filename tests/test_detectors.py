from pathlib import Path

from src.detectors import run_detectors

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_vulnerable_vault_has_critical_findings():
    source = (FIXTURES / "VulnerableVault.sol").read_text(encoding="utf-8")
    findings = run_detectors(source)
    detectors = {f.detector for f in findings}
    assert "reentrancy" in detectors
    assert "tx_origin" in detectors
    assert "missing_access_control" in detectors
    assert any(f.severity == "Critical" for f in findings)


def test_vulnerable_amm_flags_slippage_and_erc20():
    source = (FIXTURES / "VulnerableAMM.sol").read_text(encoding="utf-8")
    findings = run_detectors(source)
    detectors = {f.detector for f in findings}
    assert "swap_slippage" in detectors
    assert "unsafe_erc20" in detectors
    assert "missing_access_control" in detectors


def test_safer_amm_has_fewer_high_severity_issues():
    source = (FIXTURES / "SaferAMM.sol").read_text(encoding="utf-8")
    findings = run_detectors(source)
    # SaferAMM should not trip swap slippage or missing access on setReserves
    detectors = {f.detector for f in findings}
    assert "swap_slippage" not in detectors
    assert "missing_access_control" not in detectors
    assert "reentrancy" not in detectors
    assert "tx_origin" not in detectors

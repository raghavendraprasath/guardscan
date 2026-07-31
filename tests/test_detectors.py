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


def test_flags_delegatecall_selfdestruct_and_block_randomness():
    source = """
    contract Broken {
        function execute(address target, bytes calldata data) external {
            (bool ok, ) = target.delegatecall(data);
            require(ok, "failed");
        }
        function shutdown() external {
            selfdestruct(payable(msg.sender));
        }
        function pick() external view returns (uint256) {
            return uint256(blockhash(block.number - 1)) % 10;
        }
    }
    """
    detectors = {f.detector for f in run_detectors(source)}
    assert "delegatecall" in detectors
    assert "unprotected_selfdestruct" in detectors
    assert "weak_randomness" in detectors


def test_access_control_catches_renamed_sensitive_function():
    """The same bug under a name outside SENSITIVE_FUNCS is still reported."""
    source = """
    contract Renamed {
        address public admin;
        function updateAdmin(address a) external { admin = a; }
    }
    """
    findings = run_detectors(source)
    assert any(f.detector == "missing_access_control" for f in findings)


def test_guarded_functions_are_not_flagged():
    """onlyX modifiers, inline sender checks, and view functions must stay quiet."""
    source = """
    contract Guarded {
        address public admin;
        modifier onlyAdmin() { require(msg.sender == admin, "no"); _; }
        function setFee(uint256 f) external onlyAdmin { fee = f; }
        function setRate(uint256 r) external { require(msg.sender == admin, "no"); rate = r; }
        function updateView() external view returns (uint256) { return fee; }
        function destroy() external onlyAdmin { selfdestruct(payable(admin)); }
        function deadline() external view returns (bool) { return block.timestamp > 100; }
    }
    """
    assert run_detectors(source) == []


def test_safer_amm_has_fewer_high_severity_issues():
    source = (FIXTURES / "SaferAMM.sol").read_text(encoding="utf-8")
    findings = run_detectors(source)
    # SaferAMM should not trip swap slippage or missing access on setReserves
    detectors = {f.detector for f in findings}
    assert "swap_slippage" not in detectors
    assert "missing_access_control" not in detectors
    assert "reentrancy" not in detectors
    assert "tx_origin" not in detectors

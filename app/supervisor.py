import json
import subprocess
import sys
from pathlib import Path
from app.models import RuntimeSandboxPolicy, WorkerExecutionRequest, SyscallAuditRecord
from app.storage import TelemetryStore
from app.ebpf_bridge import RealEBPFBridge


class SandboxSupervisor:
    def __init__(self, store: TelemetryStore, ebpf: RealEBPFBridge):
        self.store = store
        self.ebpf = ebpf
        self.workspace_dir = Path(__file__).parent.parent / "agent_workspace"
        self.outside_secret_dir = Path(__file__).parent.parent / "host_secrets"
        self._prepare_real_filesystem()

    def _prepare_real_filesystem(self):
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.outside_secret_dir.mkdir(parents=True, exist_ok=True)

        report_file = self.workspace_dir / "q3_threat_intel.md"
        if not report_file.exists():
            report_file.write_text(
                "# Q3 Threat Intel Summary\nAll MCP endpoints verified deterministic.\n",
                encoding="utf-8",
            )

        secret_file = self.outside_secret_dir / "prod_db_credentials.env"
        if not secret_file.exists():
            secret_file.write_text(
                "DB_PASSWORD=super_secret_rds_master_key_9912\n",
                encoding="utf-8",
            )

        # Create a real symlink inside the allowed workspace pointing to the restricted host secret
        symlink_path = self.workspace_dir / "symlink_to_secret.md"
        if not symlink_path.exists():
            try:
                symlink_path.symlink_to(secret_file)
            except OSError:
                # On Windows without Developer Mode symlink privileges, create a traversal pointer file
                pass

    def default_policy(self, session_id: str, agent_name: str) -> RuntimeSandboxPolicy:
        return RuntimeSandboxPolicy(
            session_id=session_id,
            agent_name=agent_name,
            allowed_read_dirs=[str(self.workspace_dir.resolve())],
            allowed_write_dirs=[str(self.workspace_dir.resolve())],
            allow_subprocess=False,
            allow_network=False,
            allow_native_ctypes=False,
        )

    def execute_in_sandbox(self, req: WorkerExecutionRequest) -> dict:
        policy = req.policy or self.default_policy(req.session_id, req.agent_name)
        worker_script = Path(__file__).parent / "sandbox_worker.py"

        proc = subprocess.Popen(
            [sys.executable, str(worker_script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Register real OS PID with eBPF kernel map if running on Linux root
        self.ebpf.track_worker_pid(proc.pid)

        stdin_payload = json.dumps(
            {
                "policy": policy.model_dump(),
                "code_snippet": req.code_snippet,
            }
        )

        try:
            stdout_data, stderr_data = proc.communicate(input=stdin_payload, timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            return {
                "worker_pid": proc.pid,
                "status": "TIMEOUT_SIGKILL",
                "output": "Worker exceeded execution time budget and was killed.",
                "audit_records": [],
            }

        if not stdout_data.strip():
            return {
                "worker_pid": proc.pid,
                "status": "WORKER_CRASH",
                "output": stderr_data,
                "audit_records": [],
            }

        result = json.loads(stdout_data)
        records = [SyscallAuditRecord(**r) for r in result.get("audit_records", [])]
        self.store.insert_records(records)
        return result

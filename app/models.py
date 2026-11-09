from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class RuntimeSandboxPolicy(BaseModel):
    session_id: str
    agent_name: str
    allowed_read_dirs: List[str]
    allowed_write_dirs: List[str] = Field(default_factory=list)
    allow_subprocess: bool = False
    allowed_executables: List[str] = Field(default_factory=list)
    allow_network: bool = False
    allowed_hosts: List[str] = Field(default_factory=list)
    allow_native_ctypes: bool = False


class WorkerExecutionRequest(BaseModel):
    session_id: str = "sess-prod-agent-01"
    agent_name: str = "mcp-filesystem-worker"
    code_snippet: str = Field(..., description="Real Python tool code to execute in isolated worker process")
    policy: Optional[RuntimeSandboxPolicy] = None


class SyscallAuditRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str
    session_id: str
    agent_name: str
    worker_pid: int
    event_name: str
    target: str
    canonical_target: str
    verdict: Literal["ALLOW", "BLOCK_EPERM"]
    reason: str

# Agent-Runtime-EDR (v2.0.0 — Production Enforcement Engine)

**Synchronous Pre-Syscall C-Runtime Interceptor (PEP 578), Symlink-Canonicalized File Sandbox & Linux eBPF Kernel Bridge for Autonomous AI Agents**

## Why This Is Real Enforcement (Zero Mocks, Zero TOCTOU)
1. **Synchronous Pre-Syscall Blocking (`sys.addaudithook`):** Hooks directly into the CPython C runtime before `open()`, `socket.connect()`, `os.system()`, `subprocess.Popen()`, or `ctypes.dlopen()` reaches the OS kernel. Raises `PermissionError (-EPERM)` in sub-microsecond time—zero asynchronous race conditions.
2. **Canonical Path & Symlink Resolution:** Resolves all file descriptors through `os.path.realpath()` prior to policy evaluation, neutralizing symlink traversal (`ln -s /etc/shadow ./allowed/doc.md`) and `../` path escapes.
3. **Real Worker Process Sandboxing:** Spawns actual OS worker subprocesses (`app/sandbox_worker.py`), injects the signed JSON Intent Policy, locks the C audit hook, executes the agent tool payload, and streams real syscall telemetry into a persistent **SQLite WAL database**.
4. **Real Linux eBPF BCC Ring-Buffer Poller (`app/ebpf_bridge.py`):** When run as `root` on Linux with `python3-bcc`, compiles `ebpf/agent_edr_kern.c` into BPF bytecode, writes the spawned worker `PID` (`ctypes.c_uint32`) into the `tracked_agent_pids` kernel hash map, and polls `BPF_PERF_OUTPUT(agent_events)` in a background daemon thread.

---

## Quickstart & Real Exploit Verification

```bash
cd agent-runtime-edr
pip install -r requirements.txt

# 1. Run the Real Automated Exploit & Security Test Suite (pytest)
pytest -v

# 2. Start the Production Control Plane & Live Execution Console
python -m app.main
# Open http://127.0.0.1:8080 to execute real sandboxed worker payloads
```

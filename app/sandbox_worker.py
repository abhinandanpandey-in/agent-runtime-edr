#!/usr/bin/env python3
"""
Isolated OS Worker Process with Synchronous PEP 578 C-Runtime Syscall Enforcement.
Invoked via subprocess by the supervisor. Locks sys.addaudithook() BEFORE executing agent tool code.
"""
import json
import os
import sys
import traceback
from datetime import datetime

SENSITIVE_PATTERNS = (
    "/etc/shadow",
    "/etc/passwd",
    ".aws/credentials",
    ".ssh/id_rsa",
    ".env",
    "sam",
    "ntds.dit",
)


def _normalize_dir(path_str: str) -> str:
    return os.path.normcase(os.path.realpath(path_str))


def main():
    raw_input = sys.stdin.read()
    payload = json.loads(raw_input)
    policy = payload["policy"]
    code_snippet = payload["code_snippet"]
    worker_pid = os.getpid()

    allowed_read_dirs = [_normalize_dir(p) for p in policy.get("allowed_read_dirs", [])]
    allowed_write_dirs = [_normalize_dir(p) for p in policy.get("allowed_write_dirs", [])]
    allow_subprocess = bool(policy.get("allow_subprocess", False))
    allowed_execs = [_normalize_dir(p) for p in policy.get("allowed_executables", [])]
    allow_network = bool(policy.get("allow_network", False))
    allowed_hosts = set(policy.get("allowed_hosts", []))
    allow_ctypes = bool(policy.get("allow_native_ctypes", False))

    audit_log = []
    enforcement_active = False

    def record_event(event_name: str, target: str, canonical: str, verdict: str, reason: str):
        audit_log.append(
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "session_id": policy["session_id"],
                "agent_name": policy["agent_name"],
                "worker_pid": worker_pid,
                "event_name": event_name,
                "target": target,
                "canonical_target": canonical,
                "verdict": verdict,
                "reason": reason,
            }
        )

    def _is_within(canonical_path: str, allowed_prefixes: list[str]) -> bool:
        for prefix in allowed_prefixes:
            if canonical_path == prefix or canonical_path.startswith(prefix + os.sep):
                return True
        return False

    def runtime_audit_hook(event: str, args: tuple):
        nonlocal enforcement_active
        if not enforcement_active:
            return

        # 1. File Descriptor Open Interception (with realpath symlink canonicalization)
        if event == "open":
            path_arg = args[0]
            mode_arg = str(args[1]) if len(args) > 1 else "r"
            if not isinstance(path_arg, (str, bytes, os.PathLike)):
                return
            raw_path = os.fsdecode(path_arg)
            # Ignore internal Python .pyc / encoding loads if needed, or enforce strictly:
            canonical = os.path.normcase(os.path.realpath(raw_path))

            # Check hardcoded high-value credential signatures
            low_raw = raw_path.replace("\\", "/").lower()
            low_can = canonical.replace("\\", "/").lower()
            for pat in SENSITIVE_PATTERNS:
                if pat in low_raw or pat in low_can:
                    record_event("open", raw_path, canonical, "BLOCK_EPERM", f"CREDENTIAL_GUARD ({pat})")
                    raise PermissionError(f"[Agent-EDR -EPERM] Credential access blocked: {raw_path} -> {canonical}")

            is_write = any(m in mode_arg for m in ("w", "a", "x", "+"))
            if is_write:
                if not _is_within(canonical, allowed_write_dirs):
                    record_event("open(write)", raw_path, canonical, "BLOCK_EPERM", "WRITE_SANDBOX_VIOLATION")
                    raise PermissionError(f"[Agent-EDR -EPERM] Unauthorized file write: {canonical}")
                record_event("open(write)", raw_path, canonical, "ALLOW", "WRITE_POLICY_COMPLIANT")
            else:
                if not _is_within(canonical, allowed_read_dirs) and not _is_within(canonical, allowed_write_dirs):
                    record_event("open(read)", raw_path, canonical, "BLOCK_EPERM", "READ_SANDBOX_ESCAPE_OR_SYMLINK")
                    raise PermissionError(f"[Agent-EDR -EPERM] Sandbox read escape blocked: {raw_path} -> {canonical}")
                record_event("open(read)", raw_path, canonical, "ALLOW", "READ_POLICY_COMPLIANT")

        # 2. Subprocess & Shell Spawn Interception
        elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn"):
            if event == "subprocess.Popen":
                executable = str(args[0])
                cmd_repr = str(args[1]) if len(args) > 1 else executable
            else:
                executable = str(args[0]) if args else event
                cmd_repr = executable
            canonical_exec = os.path.normcase(os.path.realpath(executable))
            if not allow_subprocess or (allowed_execs and canonical_exec not in allowed_execs):
                record_event(event, cmd_repr, canonical_exec, "BLOCK_EPERM", "UNAUTHORIZED_PROCESS_SPAWN")
                raise PermissionError(f"[Agent-EDR -EPERM] Process spawn blocked: {cmd_repr}")
            record_event(event, cmd_repr, canonical_exec, "ALLOW", "SUBPROCESS_ALLOWED")

        # 3. Network Socket Egress Interception
        elif event == "socket.connect":
            addr = args[1] if len(args) > 1 else ()
            host = str(addr[0]) if isinstance(addr, tuple) and len(addr) >= 1 else str(addr)
            target_repr = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) and len(addr) >= 2 else str(addr)
            if not allow_network or (allowed_hosts and host not in allowed_hosts):
                record_event("socket.connect", target_repr, host, "BLOCK_EPERM", "UNAUTHORIZED_SOCKET_EGRESS")
                raise PermissionError(f"[Agent-EDR -EPERM] Outbound socket blocked: {target_repr}")
            record_event("socket.connect", target_repr, host, "ALLOW", "NETWORK_EGRESS_ALLOWED")

        # 4. Native Shared Library / FFI Bypass Prevention
        elif event in ("ctypes.dlopen", "ctypes.dlsym"):
            lib_name = str(args[0]) if args else "native_lib"
            if not allow_ctypes:
                record_event(event, lib_name, lib_name, "BLOCK_EPERM", "FFI_BYPASS_ATTEMPT_BLOCKED")
                raise PermissionError(f"[Agent-EDR -EPERM] Native FFI load blocked: {lib_name}")

    # Pre-import socket & subprocess so standard library imports don't clutter user audit log
    import socket  # noqa: F401
    import subprocess  # noqa: F401
    import ctypes  # noqa: F401

    sys.addaudithook(runtime_audit_hook)
    enforcement_active = True

    exec_status = "SUCCESS"
    exec_output = ""
    try:
        local_ns = {"__builtins__": __builtins__, "os": os, "socket": socket, "subprocess": subprocess, "ctypes": ctypes}
        exec(compile(code_snippet, "<agent_tool_execution>", "exec"), local_ns, local_ns)
        exec_output = str(local_ns.get("RESULT", "Execution completed cleanly."))
    except PermissionError as pe:
        exec_status = "BLOCKED_EPERM"
        exec_output = str(pe)
    except Exception as exc:
        exec_status = "RUNTIME_ERROR"
        exec_output = f"{exc.__class__.__name__}: {exc}"
    finally:
        enforcement_active = False

    response = {
        "worker_pid": worker_pid,
        "status": exec_status,
        "output": exec_output,
        "audit_records": audit_log,
    }
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()


if __name__ == "__main__":
    main()

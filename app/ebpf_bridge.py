import ctypes
import os
import platform
import threading
from pathlib import Path
from datetime import datetime
from app.models import SyscallAuditRecord
from app.storage import TelemetryStore


class _KernelEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("target", ctypes.c_char * 256),
    ]


class RealEBPFBridge:
    """
    Compiles ebpf/agent_edr_kern.c using BCC when running on Linux as root,
    populates the BPF_HASH(tracked_agent_pids) map with real worker PIDs,
    and polls the kernel perf ring buffer in a background daemon thread.
    """
    def __init__(self, store: TelemetryStore):
        self.store = store
        self.os_name = platform.system()
        self.kernel = platform.release()
        self.bpf = None
        self.active = False
        self.mode = f"PEP578_CRUNTIME_ENFORCER ({self.os_name} {self.kernel})"
        self._try_attach_kernel_probes()

    def _try_attach_kernel_probes(self):
        if self.os_name != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            return
        try:
            from bcc import BPF
            c_path = Path(__file__).parent.parent / "ebpf" / "agent_edr_kern.c"
            self.bpf = BPF(src_file=str(c_path))
            self.bpf["agent_events"].open_perf_buffer(self._handle_perf_event)
            t = threading.Thread(target=self._poll_loop, daemon=True)
            t.start()
            self.active = True
            self.mode = f"DUAL_KERNEL_EBPF_AND_PEP578 ({self.kernel})"
        except Exception as exc:
            self.mode = f"PEP578_CRUNTIME_ENFORCER (eBPF unavailable: {exc.__class__.__name__})"

    def track_worker_pid(self, pid: int):
        if self.active and self.bpf is not None:
            try:
                pid_map = self.bpf["tracked_agent_pids"]
                pid_map[ctypes.c_uint32(pid)] = ctypes.c_uint32(1)
            except Exception:
                pass

    def _handle_perf_event(self, cpu, data, size):
        evt = ctypes.cast(data, ctypes.POINTER(_KernelEvent)).contents
        syscall_name = "kernel:sys_enter_execve" if evt.event_type == 1 else "kernel:sys_enter_openat"
        target_str = evt.target.decode("utf-8", errors="replace")
        rec = SyscallAuditRecord(
            timestamp=datetime.utcnow().isoformat() + "Z",
            session_id="ebpf-kernel-trace",
            agent_name=evt.comm.decode("utf-8", errors="replace"),
            worker_pid=evt.pid,
            event_name=syscall_name,
            target=target_str,
            canonical_target=target_str,
            verdict="ALLOW",
            reason="KERNEL_RINGBUF_TELEMETRY",
        )
        self.store.insert_records([rec])

    def _poll_loop(self):
        while self.active and self.bpf is not None:
            try:
                self.bpf.perf_buffer_poll(timeout=200)
            except Exception:
                break

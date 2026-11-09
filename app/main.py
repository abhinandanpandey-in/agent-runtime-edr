from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path
from app.models import WorkerExecutionRequest
from app.storage import TelemetryStore
from app.ebpf_bridge import RealEBPFBridge
from app.supervisor import SandboxSupervisor
import uvicorn

app = FastAPI(
    title="Agent-Runtime-EDR Production Control Plane",
    version="2.0.0",
)

store = TelemetryStore()
ebpf = RealEBPFBridge(store)
supervisor = SandboxSupervisor(store, ebpf)


@app.get("/", response_class=HTMLResponse)
async def index():
    html_file = Path(__file__).parent / "static" / "index.html"
    return html_file.read_text(encoding="utf-8")


@app.get("/v1/edr/telemetry")
async def get_telemetry():
    return {
        "engine_mode": ebpf.mode,
        "workspace_dir": str(supervisor.workspace_dir.resolve()),
        "metrics": store.metrics(),
        "records": store.recent_records(80),
    }


@app.post("/v1/edr/execute")
async def execute_worker(req: WorkerExecutionRequest):
    return supervisor.execute_in_sandbox(req)


@app.post("/v1/edr/clear")
async def clear_telemetry():
    store.clear()
    return {"status": "CLEARED"}


if __name__ == "__main__":
    print("[*] Starting Production Agent-Runtime-EDR on http://127.0.0.1:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)

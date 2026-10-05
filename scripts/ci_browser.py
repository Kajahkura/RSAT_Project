"""Make browser failure diagnostics visible in GitHub check annotations."""

import runpy
import traceback

try:
    runpy.run_path("scripts/web_smoke.py", run_name="__main__")
except Exception:
    message = traceback.format_exc()[-6000:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error::" + message, flush=True)
    raise

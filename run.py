"""
ciphernet PQC Scanner — Startup Script
Run this file to launch the server: python run.py
"""

import sys
import os
import subprocess


def main():
    host = os.environ.get("CIPHNET_HOST", "127.0.0.1")
    port = int(os.environ.get("CIPHNET_PORT", "8000"))
    reload_flag = "--reload" if os.environ.get("CIPHNET_DEV") else ""

    # Ensure we're in the project root so imports work
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    print(f"\n{'═' * 52}")
    print(f"  ciphernet PQC Scanner")
    print(f"  Server: http://{host}:{port}")
    print(f"  Mode:   {'Development' if reload_flag else 'Production'}")
    print(f"{'═' * 52}\n")

    cmd = [
        sys.executable, "-m", "uvicorn",
        "backend.app.main:app",
        "--host", host,
        "--port", str(port),
    ]
    if reload_flag:
        cmd.append("--reload")

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n[ciphernet] Server stopped.")
    except FileNotFoundError:
        print("[ERROR] uvicorn not found. Install: pip install uvicorn[standard]")
        sys.exit(1)


if __name__ == "__main__":
    main()

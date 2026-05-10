import subprocess
import time
import webbrowser
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

print(f"[INFO] ROOT = {ROOT}")

os.chdir(ROOT)

print("[INFO] Launching server.py ...")

server = subprocess.Popen(
    [sys.executable, "server.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

time.sleep(2)

running = server.poll() is None

print(f"[INFO] Server running: {running}")

if not running:
    stdout, stderr = server.communicate()

    print("\n===== SERVER STDOUT =====")
    print(stdout)

    print("\n===== SERVER STDERR =====")
    print(stderr)

else:
    print("[INFO] Server started successfully")
    webbrowser.open(
        "file://" + os.path.join(ROOT, "index.html")
    )

input("\nPress Enter to exit...")
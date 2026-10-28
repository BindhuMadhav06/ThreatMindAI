import os
import subprocess
import sys
import time

def find_neo4j_dir():
    base_dir = os.path.join(os.path.dirname(__file__), "..", "neo4j-server")
    if not os.path.exists(base_dir):
        return None
    for item in os.listdir(base_dir):
        candidate = os.path.join(base_dir, item)
        if os.path.isdir(candidate) and os.path.exists(os.path.join(candidate, "bin")):
            return candidate
    return None

def set_neo4j_password(neo4j_dir):
    admin_cmd = os.path.join(neo4j_dir, "bin", "neo4j-admin.bat")
    if os.path.exists(admin_cmd):
        print("Setting initial Neo4j password to 'password'...")
        try:
            subprocess.run(
                [admin_cmd, "dbms", "set-initial-password", "password"],
                capture_output=True,
                text=True,
                check=False
            )
        except Exception as e:
            print(f"Password setting note: {e}")

def start_neo4j():
    neo4j_dir = find_neo4j_dir()
    if not neo4j_dir:
        print("Neo4j directory not found in neo4j-server/")
        return

    set_neo4j_password(neo4j_dir)

    console_cmd = os.path.join(neo4j_dir, "bin", "neo4jConsole.cmd")
    if not os.path.exists(console_cmd):
        console_cmd = os.path.join(neo4j_dir, "bin", "neo4j.bat")

    print(f"Launching Neo4j server from {console_cmd}...")
    proc = subprocess.Popen([console_cmd, "console"], cwd=neo4j_dir)
    print(f"Neo4j process started with PID {proc.pid}.")
    return proc

if __name__ == "__main__":
    start_neo4j()

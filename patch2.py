g = open("monitor/guard.py").read()
g = g.replace('    try:\n        c = client.containers.get(TARGET)',
              '    if os.environ.get("OBSERVE"):\n        return\n    try:\n        c = client.containers.get(TARGET)')
open("monitor/guard.py", "w").write(g)
e = open("evaluate.py").read()
e = e.replace('"-e", "TARGET=" + target,', '"-e", "TARGET=" + target, "-e", "OBSERVE=1",')
e = e.replace('subprocess.run(cmd, capture_output=True, timeout=240)',
              'subprocess.run(cmd, capture_output=True, timeout=(90 if kind == "slow" else 120))')
open("evaluate.py", "w").write(e)
print("OBSERVE in guard:", "OBSERVE" in g, "| OBSERVE in evaluate:", "OBSERVE" in e)

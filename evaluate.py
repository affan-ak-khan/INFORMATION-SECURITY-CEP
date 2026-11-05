import csv, os, shutil, subprocess, time

ROOT = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.join(ROOT, "logs", "eval")
TRIALS = {"fast": 5, "slow": 3, "gzip": 5}
MALICIOUS = {"fast", "slow"}

def sh(*args):
    return subprocess.run(list(args), capture_output=True, text=True)

def reset():
    sh("docker", "rm", "-f", "monitor", "attacker1", "legit")
    sh("docker", "volume", "rm", "victim_data")
    sh("docker", "volume", "create", "victim_data")
    sh("docker", "run", "--rm", "-v", "victim_data:/data", "attacker", "python", "seed.py")

def read(path):
    try:
        with open(path) as f:
            return list(csv.reader(f))
    except FileNotFoundError:
        return []

def analyze(logdir):
    ev = [(float(r[0]), r[1], float(r[2]), r[7]) for r in read(os.path.join(logdir, "events.csv"))]
    multi = next((i + 1 for i, e in enumerate(ev) if e[3] in ("LIKELY", "CONFIRMED")), None)
    kill = next((i + 1 for i, e in enumerate(ev) if e[3] == "CONFIRMED"), None)
    only = None
    for j, e in enumerate(ev):
        n = sum(1 for x in ev[: j + 1] if x[2] > 7.5 and e[0] - x[0] <= 5)
        if n >= 5:
            only = j + 1
            break
    return {"files": len(ev), "multi": multi, "kill": kill, "only": only}

def run_trial(kind, i):
    logdir = os.path.join(EVAL, "%s_%d" % (kind, i))
    shutil.rmtree(logdir, ignore_errors=True)
    os.makedirs(logdir)
    reset()
    target = "legit" if kind == "gzip" else "attacker1"
    sh("docker", "run", "-d", "--name", "monitor", "-v", "victim_data:/data",
       "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", logdir + ":/logs",
       "-e", "TARGET=" + target, "-e", "OBSERVE=1", "monitor", "python", "guard.py")
    time.sleep(4)
    if kind == "fast":
        cmd = ["docker", "run", "--rm", "--name", "attacker1", "-e", "FILE_DELAY=0.5",
               "-v", "victim_data:/data", "attacker", "python", "fast_attacker.py"]
    elif kind == "slow":
        cmd = ["docker", "run", "--rm", "--name", "attacker1",
               "-v", "victim_data:/data", "attacker", "python", "slow_attacker.py"]
    else:
        cmd = ["docker", "run", "--rm", "--name", "legit", "-v", "victim_data:/data",
               "alpine", "sh", "-c", "for f in /data/doc*.txt; do gzip -k $f; done"]
    try:
        subprocess.run(cmd, capture_output=True, timeout=(90 if kind == "slow" else 120))
    except subprocess.TimeoutExpired:
        sh("docker", "rm", "-f", target)
    time.sleep(20)
    sh("docker", "rm", "-f", "monitor")
    return analyze(logdir)

def fmt(x):
    return "-" if x is None else str(x)

def metrics(rows, key):
    mal = [r for r in rows if r["kind"] in MALICIOUS]
    ben = [r for r in rows if r["kind"] not in MALICIOUS]
    tp = sum(1 for r in mal if r[key] is not None)
    fn = len(mal) - tp
    fp = sum(1 for r in ben if r[key] is not None)
    tn = len(ben) - fp
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    lat = [r[key] for r in mal if r[key] is not None]
    avg = "%.1f" % (sum(lat) / len(lat)) if lat else "-"
    return tp, fn, fp, tn, prec, rec, avg

def main():
    os.makedirs(EVAL, exist_ok=True)
    rows = []
    for kind, n in TRIALS.items():
        for i in range(1, n + 1):
            r = run_trial(kind, i)
            r["kind"], r["i"] = kind, i
            rows.append(r)
            print("%-5s #%d  files_written=%-3s multi_detect_at=%-4s kill_at=%-4s entropy_only_at=%-4s" %
                  (kind, i, r["files"], fmt(r["multi"]), fmt(r["kill"]), fmt(r["only"])), flush=True)
    with open(os.path.join(EVAL, "results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "trial", "files_written", "multi_detect_at", "kill_at", "entropy_only_at"])
        for r in rows:
            w.writerow([r["kind"], r["i"], r["files"], fmt(r["multi"]), fmt(r["kill"]), fmt(r["only"])])
    print()
    print("| Detector | TP | FN | FP | TN | Precision | Recall | Avg files encrypted before detection |")
    print("|---|---|---|---|---|---|---|---|")
    for name, key in (("Entropy-only", "only"), ("Multi-signal", "multi")):
        tp, fn, fp, tn, p, rc, avg = metrics(rows, key)
        print("| %s | %d | %d | %d | %d | %.2f | %.2f | %s |" % (name, tp, fn, fp, tn, p, rc, avg))
    print()
    for kind, n in TRIALS.items():
        sub = [r for r in rows if r["kind"] == kind]
        print("%-5s: entropy-only flagged %d/%d, multi-signal flagged %d/%d" % (
            kind, sum(1 for r in sub if r["only"] is not None), n,
            sum(1 for r in sub if r["multi"] is not None), n))

main()

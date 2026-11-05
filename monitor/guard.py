import math, os, time, collections
import docker
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH = "/data"
TARGET = os.environ.get("TARGET", "attacker1")
W1, W2, W3 = 0.4, 0.3, 0.3
HIGH = 7.5
ORDER = ["normal", "SUSPICIOUS", "LIKELY", "CONFIRMED"]
client = docker.from_env()
events = collections.deque()
state = {"level": "normal", "likely": 0}
os.makedirs("/logs", exist_ok=True)
def log(name, row):
    with open("/logs/" + name, "a") as f:
        f.write(",".join(str(x) for x in row) + "\n")

def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(data).values())

def level(s):
    if s >= 0.9: return "CONFIRMED"
    if s >= 0.7: return "LIKELY"
    if s >= 0.5: return "SUSPICIOUS"
    return "normal"

def act(lvl):
    if ORDER.index(lvl) <= ORDER.index(state["level"]):
        return
    state["level"] = lvl
    log("actions.csv", [round(time.time(), 2), TARGET, lvl])
    if os.environ.get("OBSERVE"):
        return
    try:
        c = client.containers.get(TARGET)
        if lvl == "SUSPICIOUS":
            c.update(cpu_period=100000, cpu_quota=5000)
            print(">>> ACTION 1: throttled", TARGET, flush=True)
        elif lvl == "LIKELY":
            c.reload()
            for n in list(c.attrs["NetworkSettings"]["Networks"]):
                client.networks.get(n).disconnect(c)
            print(">>> ACTION 2: isolated from network", TARGET, flush=True)
        elif lvl == "CONFIRMED":
            img = c.commit(repository="forensic", tag=time.strftime("t%H%M%S"))
            c.kill()
            print(">>> ACTION 3: snapshot saved", img.tags, "and killed", TARGET, flush=True)
    except Exception as ex:
        print(">>> ACTION failed:", ex, flush=True)

class Handler(FileSystemEventHandler):
    def on_closed(self, event):
        if event.is_directory:
            return
        try:
            data = open(event.src_path, "rb").read()
        except Exception:
            return
        now = time.time()
        e = entropy(data)
        events.append((now, e, event.src_path.endswith(".locked")))
        while events and now - events[0][0] > 60:
            events.popleft()
        recent = list(events)
        ent_sig = sum(1 for t, x, l in recent if x > HIGH) / len(recent)
        io_sig = min(1.0, sum(1 for t, x, l in recent if now - t <= 10) / 10)
        ext_sig = min(1.0, sum(1 for t, x, l in recent if l) / 2)
        score = W1 * ent_sig + W2 * io_sig + W3 * ext_sig
        lvl = level(score)
        if ext_sig == 0 and lvl in ('LIKELY', 'CONFIRMED'):
            lvl = 'SUSPICIOUS'
        if lvl == "LIKELY":
            state["likely"] += 1
            if state["likely"] >= 3:
                lvl = "CONFIRMED"
        print(time.strftime("%H:%M:%S"), os.path.basename(event.src_path),
              "| score=%.2f %s" % (score, lvl), flush=True)
        log("events.csv", [round(now, 2), os.path.basename(event.src_path), round(e, 2), round(ent_sig, 2), round(io_sig, 2), round(ext_sig, 2), round(score, 2), lvl])
        act(lvl)

obs = Observer()
obs.schedule(Handler(), WATCH, recursive=False)
obs.start()
print("Guard watching /data, target =", TARGET, flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    obs.stop()
obs.join()


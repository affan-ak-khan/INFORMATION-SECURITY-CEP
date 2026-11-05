import math, os, time, collections
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH = "/data"
W1, W2, W3 = 0.4, 0.3, 0.3
HIGH = 7.5
events = collections.deque()

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
        fast = sum(1 for t, x, l in recent if now - t <= 5 and x > HIGH)
        eo = "ALERT" if fast >= 5 else "-"
        print(time.strftime("%H:%M:%S"), os.path.basename(event.src_path),
              "ent=%.2f" % e, "| E=%.2f IO=%.2f X=%.2f" % (ent_sig, io_sig, ext_sig),
              "| score=%.2f %s" % (score, level(score)), "| entropy-only:", eo, flush=True)

obs = Observer()
obs.schedule(Handler(), WATCH, recursive=False)
obs.start()
print("Engine watching /data ...", flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    obs.stop()
obs.join()

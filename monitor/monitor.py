import math, os, time, collections
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH = "/data"

def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(data).values())

class Handler(FileSystemEventHandler):
    def on_closed(self, event):
        if event.is_directory:
            return
        try:
            data = open(event.src_path, "rb").read()
        except Exception:
            return
        e = entropy(data)
        flag = "HIGH" if e > 7.5 else "ok"
        ext = " [.locked]" if event.src_path.endswith(".locked") else ""
        print(time.strftime("%H:%M:%S"), os.path.basename(event.src_path), "entropy=%.2f" % e, flag + ext, flush=True)

print("Baseline entropy of existing files:")
for f in sorted(os.listdir(WATCH)):
    print("  ", f, "%.2f" % entropy(open(os.path.join(WATCH, f), "rb").read()))

obs = Observer()
obs.schedule(Handler(), WATCH, recursive=False)
obs.start()
print("Watching /data ...", flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    obs.stop()
obs.join()

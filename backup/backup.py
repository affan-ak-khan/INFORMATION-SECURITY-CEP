import os, shutil, time
SRC, DST = "/data", "/backup"
INTERVAL = int(os.environ.get("INTERVAL", "30"))
while True:
    files = os.listdir(SRC)
    if any(f.endswith(".locked") for f in files):
        print("locked files present - backup skipped", flush=True)
    else:
        for f in files:
            shutil.copy2(os.path.join(SRC, f), os.path.join(DST, f))
        print(time.strftime("%H:%M:%S"), "backup done:", len(files), "files", flush=True)
    time.sleep(INTERVAL)

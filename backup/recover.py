import os, shutil
SRC, DST = "/backup", "/data"
for f in os.listdir(DST):
    if f.endswith(".locked"):
        os.remove(os.path.join(DST, f))
restored = 0
for f in os.listdir(SRC):
    p = os.path.join(DST, f)
    if not os.path.exists(p):
        shutil.copy2(os.path.join(SRC, f), p)
        restored += 1
print("restored", restored, "files")

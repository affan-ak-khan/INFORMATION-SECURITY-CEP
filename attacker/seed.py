import os, random
words = "the quick brown fox report invoice meeting config server log user data backup".split()
os.makedirs("/data", exist_ok=True)
for i in range(1, 21):
    text = " ".join(random.choice(words) for _ in range(8000))
    open(f"/data/doc{i}.txt", "w").write(text)
print("created 20 files")

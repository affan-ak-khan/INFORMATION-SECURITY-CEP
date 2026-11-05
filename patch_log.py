p = "monitor/guard.py"
s = open(p).read()
s = s.replace('state = {"level": "normal", "likely": 0}',
 'state = {"level": "normal", "likely": 0}\n'
 'os.makedirs("/logs", exist_ok=True)\n'
 'def log(name, row):\n'
 '    with open("/logs/" + name, "a") as f:\n'
 '        f.write(",".join(str(x) for x in row) + "\\n")')
s = s.replace('    state["level"] = lvl\n',
 '    state["level"] = lvl\n    log("actions.csv", [round(time.time(), 2), TARGET, lvl])\n')
s = s.replace('        act(lvl)\n',
 '        log("events.csv", [round(now, 2), os.path.basename(event.src_path), round(e, 2), round(ent_sig, 2), round(io_sig, 2), round(ext_sig, 2), round(score, 2), lvl])\n        act(lvl)\n')
open(p, "w").write(s)

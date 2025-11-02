# export_features_rizin.py
# pip install r2pipe
import r2pipe, json, sys

if len(sys.argv) < 2:
    print("Usage: python export_features_rizin.py <libfoo.so>")
    sys.exit(1)

path = sys.argv[1]
r2 = r2pipe.open(path, flags=["-2"])  # quiet
r2.cmd("aaa")
funcs = r2.cmdj("aflj") or []
items = []
strings = r2.cmdj("izj") or []

strs = [s.get("string") for s in strings if s.get("string")]

for f in funcs:
    addr = f.get("offset")
    name = f.get("name")
    size = f.get("size")
    pseudo = None
    try:
        pseudo = (r2.cmdj(f"pddj @{addr}") or {}).get("text")
    except Exception:
        try:
            pseudo = r2.cmd(f"pdc @{addr}")
        except Exception:
            pseudo = None
    items.append({
        "addr": hex(addr),
        "name": name,
        "size": size,
        "pseudocode": pseudo,
        "strings": strs[:50],
    })

print(json.dumps({"binary": path, "functions": items}, ensure_ascii=False, indent=2))

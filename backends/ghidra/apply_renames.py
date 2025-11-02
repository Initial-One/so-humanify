#@category so-humanify
# 从 renames.json 回写函数名与注释（Ghidra Jython 脚本）
import json
from ghidra.program.model.symbol import SourceType

path = askFile("Pick renames JSON", "Apply").getAbsolutePath()
with open(path, "r") as fp:
    data = json.load(fp)

fm = currentProgram.getFunctionManager()
for item in data.get("renames", []):
    try:
        addr = toAddr(item["addr"])
    except:
        print("skip addr", item.get("addr"))
        continue
    f = fm.getFunctionAt(addr)
    if not f:
        print("not found", addr)
        continue
    new = item.get("new_name")
    cmt = item.get("comment", "")
    try:
        if new and new != f.getName():
            f.setName(new, SourceType.USER_DEFINED)
        if cmt:
            f.setComment(cmt)
        print("OK", addr, new)
    except Exception as e:
        print("ERR", addr, e)

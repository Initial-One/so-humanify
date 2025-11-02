#@category so-humanify
#@menupath Tools.sohumanify.ExportFeatures
# 导出函数特征与伪代码（Ghidra Jython 脚本）
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_func(ifc, func, timeout_ms=60000):
    res = ifc.decompileFunction(func, timeout_ms, ConsoleTaskMonitor())
    if res and res.getDecompiledFunction():
        return res.getDecompiledFunction().getC()
    return None

def collect_strings(func):
    strings = set()
    listing = currentProgram.getListing()
    refs = getReferencesFrom(func.getBody())
    for ref in refs:
        to = ref.getToAddress()
        data = listing.getDataAt(to)
        if data and data.hasStringValue():
            try:
                strings.add(str(data.getDefaultValue()))
            except:
                pass
    return list(strings)[:50]

def get_called_funcs(func):
    called = []
    fm = currentProgram.getFunctionManager()
    xrefs = getReferencesFrom(func.getBody())
    for xr in xrefs:
        if xr.getReferenceType().isCall():
            f = fm.getFunctionAt(xr.getToAddress())
            if f: called.append(f.getEntryPoint().toString())
    return list(sorted(set(called)))

ifc = DecompInterface()
ifc.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
funcs = list(fm.getFunctions(True))

out = {"binary": currentProgram.getName(), "functions": []}
for f in funcs:
    if f.isExternal() or f.isThunk():
        continue
    item = {
        "addr": f.getEntryPoint().toString(),
        "name": f.getName(),
        "params": [p.getDataType().getDisplayName() for p in f.getParameters()],
        "ret": f.getReturnType().getDisplayName(),
        "size": f.getBody().getNumAddresses(),
        "called": get_called_funcs(f),
        "strings": collect_strings(f),
        "comment": f.getComment() or "",
        "pseudocode": None,
    }
    try:
        item["pseudocode"] = decompile_func(ifc, f)
    except:
        pass
    out["functions"].append(item)

path = askFile("Save features JSON", "Save").getAbsolutePath()
with open(path, "w") as fp:
    fp.write(json.dumps(out, ensure_ascii=False, indent=2))
print("Exported to", path)

# humanify/feature_pack.py
from __future__ import annotations
from typing import Dict, Any, List

def pack_functions_for_llm(functions: List[dict], max_strings: int = 20) -> List[dict]:
    out = []
    for f in functions:
        out.append({
            "addr": f.get("addr"),
            "name": f.get("name"),
            "params": f.get("params", []),
            "ret": f.get("ret", ""),
            "size": f.get("size", 0),
            "called": (f.get("called") or [])[:20],
            "strings": (f.get("strings") or [])[:max_strings],
            "pseudocode": (f.get("pseudocode") or "")[:4000],
        })
    return out

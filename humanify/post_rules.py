# humanify/post_rules.py
def resolve_conflicts(renames):
    seen = {}
    for r in renames:
        name = r.get("new_name")
        if not name: 
            continue
        if name in seen:
            k = seen[name] + 1
            seen[name] = k
            r["new_name"] = f"{name}_v{k}"
        else:
            seen[name] = 1
    return renames

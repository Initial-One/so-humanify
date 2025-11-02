# cli.py
from __future__ import annotations
import os, json, sys, time, pathlib
from typing import Optional, List
import typer
from rich import print
from rich.progress import track
import orjson as json_fast

app = typer.Typer(help="so-humanify: LLM 驱动的 Android .so 人性化还原 CLI")

def _read(path: str):
    with open(path, "rb") as f:
        return json_fast.loads(f.read())

def _write(path: str, data):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(json_fast.dumps(data, option=json_fast.OPT_INDENT_2))

@app.command()
def humanify(facts: str = typer.Argument(..., help="facts/*.json from exporter"),
             model: str = typer.Option("gpt-4o-mini", help="OpenAI-compatible model"),
             out: str = typer.Option("names/renames.json", help="output renames json"),
             max_concurrent: int = typer.Option(64, "--max-concurrent"),
             batch: int = typer.Option(12, "--batch"),
             base_url: Optional[str] = typer.Option(None, "--base-url", help="OpenAI-compatible base URL"),
             api_key: Optional[str] = typer.Option(None, "--api-key", help="API key (fallback to env OPENAI_API_KEY)")):
    """
    读取 features JSON -> 调用 LLM 生成命名建议 -> 输出 renames.json
    如果未配置 LLM，将使用离线启发式生成占位名称，便于流程调试。
    """
    data = _read(facts)
    funcs = data.get("functions", [])
    if not funcs:
        print("[red]No functions found in facts file.[/red]")
        raise typer.Exit(1)

    api_key = api_key or os.getenv("OPENAI_API_KEY")
    use_llm = bool(api_key)
    renames = []

    if use_llm:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
        except Exception as e:
            print(f"[yellow]OpenAI SDK init failed: {e} -> fallback to heuristic[/yellow]")
            use_llm = False

    def pack_fact(f):
        return {
            "addr": f.get("addr"),
            "name": f.get("name"),
            "params": f.get("params", []),
            "ret": f.get("ret", ""),
            "size": f.get("size", 0),
            "strings": (f.get("strings") or [])[:20],
            "called": (f.get("called") or [])[:20],
            "pseudocode": (f.get("pseudocode") or "")[:4000],
        }

    if use_llm:
        # simple batching
        prompt_header = pathlib.Path("humanify/llm_prompts/rename_template.md").read_text(encoding="utf-8")
        batch_items = []
        for f in funcs:
            batch_items.append(pack_fact(f))
            if len(batch_items) >= batch:
                renames += _call_llm(client, model, data.get("binary", "binary"), batch_items, prompt_header)
                batch_items = []
        if batch_items:
            renames += _call_llm(client, model, data.get("binary", "binary"), batch_items, prompt_header)
    else:
        # Heuristic fallback: create readable-but-generic names
        for i, f in enumerate(track(funcs, description="Heuristic naming…")):
            addr = f.get("addr")
            old = f.get("name") or ""
            new = old
            if old.startswith(("sub_", "fun_", "entry_", "unk_", "f_")) or len(old) < 3:
                new = f"func_{addr.replace('0x','')}"
            comment = "heuristic fallback name (no LLM)"
            renames.append({"addr": addr, "new_name": new, "comment": comment, "confidence": 0.35})

    out_data = {"binary": data.get("binary", "unknown"), "renames": renames}
    _write(out, out_data)
    print(f"[green]Wrote[/green] {out} with {len(renames)} items.")

def _call_llm(client, model: str, binary: str, facts_batch: list, prompt_header: str):
    import json as stdjson
    content_user = f"- Binary: {binary}\n- Function Facts (count={len(facts_batch)}):\n" + stdjson.dumps(facts_batch, ensure_ascii=False, indent=2)
    messages = [
        {"role": "system", "content": prompt_header},
        {"role": "user", "content": content_user},
    ]
    resp = client.chat.completions.create(model=model, messages=messages, temperature=0.2, response_format={"type": "json_object"})
    txt = resp.choices[0].message.content
    try:
        obj = stdjson.loads(txt)
        items = obj.get("renames") or obj.get("items") or []
        out = []
        for it in items:
            out.append({
                "addr": it.get("addr"),
                "new_name": it.get("new_name") or it.get("name"),
                "comment": it.get("comment", ""),
                "confidence": float(it.get("confidence", 0.6)),
            })
        return out
    except Exception as e:
        print(f"[yellow]LLM returned non-JSON; fallback parse: {e}[/yellow]")
        return []

@app.command()
def jni(frida: str = typer.Option(..., "--frida", help="RegisterNatives log file (json lines preferred)"),
        merge: str = typer.Option(..., "--merge", help="renames.json to merge into"),
        prefix: str = typer.Option("jni_", help="name prefix")):
    """
    合并 Frida RegisterNatives 映射进 renames.json。
    输入 frida 日志包含 {"type":"jni","name": "...","sig":"...","fn":"0x...","addr":"0x..."} 行。
    """
    rn = _read(merge)
    renames = rn.get("renames", [])
    addr2idx = {r["addr"]: i for i, r in enumerate(renames) if r.get("addr")}

    import json, re
    jni_lines = []
    with open(frida, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "jni":
                    addr = str(obj.get("addr") or obj.get("fn"))
                    if not addr.startswith("0x"):
                        try:
                            addr = hex(int(addr, 16))
                        except Exception:
                            continue
                    jni_lines.append({"addr": addr, "name": obj.get("name"), "sig": obj.get("sig")})
            except Exception:
                pass

    for it in jni_lines:
        addr = it["addr"]
        base = f"{prefix}{it['name']}"
        idx = addr2idx.get(addr)
        if idx is not None:
            renames[idx]["new_name"] = base
            renames[idx]["comment"] = (renames[idx].get("comment") or "") + f" | JNI {it['sig']}"
            renames[idx]["confidence"] = max(float(renames[idx].get("confidence", 0.6)), 0.9)
        else:
            renames.append({"addr": addr, "new_name": base, "comment": f"JNI {it['sig']}", "confidence": 0.9})

    rn["renames"] = renames
    _write(merge, rn)
    print(f"[green]Merged JNI mappings into[/green] {merge}")

@app.command()
def version():
    print("so-humanify 0.1.0")

if __name__ == "__main__":
    app()

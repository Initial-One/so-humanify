# so-humanify — LLM‑driven humanification for Android `.so` binaries

English · [简体中文](README_zh.md)

> Make stripped native code readable: export facts → LLM naming/comments → write back to Ghidra/IDA/rizin.

## Why this exists
Decompiled or stripped native libraries are hard to read. This project builds an end‑to‑end pipeline to extract facts (signatures, calls, strings, pseudocode), ask an LLM for semantic names/comments, and batch‑apply them back into your reverse‑engineering project.

## Features
- Feature export (Ghidra preferred, rizin/RetDec optional): signatures/arg counts, call graph, strings/constants, pseudocode.
- LLM semantic naming for functions/variables/structs, output as `renames.json` with confidence.
- One‑click apply back to Ghidra; IDA/rizin writers are pluggable.
- JNI‑aware: merge dynamic `RegisterNatives` logs (Frida) and static hints.
- Batch & concurrency with retries/caching (`--max-concurrent`, `--batch`).
- Evaluation hooks: readability heuristics, JNI match rate, low‑confidence review list.

## Pipeline
```
[ELF load] → [Disasm/Decompile backend] → [Facts JSON]
                          ↓
                   [LLM naming/comments]
                          ↓
        [Write back to Ghidra/IDA/rizin + side outputs]
                ↖—— [JNI dynamic/static hints] ——↗
```

## Layout
```
so-humanify/
  ├─ backends/
  │   ├─ ghidra/
  │   │   ├─ export_features.py
  │   │   └─ apply_renames.py
  │   ├─ rizin/
  │   │   └─ export_features_rizin.py
  │   └─ retdec/ (placeholder)
  ├─ humanify/
  │   ├─ llm_prompts/rename_template.md
  │   ├─ feature_pack.py
  │   ├─ llm_runner.py
  │   └─ post_rules.py
  ├─ bridge/
  │   ├─ jni_map_from_frida.js
  │   └─ jni_static_scanner.py (placeholder)
  ├─ cli.py
  ├─ pyproject.toml / requirements.txt
  └─ examples/libexample.so
```

## Requirements
- Python ≥ 3.9
- Ghidra ≥ 10.3 (headless `analyzeHeadless`)
- Optional: rizin/radare2 (`r2pipe`, pdd/pdc), RetDec, Frida
- LLM: OpenAI‑compatible API / local Ollama / others (`--model`, `--base-url`)

## Quickstart
1) Install deps
```bash
pip install -r requirements.txt
```

2) Export facts with Ghidra
```bash
GHIDRA="/Applications/ghidra*/support/analyzeHeadless"
PROJ=.work/foo_ghidra
OUT=facts/foo.json
mkdir -p "$(dirname "$OUT")"

"$GHIDRA" "$PROJ" foo_project   -import libfoo.so   -scriptPath backends/ghidra   -postScript export_features.py   -overwrite
```

3) Run LLM naming
```bash
export OPENAI_API_KEY=sk-xxx
python cli.py humanify facts/foo.json   --model gpt-4o-mini   --max-concurrent 100   --batch 12   --out names/foo.renames.json
```

4) Apply back to Ghidra
```bash
"$GHIDRA" "$PROJ" foo_project   -scriptPath backends/ghidra   -postScript apply_renames.py   -overwrite
```

5) (Optional) Merge JNI map
```bash
frida -U -f com.example.app -l bridge/jni_map_from_frida.js --no-pause > jni_map.log
python cli.py jni --frida jni_map.log --merge names/foo.renames.json
```

## Output examples
Facts (`facts/foo.json`) and rename results (`names/foo.renames.json`) follow the examples in the repo.

## Naming rules (default)
1. camelCase; verb‑object style (`parseVarInt`, `aesCbcDecrypt`).  
2. Optional module prefixes: `crypto_`, `http_`, `jni_`.  
3. Low confidence → comment only (don’t rename).  
4. Resolve conflicts with suffix (`_v2`) or module prefix.  
5. Cluster‑level consistency by call graph.

## Roadmap
- P‑code‑level fingerprints (TEA/XXHash/CRC/SHA/AES).  
- Type recovery & field naming.  
- IDA writer and `.idc` generator; rizin writer and `.r2` generator.  
- HTML evaluation report.  
- Integration with `jhumanify`.

## Legal
Reverse only on software you own or are authorized to analyze. LLM output is inferred and may not match original author intent.

## License
MIT. See `LICENSE`.

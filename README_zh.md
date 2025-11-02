# so-humanify —— LLM 驱动的 Android `.so` 人性化还原

[English](README.md) · 简体中文

> 让去符号的原生库更可读：导出事实 → LLM 语义命名/注释 → 回写 Ghidra/IDA/rizin。

## 为什么要做这个
被去符号或混淆的原生库难以阅读。本项目提供一条端到端流水线：导出函数/调用/字符串/伪代码等事实，用 LLM 生成语义化名称与注释，并把结果批量回写到你的逆向工程项目里。

## 功能
- 事实导出（优先 Ghidra，可选 rizin/RetDec）：签名/参数计数、调用关系、字符串/常量、伪代码。
- LLM 语义命名（函数/变量/结构体），输出 `renames.json`（含置信度）。
- 一键回写到 Ghidra；可扩展到 IDA/rizin。
- JNI 友好：合并动态 `RegisterNatives` 日志（Frida）与静态线索。
- 批处理与并发（重试/缓存），可调 `--max-concurrent`、`--batch`。
- 评估指标：可读性启发式、JNI 匹配率、低置信度清单。

## 流水线
```
[ELF 读取] → [反汇编/反编译后端] → [事实导出(JSON)]
                          ↓
                   [LLM 命名/注释]
                          ↓
      [回写到 Ghidra/IDA/rizin 工程 + 侧车产物]
                ↖—— [JNI 动态/静态线索] ——↗
```

## 目录结构
```
so-humanify/
  ├─ backends/
  │   ├─ ghidra/
  │   │   ├─ export_features.py
  │   │   └─ apply_renames.py
  │   ├─ rizin/
  │   │   └─ export_features_rizin.py
  │   └─ retdec/（占位）
  ├─ humanify/
  │   ├─ llm_prompts/rename_template.md
  │   ├─ feature_pack.py
  │   ├─ llm_runner.py
  │   └─ post_rules.py
  ├─ bridge/
  │   ├─ jni_map_from_frida.js
  │   └─ jni_static_scanner.py（占位）
  ├─ cli.py
  ├─ pyproject.toml / requirements.txt
  └─ examples/libexample.so
```

## 环境要求
- Python ≥ 3.9
- Ghidra ≥ 10.3（含 `analyzeHeadless`）
- 可选：rizin/radare2（`r2pipe`、pdd/pdc）、RetDec、Frida
- LLM：OpenAI 兼容 / 本地 Ollama / 其他（通过 `--model`、`--base-url` 指定）

## 快速上手
1）安装依赖
```bash
pip install -r requirements.txt
```

2）用 Ghidra 导出事实
```bash
GHIDRA="/Applications/ghidra*/support/analyzeHeadless"
PROJ=.work/foo_ghidra
OUT=facts/foo.json
mkdir -p "$(dirname "$OUT")"

"$GHIDRA" "$PROJ" foo_project   -import libfoo.so   -scriptPath backends/ghidra   -postScript export_features.py   -overwrite
```

3）运行 LLM 命名
```bash
export OPENAI_API_KEY=sk-xxx
python cli.py humanify facts/foo.json   --model gpt-4o-mini   --max-concurrent 100   --batch 12   --out names/foo.renames.json
```

4）回写到 Ghidra
```bash
"$GHIDRA" "$PROJ" foo_project   -scriptPath backends/ghidra   -postScript apply_renames.py   -overwrite
```

5）可选：合并 JNI 映射
```bash
frida -U -f com.example.app -l bridge/jni_map_from_frida.js --no-pause > jni_map.log
python cli.py jni --frida jni_map.log --merge names/foo.renames.json
```

## 输出格式
示例见 `facts/foo.json` 与 `names/foo.renames.json`。

## 命名规则（默认）
1. 驼峰，动宾短语优先。  
2. 可选模块前缀：`crypto_`、`http_`、`jni_`。  
3. 置信度低先写注释，不强制改名。  
4. 同名冲突用后缀或前缀消解。  
5. 以调用图为簇保证风格一致。

## 路线图
- P‑code 常量/指纹识别（TEA/XXHash/CRC/SHA/AES）。  
- 类型恢复与结构体字段命名。  
- IDA/rizin 回写器与脚本生成。  
- 评估报表（CLI → HTML）。  
- 与 `jhumanify` 集成。

## 法律与合规
仅在**自有或授权**的软件上进行逆向。LLM 输出为**逆向推断**，可能与原作者意图不一致。

## 许可协议
MIT。详见 `LICENSE`。

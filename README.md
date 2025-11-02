# so-humanify — LLM 驱动的 Android `.so` 人性化还原

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![Platform](https://img.shields.io/badge/Android-NDK%20ELF-green)]()
[![Backends](https://img.shields.io/badge/Backends-Ghidra%20%7C%20rizin%20%7C%20RetDec-orange)]()
[![LLM](https://img.shields.io/badge/LLM-GPT%20%7C%20OpenAI%20API%20%7C%20Ollama%20%7C%20Others-purple)]()

> Humanify stripped Android native libraries with LLMs: **extract facts → generate readable names/comments → write back to Ghidra/IDA/rizin**.

---

## ✨ 核心特性

- **事实导出（features）**：从 `.so` 导出函数签名/参数计数、调用关系、字符串/常量、伪代码片段（优先 Ghidra，可选 rizin/RetDec）。
- **LLM 语义命名**：按规则生成函数/变量/结构体的**可读名称与注释**，输出统一 `renames.json`（含置信度）。
- **一键回写**：批量把命名/注释回写到 **Ghidra** 工程（可扩展到 IDA / rizin）。
- **JNI 支持**：融合动态 `RegisterNatives` 映射与静态扫描，提高 JNI 函数命名质量。
- **批处理与并发**：内置队列、限流、重试与缓存；`--max-concurrent`、`--batch` 可调。
- **评估与回归**：可读性启发式、JNI 匹配率、低置信度清单，便于人工抽检。

---

## 🧭 流水线

```
[ELF 读取] → [反汇编/反编译后端] → [事实导出(JSON)]
                          ↓
                   [LLM 命名/注释]
                          ↓
      [回写到 Ghidra/IDA/rizin 工程 + 侧车产物]
                ↖—— [JNI 动态/静态线索] ——↗
```

---

## 📦 目录结构（建议）

```
so-humanify/
  ├─ backends/
  │   ├─ ghidra/
  │   │   ├─ export_features.py      # 导出事实（Jython）
  │   │   └─ apply_renames.py        # 回写命名/注释（Jython）
  │   ├─ rizin/
  │   │   └─ export_features_rizin.py# r2pipe 备选导出
  │   └─ retdec/
  │       └─ run_retdec.sh           # 兜底 decompile
  ├─ humanify/
  │   ├─ llm_prompts/
  │   │   └─ rename_template.md      # 提示词模版
  │   ├─ feature_pack.py             # 事实打包与裁剪
  │   ├─ llm_runner.py               # 批处理/限流/重试
  │   └─ post_rules.py               # 命名后处理与冲突消解
  ├─ bridge/
  │   ├─ jni_map_from_frida.js       # Frida 动态抓 JNI
  │   └─ jni_static_scanner.py       # 静态扫描 JNI 线索（占位）
  ├─ cli.py                          # sohumanify 命令行入口
  ├─ pyproject.toml / requirements.txt
  └─ examples/
      └─ libexample.so (占位)
```

---

## ⚙️ 环境要求

- **Python** ≥ 3.9  
- **Ghidra** ≥ 10.3（含 `analyzeHeadless`；首选后端）  
- 可选：`rizin`/`radare2`（安装 `r2pipe` 与 pdd/pdc 插件）、**RetDec**（兜底反编译）、**Frida**（Android 动态抓 JNI）  
- LLM 接入：OpenAI 兼容 API / 本地 Ollama / 其他（通过 `--model`、`--base-url` 指定）

---

## 🚀 快速上手

### 1) 安装依赖
```bash
pip install -r requirements.txt
```

### 2) 使用 Ghidra 导出事实（features）
```bash
GHIDRA="/Applications/ghidra*/support/analyzeHeadless"
PROJ=.work/foo_ghidra
OUT=facts/foo.json
mkdir -p "$(dirname "$OUT")"

"$GHIDRA" "$PROJ" foo_project   -import libfoo.so   -scriptPath backends/ghidra   -postScript export_features.py   -overwrite
```

### 3) 运行 LLM 命名（humanify）
```bash
export OPENAI_API_KEY=sk-xxx
python cli.py humanify facts/foo.json   --model gpt-4o-mini   --max-concurrent 100   --batch 12   --out names/foo.renames.json
```

### 4) 回写到 Ghidra 工程
```bash
"$GHIDRA" "$PROJ" foo_project   -scriptPath backends/ghidra   -postScript apply_renames.py   -overwrite
```

### 5) （可选）融合 JNI 动态映射
```bash
frida -U -f com.example.app -l bridge/jni_map_from_frida.js --no-pause > jni_map.log
python cli.py jni --frida jni_map.log --merge names/foo.renames.json
```

---

## 🧪 输出格式示例

**facts/foo.json**
```json
{
  "binary": "libfoo.so",
  "functions": [
    {
      "addr": "0x0000A3F0",
      "name": "sub_A3F0",
      "params": ["int", "char *"],
      "ret": "int",
      "size": 312,
      "called": ["0x000011C8"],
      "strings": ["AES", "CBC", "decrypt error"],
      "comment": "",
      "pseudocode": "int sub_A3F0(int a1, char *buf) { ... }"
    }
  ]
}
```

**names/foo.renames.json**
```json
{
  "binary": "libfoo.so",
  "renames": [
    {
      "addr": "0x0000A3F0",
      "new_name": "aesCbcDecrypt",
      "comment": "Detects AES tables & CBC loop; used by decryptAttachment()",
      "confidence": 0.86
    },
    {
      "addr": "0x00011C08",
      "new_name": "jniRegister_com_app_Foo_init",
      "confidence": 0.92
    }
  ]
}
```

---

## 🧠 命名规则（默认）

1. 驼峰式（camelCase），动宾短语优先：`parseVarInt`, `aesCbcDecrypt`。  
2. 模块前缀可选：`crypto_`, `http_`, `jni_`。  
3. 低置信度（< 阈值）仅写注释，不强行改名。  
4. 同名冲突自动消解（`_v2` 或模块前缀）。  
5. 调用图聚类（cluster）内风格统一。

---

## 🗺️ Roadmap

- [ ] P-code 级别常量/指纹提取（TEA/XXHash/CRC/SHA/AES 常量识别）。  
- [ ] 类型恢复 & 结构体字段命名。  
- [ ] IDA 回写脚本与 `.idc` 生成。  
- [ ] rizin/radare2 回写器、`.r2` 脚本生成。  
- [ ] 评测面板（CLI → HTML 报告）。  
- [ ] 与 **jhumanify** 深度整合。  

---

## 🛡️ 法律与合规

- 仅在**自有或授权**软件上进行逆向；不得用于绕过 DRM、盗版或侵害第三方权益。  
- LLM 生成的命名与注释属于**逆向推断**，不保证与原作者意图一致。  

---

## 📄 License

本项目使用 **MIT License**。详见 [LICENSE](./LICENSE)。

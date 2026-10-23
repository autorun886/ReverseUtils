---
name: ida-export-cli
description: 使用 ida-export-cli 通过 IDA Pro 的 idalib 和 ida-domain 自动分析本地二进制或已有 IDA 数据库，导出 schema v3 离线快照，包括每函数伪代码、ASM、结构化指令、CFG、调用与 xref、字符串引用、名称、数据、注释、类型、指针和 segment 内存。用于无界面运行 IDA、对单个样本生成 AI 可检索结果、查询导出状态或排查恢复与发布失败。
---

# IDA 离线分析导出

使用项目包装脚本分析一个本地文件。公开调用面固定为 `INPUT [-o OUTPUT]`，不要增加目录、并发、架构或 loader 参数。

## 环境

```bash
PROJECT_ROOT=/path/to/ida-export-cli
TOOL="$PROJECT_ROOT/scripts/ida-export-cli.sh"
test -x "$TOOL"
"$TOOL" --help
```

包装脚本优先读取 `IDA_PYTHON`，通过 `PYTHONPATH` 加载源码，不要求项目虚拟环境。所选解释器必须与 IDA 的 `idapro` wheel 匹配，并能导入 `ida-domain`。IDA 按 `IDADIR`、`~/.idapro/ida-config.json`、macOS 常见安装目录发现；自动发现失败时显式设置 `IDADIR`。

## 执行

1. 将输入解析为绝对路径并确认是普通文件。
2. 用 `file` 检查格式和架构。
3. 普通 PE、ELF、thin Mach-O 或已有 IDA 数据库直接运行。
4. Fat Mach-O 先提取当前主机架构的 thin slice。
5. 命令成功后校验 `COMPLETE`、manifest、v3 全局文件及每函数四类 artifact。

默认输出 `<INPUT>.ida-export`：

```bash
"$TOOL" "/absolute/path/sample.bin"
```

指定输出目录：

```bash
"$TOOL" "/absolute/path/sample.bin" \
  -o "/absolute/path/sample.export"
```

不要把 `-o` 指向输入文件。已有输出只会在新 staging 完整通过校验后被原子替换。

Fat Mach-O：

```bash
INPUT=/absolute/path/universal.bin
ARCH="$(uname -m)"
THIN="${TMPDIR:-/tmp}/$(basename "$INPUT").${ARCH}"
lipo -archs "$INPUT"
lipo "$INPUT" -thin "$ARCH" -output "$THIN"
"$TOOL" "$THIN" -o "$INPUT.ida-export"
```

## 验证发布结果

```bash
OUT=/absolute/path/sample.export
test -f "$OUT/COMPLETE"
test "$(cat "$OUT/COMPLETE")" = "schema=3"
for f in manifest.json function_index.jsonl callgraph.jsonl xrefs.jsonl \
  string_xrefs.jsonl names.jsonl data.jsonl comments.jsonl types.jsonl \
  function_fallbacks.jsonl function_failures.jsonl function_skipped.jsonl \
  pointers.jsonl strings.jsonl imports.json exports.json segments.json \
  memory_index.jsonl task.log; do
  test -f "$OUT/$f"
done
test -d "$OUT/functions"
test -d "$OUT/instructions"
test -d "$OUT/cfg"
test -d "$OUT/memory"
jq '{schema_version, compatibility, status, backend, api,
     runtime, capabilities, counts, artifacts, input}' "$OUT/manifest.json"
```

期望：

- `schema_version=3`、`status=complete`；
- `backend=idalib`、`api=ida-domain`；
- `compatibility.minimum_reader=2`；
- `capabilities` 包含实际可提供的 instructions/xrefs/CFG/global 语义类别；
- `counts` 与对应 JSONL 和每函数 artifact 一致；
- `artifacts` 包含文件数、总字节数和 inventory hash。

launcher 在复制最终 `task.log`、完成 schema validator 后才写 `COMPLETE` 并发布。因此只消费带正确 `COMPLETE` 的目录；失败 work 目录和仅有 `manifest.status=complete` 的 staging 不视为已发布结果。

## 读取顺序

1. 先读 `manifest.json`，确认输入 SHA-256、架构、runtime、capabilities、counts 和覆盖质量。
2. 读 fallback/failure/skipped 日志，了解局部缺失。
3. 从 `function_index.jsonl` 按名称或 EA 定位函数。
4. 同时读取 `.c`、`.asm`、instructions JSONL 和 CFG JSON。
5. 用 callers/callees、`call_sites`、`callgraph.jsonl` 和 `xrefs.jsonl` 扩展依赖。
6. 用 string refs、names、data、comments、types、pointers 补充语义。
7. 需要原始内存证据时先读 segments/memory index，再读取对应 hexdump。

函数 artifact 示例查询：

```bash
EA=0x140001000
ROW="$(jq -c --arg ea "$EA" 'select(.ea == $ea)' "$OUT/function_index.jsonl")"
printf '%s\n' "$ROW" | jq '{ea,name,signature,flags,duration_ms,slow,
  callers,callees,call_site_count,artifacts,artifact_hashes,
  decompile_error,disassembly_error,analysis_errors}'
printf '%s\n' "$ROW" | jq -r '.artifacts[]' | while read -r rel; do
  test -f "$OUT/$rel" && printf '%s\n' "$OUT/$rel"
done
```

关键词检索优先使用：

```bash
rg -n -i 'KEYWORD' \
  "$OUT/functions" "$OUT/instructions" "$OUT/memory" \
  "$OUT/strings.jsonl" "$OUT/string_xrefs.jsonl" \
  "$OUT/names.jsonl" "$OUT/data.jsonl" "$OUT/comments.jsonl" \
  "$OUT/imports.json" "$OUT/exports.json"
```

结构化统计：

```bash
jq '.counts | {
  total_functions, functions, successful, exported, fallbacks, skipped, failed,
  instructions, xrefs, cfg_functions, string_xrefs, names, data, comments, types,
  strings, pointers, imports, exports, segments, memory_bytes, memory_chunks
}' "$OUT/manifest.json"
```

详细字段见 [../../docs/output-schema.md](../../docs/output-schema.md)。

## 函数与关系解释

每个未跳过函数必须有：

- `functions/*.c`：伪代码或明确的 decompile error 占位；
- `functions/*.asm`：文本反汇编或明确的 disassembly error 占位；
- `instructions/*.jsonl`：地址、bytes、mnemonic、operands、注释和局部读取错误；
- `cfg/*.json`：基本块、instruction EA、前驱和后继。

伪 C 用于语义定位，ASM/instructions/CFG 用于验证。`instruction_count` 是 Hex-Rays 保护计数，`structured_instruction_count` 是实际结构化记录数。普通顺序控制流由 CFG 表达，`xrefs.jsonl` 聚焦调用、跳转和数据等有意义引用。

`pointers.jsonl` 的 `evidence` 可含 `data_xref`、`raw_pointer` 或两者；`target_type` 可为 import/string/function/code/struct/data/unknown pointer 分类。不要把启发式裸指针与确定的 call site 等同。

## 恢复与故障定位

失败时检查输出父目录：

```text
.ida-export-work/<job-id>/
  identity.json
  identity.previous.json
  progress.jsonl
  progress.json
  currently_processing.json
  decompile_blacklist.json
  heartbeat.json
  snapshot/
  task.log
```

- 只有 `phase=decompile` 的中断函数进入 blacklist；其他阶段重试。
- C/ASM、全局阶段和 memory chunk 的有效 checkpoint 会复用。
- runtime/capability/policy/input identity 变化会保留 previous identity、清理旧工具产物并完整重建。
- 输入分析期间变化会阻止发布。
- watchdog 约束为 10 分钟无进展和 2 小时最终墙钟；终止会清理 worker 进程组。
- 大于 16 KiB、超过 3000 条指令或命中 blacklist 的函数跳过 Hex-Rays，但仍保留其他证据。
- `task.log` 包含 launcher、worker、进度、警告和失败尾部。

常见检查：

```bash
cat "$OUT/function_fallbacks.jsonl"
cat "$OUT/function_failures.jsonl"
cat "$OUT/function_skipped.jsonl"
jq -c 'select(.decompile_error or .disassembly_error or .analysis_errors)' \
  "$OUT/function_index.jsonl"
```

## 修改工具后的验证

只在修改项目代码或 schema 文档后执行：

```bash
cd "$PROJECT_ROOT"
PYTHON="${IDA_PYTHON:-python3}"
"$PYTHON" -m compileall -q src
if [ -d tests ]; then
  PYTHONPATH="$PROJECT_ROOT/src" "$PYTHON" -m pytest -q -m 'not integration'
fi
```

`tests/` 仅存在于本地开发目录并由 Git 忽略；存在时可执行单元回归。公开仓库以源码编译检查和实际样本导出结果为准。

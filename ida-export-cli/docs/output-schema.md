# IDA Export CLI 离线快照字段说明

当前发布格式为 **schema v3**，validator 继续接受 schema v2。v3 在保留 v2 C/ASM、调用图、字符串、导入、导出、pointer 和 memory 的基础上，增加结构化 instruction、CFG、xref、string refs、names、data、comments 和 types。

## 目录结构

```text
<output>/
├── COMPLETE
├── manifest.json
├── function_index.jsonl
├── callgraph.jsonl
├── xrefs.jsonl
├── string_xrefs.jsonl
├── names.jsonl
├── data.jsonl
├── comments.jsonl
├── types.jsonl
├── function_fallbacks.jsonl
├── function_failures.jsonl
├── function_skipped.jsonl
├── pointers.jsonl
├── strings.jsonl
├── imports.json
├── exports.json
├── segments.json
├── memory_index.jsonl
├── task.log
├── functions/
│   ├── <SAFE_NAME>__<EA>.c
│   └── <SAFE_NAME>__<EA>.asm
├── instructions/
│   └── <SAFE_NAME>__<EA>.jsonl
├── cfg/
│   └── <SAFE_NAME>__<EA>.json
└── memory/
    └── <START>--<END>.txt
```

`<EA>` 是十六进制地址。安全名称会清理特殊字符并追加地址；同名函数不会覆盖。

`COMPLETE` 内容必须精确为 `schema=3`。它由 launcher 在复制最终 `task.log`、validator 校验 staging 后写入，存在且内容匹配才代表目录已经发布。worker 失败时的 `snapshot/` 不是可消费快照。

## manifest.json

顶层字段：

| 字段 | 说明 |
|---|---|
| `schema_version` | 当前为 `3` |
| `compatibility.minimum_reader` | 当前为 `2`，表示 v2 reader 可读取兼容公共字段 |
| `generator.name/version` | `ida-export-cli` 和生成版本，当前版本为 `0.5.0` |
| `backend` / `api` | 固定为 `idalib` / `ida-domain` |
| `status` | 完整 worker 结果为 `complete` |
| `capabilities` | 实际可生成的结构化能力名列表 |
| `runtime` | adapter 报告的 IDA/ida-domain 版本、feature flags 和 decompilation flags |
| `artifacts` | inventory 文件数、字节数和 inventory SHA-256 |
| `input` | 输入路径、大小、最终 SHA-256 |
| `database` | IDA database metadata，如格式、架构、位数、映像基址 |
| `counts` | 所有记录和 memory 统计 |
| `started_at/finished_at` | UTC ISO-8601 时间 |
| `duration_seconds` | 导出耗时 |

`runtime` 与 work 状态的 identity 不同：runtime 是最终快照中供读取者诊断的信息；`identity.json` 还包含输入、schema、generator、runtime/capability/policy fingerprint，用于恢复状态失效判断。

### counts

```json
{
  "total_functions": 0,
  "functions": 0,
  "successful": 0,
  "exported": 0,
  "decompiled": 0,
  "assembly": 0,
  "disassembled": 0,
  "fallbacks": 0,
  "skipped": 0,
  "failed": 0,
  "hard_failed": 0,
  "decompile_failed": 0,
  "disassembly_failed": 0,
  "call_edges": 0,
  "instructions": 0,
  "xrefs": 0,
  "cfg_functions": 0,
  "string_xrefs": 0,
  "names": 0,
  "data": 0,
  "comments": 0,
  "types": 0,
  "strings": 0,
  "pointers": 0,
  "imports": 0,
  "exports": 0,
  "segments": 0,
  "memory_chunks": 0,
  "memory_bytes": 0
}
```

- `total_functions = functions + skipped`；
- `assembly` 是进入 function index 的函数数，`disassembled` 是 ASM 成功数；
- `exported = disassembled`，包含 decompile fallback；
- `hard_failed` 同时缺少 C 和 ASM 的函数数；
- `instructions` 只计有有效 EA 的结构化指令；
- `cfg_functions` 只计存在非空 block 列表的 CFG；
- `memory_bytes` 是 memory index 中原始字节数之和，不是 hexdump 文本大小。

`artifacts.inventory_sha256` 对除 `manifest.json`、`COMPLETE`、`task.log` 和内部 state 外的所有文件按路径排序后计算，validator 会重新增量计算并比较。
由于 `function_index.jsonl` 包含本次运行的耗时指标，该 hash 用于当前快照完整性校验，不承诺跨次运行保持不变；跨版本内容复用属于后续 content hash 能力。

## function_index.jsonl

每行对应一个未跳过、有效函数：

| 字段 | 说明 |
|---|---|
| `ea` / `end_ea` | 起止 EA，形如 `0x140001000` |
| `size` | `end_ea - ea` |
| `instruction_count` | Hex-Rays 保护计数，可能为 `null` |
| `structured_instruction_count` | instructions JSONL 中有有效 EA 的行数 |
| `name` / `safe_name` | IDA 名称和文件安全名称 |
| `signature` | IDA 类型签名，没有时为 `null` |
| `flags` | 函数属性列表 |
| `callers` / `callees` | 函数级地址和名称列表 |
| `call_site_count` | 该函数产生的 CALL xref 数量 |
| `duration_ms` | 函数总处理耗时 |
| `decompile_duration_ms` | Hex-Rays 处理耗时，没有调用时为 `null` |
| `slow` | 是否超过内部慢函数阈值 |
| `kind` / `artifact` | 兼容字段；`c` 或 `asm` |
| `artifacts` | pseudocode、disassembly、instructions、cfg 相对路径 |
| `artifact_hashes` | 上述 artifact 的 SHA-256 |
| `analysis_errors` | 名称、签名或局部 IDA 读取错误 |
| `decompile_error` | 伪代码失败或保护原因 |
| `disassembly_error` | ASM 失败原因 |

每个函数应同时有 `.c` 和 `.asm`。伪代码失败时 `.c` 是带原因的占位文本，ASM 不会因为 fallback 被删除。instructions JSONL 和 CFG JSON 是独立结构证据。

## 函数 artifact

### C 与 ASM

两者都包含函数名称、EA、callers、callees 头部。C 是 Hex-Rays 文本或错误说明；ASM 是 IDA 文本反汇编或错误说明。文本证据用于检索，不能替代结构化指令和 CFG。

### instructions/<SAFE_NAME>__<EA>.jsonl

每行字段：

```json
{
  "ea": "0x140001020",
  "size": 5,
  "bytes": "E8 DB 0F 00 00",
  "mnemonic": "call",
  "operands": ["sub_140002000"],
  "text": "call sub_140002000",
  "regular_comment": null,
  "repeatable_comment": "dispatch",
  "read_error": null
}
```

`bytes` 是大写、空格分隔的十六进制字符串。单条 byte/comment/mnemonic 读取失败时保留该行并写 `read_error`，后续指令继续导出。`ea=null` 的错误诊断行不计入 `counts.instructions`。

### cfg/<SAFE_NAME>__<EA>.json

```json
{
  "function_ea": "0x140001000",
  "entry_block": "0x140001000",
  "blocks": [
    {
      "id": "0x140001000",
      "ordinal": 0,
      "start_ea": "0x140001000",
      "end_ea": "0x140001030",
      "instruction_eas": ["0x140001000", "0x140001005"],
      "successors": ["0x140001040"],
      "predecessors": [],
      "read_error": null
    }
  ],
  "read_error": null
}
```

block ID 使用起始 EA；`ordinal` 仅作诊断。普通顺序控制流由 CFG 表达，不重复进入全局 xref。

## 调用图与 xref

### callgraph.jsonl

每行包含 `ea`、`name`、`callers`、`callees` 和 schema v3 的 `call_sites`。函数级 callers/callees 保留兼容语义，具体 call 地址从 `call_sites` 或 `xrefs.jsonl` 获取。

### xrefs.jsonl

```json
{
  "source_ea": "0x140001020",
  "target_ea": "0x140002000",
  "source_function_ea": "0x140001000",
  "target_function_ea": "0x140002000",
  "xref_type": "CALL_NEAR",
  "xref_type_value": 16,
  "is_code": true,
  "user": false,
  "confidence": "ida_xref"
}
```

兼容版本可能同时出现 `xref_type`、`xref_type_value` 或 `type` 字段。普通 `ORDINARY_FLOW`/`fl_F`/数值 `0x15` 控制流被过滤；带 `read_error` 的诊断记录保留。间接调用可使用 `target_ea=null` 和 `confidence=indirect`。

## 全局 JSONL

| 文件 | 主要字段 |
|---|---|
| `string_xrefs.jsonl` | `string_ea`、`source_ea`、`source_function_ea`、`value`、`xref_type`、`read_error` |
| `names.jsonl` | `ea`、`name`、`segment`、`is_function`、`function_ea`、`is_auto`、`name_flags`、`read_error` |
| `data.jsonl` | `ea`、`size`、`segment`、类型/bytes/hash、references、`read_error` |
| `comments.jsonl` | `ea`、`function_ea`、`kind`、`text`、`extra_index`、`read_error` |
| `types.jsonl` | `name`、`declaration`、`kind`、`size`、`details`、`read_error` |

未知 enum 使用可读的 `UNKNOWN_<value>` 和 raw value；单条异常不终止整个阶段。counts 必须等于对应 JSONL 的非空物理行数。

## 日志、字符串、导入导出

- `function_fallbacks.jsonl`：伪代码失败但 ASM 可用的函数、原因和 ASM artifact；
- `function_failures.jsonl`：ASM 失败及 C/ASM 错误；
- `function_skipped.jsonl`：library、invalid entry 或其他跳过原因；
- `strings.jsonl`：`ea`、`length`、`type`、可选 `type_value`、`encoding`、`value`；
- `imports.json`：数组，条目包括 `ea`、`name`、`ordinal`、`module`；
- `exports.json`：数组，条目包括 `ea`、`name`、`ordinal`、`forwarder`；
- `task.log`：launcher 和 worker 的阶段、进度、警告、异常尾部和发布诊断。

即使记录数为零，以上日志和 JSONL 文件也必须存在。

## pointers.jsonl

每行描述一条去重后的源到目标关系：

```json
{
  "source_ea": "0x140003000",
  "source_segment": ".data",
  "target_ea": "0x140002000",
  "target_segment": ".text",
  "target_name": "sub_140002000",
  "target_type": "function_pointer",
  "target_detail": "function",
  "evidence": ["data_xref", "raw_pointer"]
}
```

`target_type` 可为 `import_pointer`、`string_pointer`、`function_pointer`、`code_pointer`、`struct_pointer`、`data_pointer` 或 `unknown_pointer`。`evidence` 说明来自确定的 IDA data xref、可读数据段裸指针扫描或两者。

## segments、memory_index 与 memory

### segments.json

数组条目包括：

- `name`、`class`、`start_ea`、`end_ea`、`size`；
- `bitness`；
- `permissions.value/read/write/execute`；
- `memory_chunks`、`memory_bytes`。

### memory_index.jsonl

memory 按 segment、最多 1 MiB 原始字节分片：

```json
{
  "segment": ".text",
  "segment_class": "CODE",
  "segment_start_ea": "0x1000",
  "segment_end_ea": "0x9000",
  "start_ea": "0x1000",
  "end_ea": "0x9000",
  "size": 32768,
  "bitness": 64,
  "permissions": {"read": true, "write": false, "execute": true},
  "artifact": "memory/0000000000001000--0000000000009000.txt",
  "sha256": "...",
  "artifact_sha256": "..."
}
```

`sha256` 是 IDA 读出的原始字节 hash，`artifact_sha256` 是 hexdump 文本 hash。文本每行含地址、16 个十六进制字节和 ASCII 视图。读取失败或短读会中止当前导出，不发布不完整 memory。

## work 状态与恢复

work 状态不进入最终快照：

```text
.ida-export-work/<job-id>/
├── identity.json
├── identity.previous.json
├── progress.jsonl
├── progress.json
├── currently_processing.json
├── decompile_blacklist.json
├── heartbeat.json
├── snapshot/
├── task.log
└── .job.lock
```

- `identity.json`：输入、schema/generator、后端、runtime/capability/policy fingerprint；
- `identity.previous.json`：identity 失配时的旧值；
- `progress.jsonl`：`complete`、`invalidate`、`stage`、`memory_chunk` 事件；
- `progress.json`：最多 256 个事件后压缩的完成、阶段和 memory 索引；
- `currently_processing.json`：EA、name、position、phase、started_at；
- `decompile_blacklist.json`：仅 Hex-Rays 中断函数；
- `heartbeat.json`：launcher 判断阶段进展。

身份失配会清理 exporter 所有权的 snapshot 目录和旧索引，避免 orphan artifact；日志、锁和非工具文件保留。成功发布后 launcher 清理整个 work 目录；失败、超时或中断则保留以便诊断和恢复。

## 读取建议

1. 校验 `COMPLETE` 和 `manifest.status`；
2. 比较 `input.sha256` 与目标样本；
3. 检查 fallback/failure/skipped 比例；
4. 按 `function_index` 定位并同时读取 C/ASM/instructions/CFG；
5. 依赖追踪使用 callgraph、call sites 和 xrefs；
6. 类型、数据、注释和内存证据按地址交叉验证；
7. 对 `read_error`、`UNKNOWN_*` 和 pointer `confidence` 保留不确定性，不把缺失值当作确定事实。

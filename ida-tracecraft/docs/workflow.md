# 从选择函数到查看结果

工具仍以单个 `entry_trace.py` 交付。原有 CLI、Python API 和文本日志默认行为保留。

## 先预览，再生成

```powershell
python entry_trace.py preview --input libsample.so --mode regex --query "decrypt|decode" --exclude "^thunk_" --infer-types
python entry_trace.py --input libsample.so --mode regex --query "decrypt|decode" --exclude "^thunk_" --infer-types --log-format jsonl --max-events 2000 --duration 30 --save-config observe.json --bundle runs/observe -o trace.js
```

`preview` 输出目标名称、IDA 地址、模块偏移、选择原因、Hook 数、排除数、详细上下文数量和运行限制；加 `--infer-types` 后还会列出类型建议与不确定项。预览本身不写 JS 文件。原型只在明确请求类型推导或 AI 上下文时读取。

`--exclude REGEX` 可重复，对函数原始名称匹配，在线和离线生成均生效。排除窗口触发函数会报错。

`--infer-types` 只推导简单的 32 位整数和指针；字符串指针保留为原始指针。浮点、结构体、64 位整数、复杂声明等保留默认参数类型并显示提示。明确的 `--arg-types`、`--ret-type` 和逐函数 plan 优先。推导结果仍需结合调用约定检查；超过寄存器参数范围的参数请使用专用 JS。

## 复用配置与归档

```powershell
python entry_trace.py preview --config observe.json
python entry_trace.py --config observe.json --max-events 500 --duration 10 -o short.js
```

配置使用 CLI 参数的 Python 名称，例如 `max_events`、`arg_types`、`selectors`。完整示例见 [observe.json](../examples/observe.json)。`arg_types` 与 CLI 一样是逗号分隔字符串，重复选项使用数组。显式 CLI 参数覆盖配置；显式重复选项替换配置中的整个数组。文件路径相对于当前工作目录解释。

`--bundle DIR` 保存脚本、原始快照、可离线复用的配置和 manifest。manifest 记录实际文件路径及预览结果。已有文件自动编号，始终使用返回路径。重复归档不会覆盖旧文件。运行日志可通过 Frida 的 `-o` 保存到同一目录：

```powershell
frida -U -f com.example.app -l trace.js -o runs/observe/events.jsonl
```

上面的 `trace.js` 应替换为生成命令返回的实际 `script_path`。`--bundle` 只归档生成材料；采集由 Frida 执行。`--ai-script` 使用完整自定义脚本时，运行状态和限额由该脚本自行实现。

## 采集限制

| 参数 | 行为 |
| --- | --- |
| `--max-events N` | 接受 N 次入口事件或 Hook 调用后停止；默认 0 表示不限 |
| `--duration SECONDS` | 从脚本加载开始计时，包含等待模块时间；默认 0 表示不限 |
| `--per-function-limit N` | 每个函数最多接受 N 次；达到后只跳过该函数 |
| `--sample-every N` | 对每个函数保留第 1、N+1、2N+1…次符合条件的事件 |
| `--thread-id TID` | 仅采集指定线程，可重复 |
| `--single-thread` | 使用默认主线程候选；window 模式使用首个触发线程 |

顺序为：线程／参数条件 → 采样 → 单函数限额 → 全局限额。采样和单函数计数跨线程、跨模块重载累计，直到脚本重新加载。纯 Hook 的 ENTER/LEAVE 算一次调用，LEAVE 不额外消耗额度。达到全局限额后在下一个 JS 调度点停止；在途调用可能没有 LEAVE，调用次数仍严格受限。诊断消息不消耗额度。

window 的触发入口不消耗后续窗口额度或全局入口额度。history 的触发入口消耗全局额度，但保留触发控制语义，不参与采样和单函数截断。history/window 开启采样后，前后窗口表示保留的入口事件，而非原始全部入口次数。

Stalker 不保证所有线程都被发现。状态中的 `threads` 列出线程名称、选择原因、命中次数和跟踪状态。Windows 使用首个枚举线程作为默认主线程候选，需要确定线程时使用 `--thread-id`。对挂起的新进程，全量模式最多进行三次无命中重新跟踪；history 在首次实际触发时重新启动尚未产生命中的跟踪。

## 运行状态与日志

生成脚本仍提供 `rpc.exports.status()` 和 `stop()`。状态包含：

- `state`：`waiting-module`、`ready`、`partial`、`failed`（纯 Hook 全部安装失败）或 `stopped`。
- `expected`/`installed`/`hookFailures`：纯 Hook 的目标数、已安装数及失败数；Stalker 使用 `expectedHooks`/`installedHooks`，另有 `followFailures`。
- `observed`、`accepted`、`filtered`、`sampled`、`capped`：观察、接受、条件过滤、采样跳过及限额跳过次数。
- `readErrors`、`lastEvent`、`elapsedMs`、`stopReason`：读取失败次数、最近接受事件时间、运行时长及停止原因。
- `perFunction`：每个函数的符合条件次数 `seen` 和接受次数 `accepted`。

纯 Hook 部分安装失败会显示 `partial`，全部失败显示 `failed`。读取失败的参数在 JSONL 中明确显示 `{ "error": "read-failed", "type": "cstring" }`，与空指针的 `null` 区分。字符串读取先在上限内查找结束符，再解码；越界、编码异常等仍会计入读取失败。

`--log-format jsonl` 为每条输出增加 `schema`、`session`、`module`、`time`、`type` 和人读消息。入口及返回事件还有线程 ID、函数名、偏移、调用／入口 ID、参数或返回值。history 事件带 `phase` 和 `snapshot`，重复输出的历史入口保留原始 ID。

## 查看结果

```powershell
python entry_trace.py results --results-file runs/observe/events.jsonl
python entry_trace.py results --results-file runs/observe/events.jsonl --tid 1234 --limit 100
python entry_trace.py results --results-file runs/observe/events.jsonl --session SESSION_ID --limit 0
```

输出函数命中排行、线程集合，以及最近 N 条事件。排行按采集会话和模块分别统计，重复打印的历史入口只计一次。允许日志中包含 Frida banner 等非 JSON 行，`skipped_lines` 给出跳过数；格式损坏的事件也会跳过。事件尾部数量受 `--limit` 限制，排行去重所需索引随事件数量增长。

在 IDA 右键菜单的 **Entry Trace → Open trace results…** 打开函数排行，或用 **Open trace timeline…** 打开事件序列；双击行按当前数据库基址加偏移跳转。时间线窗口默认保留最近 2000 条日志中的入口／返回事件。

IDA Python 中可以筛选线程或会话：

```python
entry_trace.show_results(r'D:\runs\events.jsonl', tid=1234, timeline=True, limit=500)
```

结果窗口按当前数据库解释偏移；打开日志时请自行选择对应数据库。

## 验证

```powershell
python -m unittest -v test_entry_trace.py
python tests/entry_trace/test_instances.py -v
python tests/entry_trace/test_entrypoint.py -v
python tests/entry_trace/test_workflow.py -v
```

原生集成测试使用已经安装的 gcc 与 Frida Python 包，在临时目录编译小型样例并启动本地进程，不依赖 IDA：

```powershell
$env:TRACECRAFT_NATIVE_TESTS='1'
python tests/entry_trace/test_native_runtime.py -v
```

覆盖递归、多线程、DLL 延迟加载和卸载重载、正常字符串与无效指针读取、全量跟踪、历史窗口及停止限额。测试完成后结束样例进程并清理构建目录。

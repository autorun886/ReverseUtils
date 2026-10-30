# IDA Tracecraft

你只需要给 AI 一句话：

```sh
python /path/to/entry_trace.py -h
```

让 AI 读取帮助后，根据你的观察目标选择模式、定位 IDA 实例并生成 Frida 脚本。

[English documentation](README.en.md)

## 快速开始

1. 把 `entry_trace.py` 放入 IDA 的 `plugins` 目录，重启 IDA 并打开目标数据库。
2. 将上面的命令交给 AI，把 `/path/to/entry_trace.py` 换成实际路径，再说明要观察的函数或行为。
3. 将返回的 `script_path` 对应脚本加载到 Frida，例如：

```sh
frida -U -f com.example.app -l trace.js
```

## 能做什么

| 模式 | 用途 |
| --- | --- |
| `full` | 查看模块整体执行流程，记录被追踪线程经过的已知函数入口 |
| `window` | 到达指定函数后，记录后续 N 次入口 |
| `history` | 查看到达指定函数前后的入口记录 |
| `hooks` | 按函数名子串选择，观察参数和返回值 |
| `selected` | 观察明确指定函数的参数和返回值 |
| `regex` | 按函数名正则选择并 Hook |
| `callers` | 从指定函数向上扩展代码引用，Hook 种子及引用者 |
| `callees` | 从指定函数向下扩展直接调用，Hook 种子及被调用者 |

前三种使用 Stalker，其余使用 Interceptor。Hook 支持类型设置和参数条件过滤。窗口默认前后各 100 次，可分别调整；计数单位是入口事件。

## 常用命令

```sh
# 多实例：先列出，再选择目标文件或端口
python entry_trace.py instances
python entry_trace.py --input "D:/samples/libsample.so" --mode full -o trace.js

# 指定函数前 50 次、后 100 次入口
python entry_trace.py --mode history --root FUNC --before 50 --after 100

# 参数符合条件时记录参数与返回值
python entry_trace.py --mode selected --select FUNC --arg-types int,cstring --where 0:int:eq:7

# 导出分析上下文，之后离线生成
python entry_trace.py context --mode selected --select FUNC --ai-level guided --context-out context.json --prompt-out task.txt
python entry_trace.py --snapshot context.json --mode selected -o hooks.js
```

## 使用要点

- 函数可用精确名称、IDA 绝对地址或 `+0x模块偏移` 指定。数据库与运行时模块布局应一致；`--module` 可覆盖模块文件名。
- 同一文件多开时用 `--port` 区分。实例列表和歧义错误均返回 JSON，在线采集结果记录来源 PID/端口。
- 输出自动避开重名文件，后续操作以返回的绝对 `script_path` 为准。
- 历史仅覆盖线程开始追踪后的记录；追踪不保证捕获所有线程的全部入口。ARM64 追踪要求 Frida 17.10+；Android ART 默认启用 Java 解释执行，会增加开销。
- AI 上下文由工具导出，模型调用在外部完成。离线快照固定目标集合，改变选择需重新采集。

全部参数、模式语义和 AI 操作流程见 `-h`；可编辑的条件 Hook 示例见 [conditional_hooks.js](examples/conditional_hooks.js)。

## 测试

```sh
python -m unittest -v test_entry_trace.py
```

测试不依赖 IDA/Frida；安装 Node.js 可运行生成脚本的事件模拟。

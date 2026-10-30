# Entry Trace：IDA / AI 单文件入口

帮助参数支持 `-h` 和 `--help`：普通终端执行 `python D:\IDA\plugins\entry_trace.py -h`；IDA 内加载模块后调用 `entry_trace.main(['-h'])`。帮助包含模式、参数和使用示例。

每次通过菜单、generate_file() 或 main() 成功生成脚本，都会打印包含 script_path 绝对路径的 JSON；generate_file() 同时返回该字典。AI 应读取返回的实际路径继续编辑，因为文件重名时会自动编号。

entry_trace.py 作为 IDA 插件直接读取当前数据库。插件加载后，普通终端的 CLI 可直接连接当前 IDA；也可用 JSON 快照离线生成 Frida 脚本。原右键菜单保留。

```powershell
python entry_trace.py --mode window --root FUNC --count 20 -o after20.js
python entry_trace.py --mode history --root FUNC --before 50 --after 100 -o around.js
python entry_trace.py --mode selected --select FUNC_A --select FUNC_B --where 0:int:eq:7 -o hooks.js
```

实时调用需 IDA 已打开数据库并加载插件；输出文件写在 CLI 所在机器，返回实际绝对路径。

## IDA 内传参调用

在 IDA Python 控制台或 IDA 内执行的 Python 脚本中：

```python
import importlib.util
spec = importlib.util.spec_from_file_location('entry_trace_api', r'D:\IDA\plugins\entry_trace.py')
entry_trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry_trace)

# 触发后20次入口；省略count默认100
result = entry_trace.generate_file({
    'mode': 'window', 'root': 'FUNC', 'count': 20,
    'output': r'D:\reverse\utils\after20.js'
})
print(result['script_path'])

# 触发前50次、后100次
result = entry_trace.generate_file({
    'mode': 'history', 'root': 'FUNC', 'history_size': 50, 'window_size': 100
})
```

FUNC 换成当前数据库的函数名。root/selectors 支持函数名、IDA 绝对地址、模块相对地址字符串 +0x1234。count 同时设置前后数量，history_size/window_size 分别覆盖前后数量。

也可在 IDA 内直接传入参数列表：

```python
entry_trace.main(['generate', '--mode', 'window', '--root', 'FUNC', '--count', '20'])
entry_trace.main(['generate', '--mode', 'history', '--root', 'FUNC', '--before', '50', '--after', '100'])
```

计数指运行时观察到的入口次数，含重复调用。window 触发点不消耗后续额度。history 的前序只包含线程开始跟踪后观察到的事件，重复触发重置后续窗口。

generate_file() 返回含 script_path 绝对路径的字典，便于 AI 二次编辑。已有文件自动添加 _1、_2 后缀，父目录应预先存在。未指定输出时默认写入 IDA 输入文件所在目录；main() 默认写当前工作目录，并打印含 script_path 的 JSON。

## 模式

| mode | 行为 | Python 参数 |
| --- | --- | --- |
| full | 全模块入口跟踪 | single_thread |
| window | 触发后的入口窗口 | root、count/window_size |
| history | 触发前后入口窗口 | root、history_size、window_size |
| hooks | 函数名子串匹配，区分大小写 | query |
| selected | 精确指定函数集合 | selectors 列表 |
| regex | 函数名正则匹配 | query |
| callers | 种子及引用它的代码所在函数 | selectors、depth |
| callees | 种子及直接 call 目标 | selectors、depth |

main() 对应 --root、重复 --select、--query、--depth。调用关系依赖 IDA 静态引用，间接调用可能缺失。通用参数包含 backtrace、timestamps、single_thread、module、max_string、no_java_interpreter；main() 使用相应连字符参数。

## 精确函数与参数条件

在 IDA 内：

```python
result = entry_trace.generate_file({
    'mode': 'selected', 'selectors': ['FUNC_A', 'FUNC_B'],
    'arg_types': ['int', 'cstring'], 'ret_type': 'int',
    'when': {'all': [
        {'arg': 0, 'type': 'int', 'op': 'eq', 'value': 7},
        {'arg': 1, 'type': 'cstring', 'op': 'contains', 'value': 'hello'}
    ]}
})
print(result['script_path'])
```

参数序号从0开始，支持 pointer/int/uint/cstring/utf16，最多八个寄存器参数，默认六个原始指针。浮点、向量、按值结构体和栈参数需根据 ABI 编写专用 JS。

条件支持 eq/ne/contains/startsWith/endsWith/regex/gt/gte/lt/lte。数值比较使用 int/uint，文本使用 cstring/utf16；pointer 支持 eq/ne，采用规范十六进制字符串如 0x0。all 表示 AND，any 表示 OR，可嵌套：

```json
{"all":[{"arg":0,"type":"int","op":"eq","value":7},{"any":[{"arg":1,"type":"cstring","op":"contains","value":"hello"},{"arg":1,"type":"cstring","op":"startsWith","value":"world"}]}]}
```

main() 支持重复 --where ARG:TYPE:OP:VALUE（AND），如 --where 0:int:eq:7。复杂条件用 --when-file conditions.json 或 --when JSON；Windows 推荐表达式或文件以避免引号转换。

条件适用于纯 Hook 模式，入口检查通过时记录 ENTER/LEAVE；检查仍需安装入口拦截器。条件不修改目标参数或返回值，也不控制 Stalker 窗口。字符串读取受 max_string 限制。

纯 Hook 输出采用精简模板，顶部 CONFIG.hooks 列出函数、offset、Thumb 标志、参数/返回类型及条件，正文保留模块监听、条件判断、日志及 stop/status。跟踪模式需要全模块入口表，脚本会相应增大。

## AI 参与与快照

| ai_level | 导出内容 | 参与方式 |
| --- | --- | --- |
| off | 函数名、地址、Thumb | AI 决定模式、范围和计数 |
| light | 增加原型、注释 | AI 选择函数和参数 |
| guided | 增加反编译、引用 | AI 回填类型化方案 |
| deep | 同 guided，提示词允许完整脚本 | AI 编写完整 JS |

在 IDA 内导出：

```python
entry_trace.main(['context', '--mode', 'selected', '--select', 'FUNC',
                  '--ai-level', 'guided', '--context-out', r'D:\reverse\utils\context.json',
                  '--prompt-out', r'D:\reverse\utils\task.txt'])
```

max_functions 默认40，只限制详细分析信息，不限制跟踪入口。Hex-Rays 缺失或失败记入函数的 decompile_error。工具不内置模型账号，AI 阅读上下文后编写方案或脚本。

方案示例，offset 必须位于快照函数列表中：

```json
{"hooks":[{"offset":"0x1234","args":["int","cstring"],"ret":"uint","when":{"arg":1,"type":"cstring","op":"contains","value":"hello"}}]}
```

全局和函数条件按 AND 合并。plan 在纯 Hook 模式替换目标集合，在跟踪模式增加参数/返回 Hook；条件仅支持纯 Hook 模式。AI 类型推断需结合原型与运行结果验证。

## IDA 外离线生成

在普通 PowerShell 中指定已导出的快照：

```powershell
python D:\IDA\plugins\entry_trace.py generate --snapshot context.json --mode selected --plan plan.json -o typed.js
python D:\IDA\plugins\entry_trace.py generate --snapshot context.json --mode selected --arg-types int,cstring --where 0:int:eq:7 -o filtered.js
python D:\IDA\plugins\entry_trace.py generate --snapshot context.json --mode selected --ai-level deep --ai-script standalone.js -o final.js
```

离线运行使用 --snapshot；mode 应与采集时一致，改变范围、root、参与深度后重新采集。省略 --snapshot 时，CLI 直接访问已加载插件的 IDA。ai-script 是完整脚本替换，不执行或合并模板。

Python 离线调用可向 generate(request, snapshot) 或 generate_file(request, path, snapshot) 传入快照。collect_snapshot(**request) 直接读取 IDA。render_script(root_ea=None, mode='full', substring=None, **options) 保留原接口。

右键菜单默认窗口为100，自定义参数使用 Python API 或 main()。更新菜单代码需重新加载插件或重启 IDA。生成脚本提供 Frida RPC status()/stop()，运行时模块基址应对应 IDA imagebase。

## 验证

```powershell
python test_entry_trace.py
python D:\IDA\plugins\entry_trace.py --help
```

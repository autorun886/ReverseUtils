# IDA Export CLI

本仓库用于在当前 Windows 环境里无界面调用 IDA，导出一个本地二进制的反编译快照。已经验证可用的本机配置：

- IDA: `D:\IDA`
- Python: `py -3.11`
- 入口目录: `C:\Users\24480\Desktop\reverse\utils\ida-export-cli

## 命令行

```powershell
cd C:\Users\24480\Desktop\reverse\utils\ida-export-cli

$env:IDADIR = "D:\IDA"
$env:PATH = "D:\IDA;" + $env:PATH
$env:PYTHONPATH = "$PWD\src"

py -3.11 -m cli `
  "C:\Users\24480\Desktop\reverse\utils\myctf\libkctf.so" `
  -o "C:\Users\24480\Desktop\reverse\utils\ida-export-smoke\libkctf.so.ida-export"
```

成功时会打印输出目录。默认输出目录是 `<INPUT>.ida-export`，指定 `-o` 时使用指定目录。已有输出只会在新结果完整校验通过后被替换。

## Python 接口

```powershell
cd C:\Users\24480\Desktop\reverse\utils\ida-export-cli

$env:IDADIR = "D:\IDA"
$env:PATH = "D:\IDA;" + $env:PATH
$env:PYTHONPATH = "$PWD\src"
```

```python
from api import export_binary

result = export_binary(
    r"C:\Users\24480\Desktop\reverse\utils\myctf\libkctf.so",
    r"C:\Users\24480\Desktop\reverse\utils\ida-export-smoke\libkctf.so.api-export",
)

print(result.output_path)
print(result.complete_marker)
print(result.manifest["status"])
print(result.manifest["counts"])
```

`export_binary()` 返回：

- `output_path`: 发布后的导出目录
- `complete_marker`: `COMPLETE` 文件内容，正常为 `schema=3`
- `manifest`: 解析后的 `manifest.json`

## 运行环境说明

实际导出会由 launcher 启动 worker 子进程，并在 worker 入口导入 `idapro`。在 Windows 上这一步会加载 `D:\IDA\idalib.dll` 以及同目录的依赖 DLL，因此建议在同一个 PowerShell 进程里设置：

```powershell
$env:IDADIR = "D:\IDA"
$env:PATH = "D:\IDA;" + $env:PATH
$env:PYTHONPATH = "$PWD\src"
```

如果命令输出类似 `IDA worker exited with status 2`，但 `task.log` 里只有 `ida-export-cli: launcher started`，通常表示 worker 在进入项目逻辑前加载或初始化 `idapro` 失败。先用下面的最小命令确认 IDA Python 运行时：

```powershell
$env:IDADIR = "D:\IDA"
$env:PATH = "D:\IDA;" + $env:PATH
$env:PYTHONPATH = "D:\IDA\idalib\python;$PWD\src"
py -3.11 -c "import idapro; print('idapro ok')"
```

受限沙箱可能会拦截 IDA 原生 DLL 的加载；在正常本机进程中确认 `idapro ok` 后，再运行导出命令。

## 输出检查

```powershell
$out = "C:\Users\24480\Desktop\reverse\utils\ida-export-smoke\libkctf.so.ida-export"

Get-Content "$out\COMPLETE"

$m = Get-Content -Raw "$out\manifest.json" | ConvertFrom-Json
$m.status
$m.schema_version
$m.counts
```

一次成功导出至少应该有：

- `COMPLETE`

## 代码入口

- `src\api.py`: Python 接口 `export_binary()`
- `src\cli.py`: 命令行入口
- `src\launcher.py`: worker 启动、watchdog、发布
- `src\worker.py`: 初始化 idalib 并执行导出
- `src\exporter.py`: 写出快照内容
- `src\layout.py`: 校验输出目录

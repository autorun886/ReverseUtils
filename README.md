# utils

逆向分析常用工具、IDA 插件与 Android 动态分析脚本集合。各工具独立使用，依赖和运行环境以对应目录的说明为准。

## 工具一览

| 目录 | 来源 | 用途 / 文档 |
| --- | --- | --- |
| [GAMBA/](GAMBA/) | [DenuvoSoftwareSolutions/GAMBA](https://github.com/DenuvoSoftwareSolutions/GAMBA) | 混合布尔算术（MBA）表达式化简，见 [README](GAMBA/README.md) |
| [deflat/](deflat/) | [cq674350529/deflat](https://github.com/cq674350529/deflat) | 基于 angr 的 OLLVM 控制流平坦化与虚假控制流还原，见 [README](deflat/README.md) |
| [deflat-angr/](deflat-angr/) | [Qmeimei10086/deflat-angr](https://github.com/Qmeimei10086/deflat-angr) | 查找真实块、分析块关系并修补控制流，见 [README](deflat-angr/README.md) |
| [eBPF/](eBPF/) | [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz)、[LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) | Android 堆栈追踪、DEX / SO 转储与修复；见 [stackplz 常用命令](eBPF/stackplz-常用命令.md)、[eBPFDexDumper 常用命令](eBPF/eBPFDexDumper-常用命令.md) |
| [frida-script/](frida-script/) | 自研 / 收集 | 观察 SO 加载、`dlsym` 与 `pthread_create`；含原版 Frida 脚本、rustfrida 适配脚本和 Python 启动器，见 [README](frida-script/README.md) |
| [frida_dump/](frida_dump/) | [lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump) | 运行时转储 Android DEX / SO，见 [README](frida_dump/README.md) |
| [ida-export-cli/](ida-export-cli/) | [OrientalGlass/ida-export-cli](https://github.com/OrientalGlass/ida-export-cli) | 通过 IDA idalib 无界面导出反编译快照，提供 CLI 与 Python 接口，见 [README](ida-export-cli/README.md) |
| [ida-tracecraft/](ida-tracecraft/) | 仓库内维护 | 从 IDA 数据库生成 Frida Stalker / Interceptor 脚本，支持多实例、条件 Hook 和离线快照，见 [中文说明](ida-tracecraft/README.md)、[English](ida-tracecraft/README.en.md) |
| [IDA-Plugins/](IDA-Plugins/) | 自研 / 收集 | IDA 插件集合，包括入口追踪、D810、Keypatch、Patching、FindCrypt、LazyIDA、Dereferencing、DataExportPlus 等 |
| [rustfrida/](rustfrida/) | [kkkbbb/rustFrida](https://github.com/kkkbbb/rustFrida) | Android ARM64 动态分析工具及配套文件；见 [JS API](rustfrida/JS_API.md)、[使用注意事项](rustfrida/NOTES.md) |

`brpatch` 已独立维护于 [autorun886/brpatch](https://github.com/autorun886/brpatch)，本仓库不再跟踪该目录。

## 按任务选择

- **反混淆**：MBA 表达式用 `GAMBA`；OLLVM 控制流还原用 `deflat` / `deflat-angr`。
- **动态分析**：观察加载与符号解析用 `frida-script`；从 IDA 生成函数追踪和参数 Hook 用 `ida-tracecraft`。
- **转储与追踪**：Frida 转储用 `frida_dump`；eBPF 堆栈追踪与转储用 `eBPF`。
- **批量导出**：通过 `ida-export-cli` 生成可供后续分析的反编译快照。
- **IDA 交互分析**：按需选用 `IDA-Plugins` 中的插件；Tracecraft 的安装入口是 `ida-tracecraft/entry_trace.py`。

## 快速开始

### 使用 rustfrida Hook 脚本

在仓库根目录执行：

```powershell
# 默认 spawn，并加载 dlsym、pthread_create、SO 加载三个观察脚本
python .\frida-script\run_rustfrida.py -n com.example.app

# 只加载 dlsym，附加已运行进程，同时保存日志
python .\frida-script\run_rustfrida.py -n com.example.app --attach --only dlsym -o hooks.log
```

需要 Python 3.9+、PATH 中的 `adb`、已连接的 ARM64 Android 设备及可用的 `su -c`。若设备 shell 已是 root，可传入 `--no-su`。启动器默认使用本仓库 `rustfrida/rustfrida`，更多参数见 [脚本说明](frida-script/README.md)。

### 从 IDA 生成 Frida 追踪脚本

将 `ida-tracecraft/entry_trace.py` 放入 IDA 的 `plugins` 目录，重启 IDA 并打开目标数据库。保留仓库中的副本作为命令行入口：

```powershell
python .\ida-tracecraft\entry_trace.py -h
python .\ida-tracecraft\entry_trace.py instances
python .\ida-tracecraft\entry_trace.py --input "D:/samples/libsample.so" --mode full -o trace.js
frida -U -f com.example.app -l trace.js
```

支持 `full`、`window`、`history`、`hooks`、`selected`、`regex`、`callers`、`callees` 八种模式。ARM64 Stalker 追踪要求 Frida 17.10+；模式与参数见 [Tracecraft 文档](ida-tracecraft/README.md)。

## 使用说明

- 本仓库包含源码、脚本及部分预编译工具，无统一安装步骤；先阅读所选工具的文档，再配置依赖。
- `IDA-Plugins` 中的插件对 IDA、Python、Qt 和 Hex-Rays 版本的要求各不相同，按需安装。
- `rustfrida` 的 JS 接口与原版 Frida 存在差异；原版脚本位于 `frida-script/`，适配版本位于 `frida-script/rustfrida/`。
- QBDI helper 与 KPM 等配套组件是否需要加载，取决于使用功能；版本和环境注意事项见 [rustfrida/NOTES.md](rustfrida/NOTES.md)。
- 第三方工具的版权与许可遵循各自项目及目录中的声明。

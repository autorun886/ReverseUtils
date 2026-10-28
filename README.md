# utils

逆向常用工具与脚本集合

## 工具一览

| 目录 / 文件 | 来源 | 简介 | 用处 |
| --- | --- | --- | --- |
| `GAMBA/` | [DenuvoSoftwareSolutions/GAMBA](https://github.com/DenuvoSoftwareSolutions/GAMBA) | 通用混合布尔算术（MBA）表达式化简器，基于 SiMBA 迭代化简线性子表达式 | 还原被 MBA（不透明谓词、数据流混淆）保护的程序，配合 Z3 校验化简结果 |
| `deflat/` | [cq674350529/deflat](https://github.com/cq674350529/deflat) | 基于 angr 的 OLLVM 反混淆脚本，含 `flat_control_flow`（平坦化）与 `bogus_control_flow`（虚假控制流） | 去除 OLLVM 控制流平坦化 / 虚假控制流，恢复可读控制流 |
| `deflat-angr/` | [Qmeimei10086/deflat-angr](https://github.com/Qmeimei10086/deflat-angr) | 基于 angr 符号执行对抗 OLLVM 的脚本集（`find_all_block.py` / `find_block_relation.py` / `patch_all.py`） | 按真实块查找、梳理块关系并 patch，还原变异 OLLVM 控制流 |
| `eBPF/stackplz` | [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz) | 基于 eBPF 的 Android 堆栈追踪工具 | arm64 syscall trace、uprobe hook 动态库、硬件断点，打印参数 / 调用栈 / 寄存器 |
| `eBPF/eBPFDexDumper-arm64` | [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) | 基于 eBPF 与进程内存读取的 Android 内存脱壳工具（ARM64） | 转储并修复 DEX 与 native `.so`，恢复动态注册的 JNI 符号名 |
| `frida-script/` | 自研 / 收集，无公开仓库 | Frida 脚本合集（`hook_dlsym.js`、`hook_pthread_create.js`、`hook_so_load.js`） | Hook `dlopen` / `dlsym` / `pthread_create` 等，观察 so 加载与调用来源 |
| `frida_dump/` | [lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump) | Frida dump dex / so 工具集 | 运行时 dump Android 的 DEX（含 `dexCache_dump.js`）与内存中的 `.so` 并修复 |
| `ida-export-cli/` | [OrientalGlass/ida-export-cli](https://github.com/OrientalGlass/ida-export-cli) | 无界面调用 IDA 导出反编译快照的 CLI / Python 接口 | 批量、自动化导出二进制反编译结果，方便让 AI 全自动处理 |
| `wxshadow/rustfrida` | [kkkbbb/rustFrida](https://github.com/kkkbbb/rustFrida) | Rust 编写的 Frida 替代实现 | Android ARM64 下的 Native / Java Hook、JNI 操作、QBDI trace，支持无痕 hook |
| `wxshadow/wxshadow.kpm`、`wxshadow/hide-so.kpm`、`wxshadow/wxshadow_client` | [kkkbbb/mkpms](https://github.com/kkkbbb/mkpms) | 基于内核页表 shadow 机制的无痕 hook KPM 模块及配套客户端 | 无痕 probe / inline hook、隐藏 so，配合 rustFrida 的 `Hook.WXSHADOW` 模式使用 |
| `brpatch/` | 自研，基于 `wxshadow/rustfrida` | 记录 Android `.so` 的寄存器间接转移（`br xN` / `blr xN`），目标唯一的站点离线还原成 `b` / `bl`；`ollvm.py` 纯静态识别 OLLVM 风格控制流平坦化并一键还原安全子集 | 还原混淆控制流，配合反调试绕过使用（见目录内 README） |

> `wxshadow/JS_API.md` 整理自 [rustFrida README 的 JS API 参考](https://github.com/kkkbbb/rustFrida#js-api-%E5%8F%82%E8%80%83)，是 rustFrida 的 JS 接口速查。

## 分类说明

- **反混淆**：`GAMBA`（MBA 化简）、`deflat` / `deflat-angr`（OLLVM 控制流还原）
- **动态分析**：`frida-script`、`frida_dump`、`rustfrida`、`wxshadow`
- **脱壳 / 追踪**：`eBPF/stackplz`、`eBPF/eBPFDexDumper-arm64`
- **自动化分析**：`ida-export-cli`

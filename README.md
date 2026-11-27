# 逆向工具与脚本推荐

按当前目录中的独立工具归类，项目内部的模块与依赖合并列出。GitHub 链接指向上游项目；本地副本可能包含适配或修改，不代表与上游版本完全一致。整理日期：2026-11-27。

## Android 分析与转储

| 工具 / 本地位置 | GitHub 地址 | 简短介绍 |
| --- | --- | --- |
| frida_dump：`frida_dump/` | [lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump) | 使用 Frida 在运行时转储 DEX 和 SO，包含按类加载、内存扫描等方式提取 DEX 的脚本。 |
| rustFrida：`rustfrida/` | [kkkbbb/rustFrida](https://github.com/kkkbbb/rustFrida) | 面向 Android ARM64 的动态分析工具，提供 JavaScript Hook 接口；本地附有 API 说明和使用笔记。 |
| stackplz：`eBPF/` | [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz) | 基于 eBPF 的 Android 堆栈追踪工具，适合观察函数调用、系统调用和参数。 |
| eBPFDexDumper：`eBPF/` | [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) | 基于 eBPF 的 Android DEX 转储工具，本地目录附有常用命令说明。 |

## 反混淆

| 工具 / 本地位置 | GitHub 地址 | 简短介绍 |
| --- | --- | --- |
| GAMBA：`GAMBA/` | [DenuvoSoftwareSolutions/GAMBA](https://github.com/DenuvoSoftwareSolutions/GAMBA) | 化简混合布尔算术（MBA）表达式，帮助理解被算术与位运算混淆的逻辑。 |
| deflat-angr：`deflat-angr/` | [Qmeimei10086/deflat-angr](https://github.com/Qmeimei10086/deflat-angr) | 基于 angr 分析真实基本块、恢复块间关系并修补平坦化控制流，入口包括 `find_all_block.py`、`find_block_relation.py` 和 `patch_all.py`。地址来自本仓库 README，本次网页访问未完成核实。 |
| D-810：`IDA-Plugins/D810.py`、`d810/` | [zhkl0228/d810](https://github.com/zhkl0228/d810)（GitHub 分支） | 通过优化 Hex-Rays 微码进行反混淆，包含表达式化简和控制流还原规则。原项目位于 [eshard/d810（GitLab）](https://gitlab.com/eshard/d810)，所列 GitHub 分支供参考，本地副本的具体来源分支待确认。 |

## IDA Python 插件

以下本地位置均相对于 `IDA-Plugins/`。

| 插件 / 本地位置 | GitHub 地址 | 简短介绍 |
| --- | --- | --- |
| FindCrypt：`findcrypt3.py`、`findcrypt3.rules` | [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) | 使用 YARA 规则识别密码算法常量及其他特征，辅助定位加密相关代码。 |
| Keypatch：`keypatch.py` | [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) | 基于 Keystone 的多架构汇编修补插件，支持指令修改、区域填充和搜索。 |
| Patching：`patching.py`、`patching/` | [gaasedelen/patching](https://github.com/gaasedelen/patching) | 提供交互式汇编修改、补丁预览和保存功能，方便在 IDA 中编辑二进制。 |
| LazyIDA：`LazyIDA.py` | [L4ys/LazyIDA](https://github.com/L4ys/LazyIDA) | 集成数据转换、数据提取等便捷操作，减少 IDA 中的重复操作。 |
| deREferencing：`dereferencing.py`、`dereferencing/` | [danigargu/deREferencing](https://github.com/danigargu/deREferencing) | 增强调试时的寄存器和栈视图，展示指针解引用后的内容。 |
| DataExportPlus：`DataExportPlus.py` | [Krietz7/IDA-DataExportPlus](https://github.com/Krietz7/IDA-DataExportPlus) | 增强选中数据的导出，支持数据类型、进制、大小端以及 C / Python 变量等格式。 |
| Auto Enum：`enumlib/` | [junron/auto-enum](https://github.com/junron/auto-enum) | 自动识别标准函数参数中的枚举值，提升反编译代码的可读性。 |
| iOS Helper：`ida_plugin_stub.py` | [yoavst/ida-ios-helper](https://github.com/yoavst/ida-ios-helper) | 辅助 iOS、Objective-C 和内核代码分析；本地仅包含加载入口，实际功能依赖 `ida-ios-helper` Python 包。 |

## 本仓库维护及来源说明

| 脚本 / 位置 | 地址 | 简短介绍 |
| --- | --- | --- |
| Frida Hook 脚本：`frida-script/` | [autorun886/ReverseUtils](https://github.com/autorun886/ReverseUtils/tree/main/frida-script)（本仓库） | 观察 SO 加载、`dlsym` 和 `pthread_create`，包含原版 Frida 脚本、rustFrida 适配版本及 Python 启动器；未确认独立上游。 |
| IDA 追踪脚本：`IDA-Plugins/entry_trace.py` | [autorun886/ReverseUtils](https://github.com/autorun886/ReverseUtils/blob/main/IDA-Plugins/entry_trace.py)（本仓库） | 从 IDA 函数信息生成 Frida 追踪或 Hook 脚本，支持全模块、窗口、历史及名称匹配模式；未确认独立上游。 |
| AI 分析导出：`IDA-Plugins/INP.py` | [autorun886/ReverseUtils](https://github.com/autorun886/ReverseUtils/blob/main/IDA-Plugins/INP.py)（本仓库） | 导出反编译结果、反汇编、字符串、内存及导入导出信息，供后续分析使用；独立上游来源待确认。 |
| IDA Feeds：`IDA-Plugins/ida_feeds/` | [Hex-Rays 官方说明](https://docs.hex-rays.com/9.0/user-guide/plugins/plugins-shipped-with-ida/ida-feeds) | IDA 随附的 FLIRT 签名管理工具，本地代码还包含 Rust 签名生成功能；未确认独立 GitHub 源码仓库。 |
| Bochs 配套脚本：`IDA-Plugins/bochs/` | IDA 随附组件，未确认独立 GitHub 源码仓库 | 为 IDA 的 Bochs 调试器提供启动逻辑及部分 Windows API 模拟。 |

这里只整理脚本及其所属项目；IDA 自带 DLL、Qt 运行库、缓存与内嵌依赖未逐一列出。

## 补充推荐

其他值得关注的逆向分析项目：

| 项目 | GitHub 地址 | 简短介绍 |
| --- | --- | --- |
| ASC | [MG1937/ASC](https://github.com/MG1937/ASC) | 面向 Agent 和移动研究人员的轻量 Android 反编译工具。 |
| unidbg 修改版 | [LunFengChen/unidbg](https://github.com/LunFengChen/unidbg) | 基于 unidbg 增加实用功能的修改版，侧重 trace 加速及减少部分环境补全工作。 |
| xdec | [zhuzhu-Top/xdec](https://github.com/zhuzhu-Top/xdec) | 以库为核心的可编程反编译与去虚拟化框架，将 AArch64 机器码或自定义 VM 字节码转换为 SSA 中间表示，支持 OLLVM 控制流还原、MBA 化简及 C / Objective-C 输出，并提供 Python 绑定和 MCP 服务。 |

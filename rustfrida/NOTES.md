# rustfrida / wxshadow 使用注意事项

> 面向本目录 `rustfrida` + `libagent.so` + `libqbdi_helper.so` 在 ARM64 Android 上的使用。
> 通用 API 见同目录 `JS_API.md`；本文件只记易错点与通用规避手法，不含具体目标信息。

## 1. 版本与环境一致性

* 三个文件必须**整套同版本**使用；只换一个往往表现为难定位的异常。
* `libagent.so` 是**内嵌在 rustfrida 二进制里**的：单独 push 到设备不改变行为，只能整体替换或重建。
* `libqbdi_helper.so` 是 `qbdi.*` 的后端，必须让 linker 能按名字找到（`/data/local/tmp` 或 app 的 native lib 目录）。
  **缺它时 `qbdi.newVM()` 表现为挂死，而不是报错。**
* 常见构建问题：`Loader link 失败: unsupported relocation type: 1031`
  （agent 内含 `R_AARCH64_TLSDESC`，loader 不支持）。只能改构建解决
  （避免 `thread_local!`，或加 `-C target-feature=-tlsdesc` 之类），改二进制文件无效。

## 2. 运行方式

```sh
tail -f /dev/null | /data/local/tmp/rustfrida \
    -f <pkg> -l /data/local/tmp/x.js -o /data/local/tmp/x.log
```

* **必须保持 stdin 打开**，否则 pty 关闭会把进程一起带走。
* spawn 到应用真正起来需要十几到二十几秒，不要过早判死。
* 脚本加载期进程处于**暂停**状态：需要运行环境的初始化（如 `qbdi.newVM()`）应放到进程已恢复的时机
  （如 `dlopen` 的 `onLeave`），否则容易超时。
* `/data/local/tmp` 下文件的 SELinux 上下文通常是 `shell_data_file`，`untrusted_app` 可能无权 mmap
  → `chcon u:object_r:apk_data_file:s0`，或使用 `su -mm`（全局命名空间）。

## 3. 目标自带反调试时

若目标库在加载期起了 `ptrace` / `fork` 之类的反调试，凡是会向目标进程投递 **SIGTRAP** 的手段都会被破坏：

* 典型症状：attach 报 `EPERM: 暂停线程失败`；spawn 后应用秒退或 `SIGSEGV`（`pc == fault addr`）；
  uprobe / 硬件断点一命中就跳飞（`crash_dump64: already traced by ...`）。
* 通用处理：**先关掉反调试再注入**（例如 bind-mount 覆盖已安装的 so，把反调试线程入口改成 `ret`）。
* 顺序要求：**先 `am force-stop`，再 mount，再启动应用**（库在启动时 mmap，运行中 mount 无效）。
* 收尾：`umount` + `force-stop` + 结束 hook 进程。
  注意 `umount /data/app/~~*/...` 的 glob 在引号内不展开，要用 `pm path` 动态取路径。
* 定位挂起时（不杀进程）：
  ```sh
  debuggerd -b <pid>                  # 全线程栈，可看出是否停在动态链接器的构造器阶段
  cat /proc/<pid>/task/<tid>/syscall  # running=用户态空转；futex=在等锁
  ```

## 4. JS 环境并非完整 QuickJS（易错清单）

| 项 | 表现 |
| --- | --- |
| `Stalker` | 可能未导出 → 没有指令级 trace，只能用 QBDI |
| `setTimeout` / `setInterval` | 可能未导出 → 周期轮询只能忙等或用 hook 触发 |
| `Thread.backtrace` | 可能未导出（无 `Thread`） |
| `NativeCallback` | 可能未导出 → 无法用原始 QBDI C API 注册 JS 回调 |
| `typeof x` | 对**非原始值**可能一律返回 `"string"`，不可用于类型判断 |
| `hook()` / `recompHook()` | 可能注册成功但**回调从不触发**，不能当 `Interceptor.attach` 的替代 |
| `CModule` | 能编译，但导出符号不能直接当 JS 函数调用，须先包 `NativeFunction` |
| `Hook` 常量 | `Hook{NORMAL:0, WXSHADOW:1, RECOMP:2}` |

建议：动手前先用一行日志探明当前环境有哪些能力，再决定方案，不要照搬文档。

## 5. Hook 地址的选择

* **不要 hook 分支指令站点**（`bl` / `b` 等）：会破坏目标路径逻辑，表现为"挂上后该路径不再命中"。
* **不要 hook 极高频函数**：命中几次后进程崩溃。
* 可安全 hook 的通常是普通取数 / 判断指令。
* 要对某地址做 QBDI trace 时，**先 `Interceptor.detachAll()`**，否则与 QBDI 转译冲突崩溃。

## 6. QBDI Trace 要点

`JS_API.md` §8 的示例是 2 参数，**实际 `registerTraceCallbacks` 取 3 个参数**
（vm / 目标函数地址 / 输出目录）：

```js
var vm = qbdi.newVM();
qbdi.allocateVirtualStack(vm, 1 << 20, "qs");
qbdi.registerTraceCallbacks(vm, targetFnAddr, outputDir);
qbdi.setGPR(vm, 0, a0);            // xN 的 reg id 就是 N；LR=30, SP=31, FLAG=32, PC=33
qbdi.call(vm, targetFnAddr);
qbdi.unregisterTraceCallbacks(vm);
qbdi.destroyVM(vm);
```

* **`outputDir` 必须是 app 自己可写的目录**；写公共目录会失败：`Permission denied (os error 13)`。
  用 app 私有目录，并保证属主与 SELinux 标签正确。
* 产物：事件流分片 + 动态转译块分片。
* 分片格式为 `[u64 seq][u32 len][len 字节的 length-delimited protobuf 事件]`；
  按裸 protobuf 解析会**漏掉大量事件**，分析前先核对条数。
* 常见事件类型：指令地址、内存访问 `{inst_addr, access_addr, value, size}`、外部返回、
  动态块、寄存器快照、元数据 `{module_path, module_base}`。
* ⚠️ **元数据里的 `module_base` 不可信**，不要直接当基址；用多条不变量交叉推算
  （例如"某指令读到的字面量地址 − 该字面量的静态偏移 = 运行时基址"，多组吻合才锁定）。

## 7. 排障速查

| 症状 | 可能原因 | 处理 |
| --- | --- | --- |
| `EPERM: 暂停线程失败` | 目标自带 tracer 占用 | 先绕反调试，见 §3 |
| spawn 后秒退 / `pc == fault addr` | SIGTRAP 与目标自身 tracer 冲突 | 同上 |
| `unsupported relocation type: 1031` | agent 含 `R_AARCH64_TLSDESC` | 换 / 重建整套二进制 |
| `qbdi.newVM()` 挂死、无 tombstone | 缺 helper，或 helper 构造期自旋死锁 | 换整套；用 §3 的方法看是否停在链接器构造器阶段 |
| 回调注册成功但从不触发 | 回调 ABI / 签名不匹配，或环境缺 `NativeCallback` | 用 helper 提供的回调桥；先探测环境能力 |
| trace 目录 `Permission denied (13)` | 输出目录不可写 | 换成 app 私有目录 |
| `setInterval is not defined` 之类 | JS 环境缺件 | 换实现方式（忙等 / hook 触发） |
| hook 后目标路径不再命中 | 挂在了分支指令站点 | 换非分支指令地址 |

## 8. kpm 模块（未验证）

本目录的 `wxshadow.kpm` / `hide-so.kpm` 是 KernelSU 侧模块，对应 `Hook.WXSHADOW`(=1) /
`Interceptor` 的 mode 参数、`ptr.writeBytes(bytes, 1)` 这类"内存读取仍见原字节"的隐形 patch，
以及 soinfo 隐藏。使用前先在 KernelSU 中确认加载状态；并非所有场景都需要
（仅做 bind-mount 级补丁时可以不依赖）。

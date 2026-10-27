# eBPFDexDumper 常用命令

用于采集 Android 内存中的 DEX、SO，以及修复转储文件、收集动态注册 JNI 名称。

以下 `adb` 命令在电脑执行；`./eBPFDexDumper` 命令在手机的 root shell 中执行。将 `com.example.app` 换成实际包名，示例 UID 和偏移也需替换。

## 1. 部署与帮助

```powershell
adb devices
adb push .\eBPFDexDumper /data/local/tmp/
adb shell
```

进入手机后：

```sh
su
cd /data/local/tmp
chmod 755 eBPFDexDumper
uname -r
./eBPFDexDumper --help
./eBPFDexDumper dump --help
./eBPFDexDumper dumpso --help
./eBPFDexDumper fix --help
./eBPFDexDumper fixso --help
```

运行环境为 ARM64 Android，采集需要 root 和相应内核功能。上游测试环境为 Android 13/16，其他系统需实际检查兼容性。

## 2. DEX 采集

```sh
# 按包名采集，指定输出位置
./eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out

# 按应用 UID 采集：这里不是 PID
./eBPFDexDumper dump -u 10244 -o /data/local/tmp/dex_out

# 同时显示方法执行信息
./eBPFDexDumper dump -n com.example.app -t

# 保留现有 OAT 优化文件
./eBPFDexDumper dump -n com.example.app --no-clean-oat

# 只采集，结束后再单独修复
./eBPFDexDumper dump -n com.example.app --no-auto-fix
```

默认会清理目标应用 OAT，并在结束后自动修复 DEX。开始采集后启动或重新进入应用，操作需要覆盖的页面，再按 `Ctrl+C` 正常结束，等待写盘与修复完成。JSON 方法数据在正常退出或收到 SIGINT/SIGTERM 时保存，避免直接强杀。

```sh
# 查询应用 UID 与进程 PID
cmd package list packages -U com.example.app
pidof com.example.app

# 单独修复已有 DEX 目录
./eBPFDexDumper fix -d /data/local/tmp/dex_out
```

## 3. SO 采集与修复

先启动应用，确保目标库已加载。

```sh
# 采集应用已映射的 SO，默认自动修复
./eBPFDexDumper dumpso -n com.example.app -o /data/local/tmp/so_out

# 按库路径子串筛选
./eBPFDexDumper dumpso -n com.example.app -l libnative.so

# 持续观察 120 秒，捕获后续加载或内容变化的模块
./eBPFDexDumper dumpso -n com.example.app --watch --watch-timeout 120

# 每 2 秒扫描，直到 Ctrl+C
./eBPFDexDumper dumpso -n com.example.app --watch --watch-interval 2 --watch-timeout 0

# 只采集正常文件映射，跳过匿名 ELF 扫描
./eBPFDexDumper dumpso -n com.example.app --no-anon

# 同时包含系统分区中的库
./eBPFDexDumper dumpso -n com.example.app --include-system

# 单独修复已有 SO 目录
./eBPFDexDumper fixso -d /data/local/tmp/so_out
```

`dumpso` 直接读取进程内存，不依赖 DEX 采集所用的 eBPF 探针；仍需要读取目标进程的权限。

## 4. JNI 名称与 ART 参数

在 `dump` 运行期间触发应用的 JNI 注册，输出目录会生成对应模块的 `jni_symbols_*.txt`。名称以实际生成文件为准：

```sh
ls /data/local/tmp/dex_out/jni_symbols_*.txt
./eBPFDexDumper fixso -d /data/local/tmp/so_out -s /data/local/tmp/dex_out/jni_symbols_libnative.txt
```

ART 默认路径或自动定位不匹配时，按当前设备的 libart 调整：

```sh
./eBPFDexDumper dump -n com.example.app -l /apex/com.android.art/lib64/libart.so

# 以下仅为参数格式示例，偏移必须由当前 libart 分析得到
./eBPFDexDumper dump -n com.example.app --execute-offset 0x12345 --nterp-offset 0x67890
./eBPFDexDumper dump -n com.example.app --register-natives-offset 0x12345
```

## 5. 导出结果

退出手机 shell 后，在电脑执行：

```powershell
adb pull /data/local/tmp/dex_out .\dex_out
adb pull /data/local/tmp/so_out .\so_out
```

| 位置 | 内容 |
| --- | --- |
| `dex_out/dex_*.dex` | 原始 DEX |
| `dex_out/*_code.json` | 运行期间采集的方法字节码 |
| `dex_out/fix/*_fix.dex` | 修复后的 DEX |
| `dex_out/jni_symbols_*.txt` | JNI 名称与偏移 |
| `so_out/so_*.so` | 原始 SO |
| `so_out/fix/*_fix.so` | 修复后的 SO |

若 `adb pull` 报权限错误，先在 root shell 中给所需输出目录设置可读取权限，再重试。

## 6. 常见问题

- 没有 DEX：核对包名/UID，确认采集时应用实际执行了相关方法；观察 ART 定位和探针加载日志。
- SO 缺失：确认库已加载，使用 `--watch` 等待；检查 `-l` 是否过滤过多。
- 修复结果不完整：扩大页面与功能覆盖范围，保留原始 DEX 和对应 JSON；采集结果取决于运行时实际出现的数据。
- BPF 加载报错：检查 root、内核配置与 Android/ART 版本，参数语法以设备上的 `--help` 为准。

## 参考与核对范围

依据 [上游中文说明](https://github.com/LLeavesG/eBPFDexDumper/blob/master/README.md) 整理，核对日期：2026-10-27。本地二进制含 `watch-timeout`、`no-clean-oat`、`register-natives-offset` 等参数字符串；本次未连接 Android 设备运行验证。

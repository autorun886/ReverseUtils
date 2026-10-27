# stackplz 常用命令

用于 Android 系统调用追踪、用户态函数探针、调用栈与寄存器观察。

本文使用新版的 `-s` / `-l` / `-w` 语法。将包名 `com.example.app`、PID `12345`、TID `12346` 和偏移换成实际值。电脑执行 `adb`，手机 root shell 执行 `./stackplz`。

## 1. 部署

```powershell
adb devices
adb push .\stackplz /data/local/tmp/
adb shell
```

手机中执行：

```sh
su
cd /data/local/tmp
chmod 755 stackplz
uname -r
./stackplz --help
```

新版上游要求 root、内核 5.10+，用户态函数追踪针对 64 位库。实际可用功能取决于内核配置。v3.0.1 之前的新语法版本需先执行 `./stackplz --prepare`；当前版本是否需要，以其帮助和启动提示为准。

## 2. 系统调用追踪

```sh
# 文件访问
./stackplz -n com.example.app -s openat,read,write,close -o file.log

# 网络调用与数据
./stackplz -n com.example.app -s connect,sendto,recvfrom --dumphex -o net.log

# 追加调用栈、寄存器
./stackplz -n com.example.app -s openat --stack --regs -o openat.log

# 文件、网络分组，排除高频调用
./stackplz -n com.example.app -s '%file,%net' --no-syscall openat,recvfrom -o group.log

# 全部系统调用，数据量较大
./stackplz -n com.example.app -s all -o all.log
```

先运行追踪，再操作应用触发相关行为；按 `Ctrl+C` 停止。建议先缩小到少量调用，再增加堆栈输出。

## 3. 进程、线程筛选

```sh
pidof com.example.app
cmd package list packages -U com.example.app

# 指定进程
./stackplz -p 12345 -s openat --stack

# 指定 UID
./stackplz -u 10244 -s connect

# 指定线程
./stackplz -p 12345 -t 12346 -s openat

# 排除线程
./stackplz -n com.example.app --no-tid 12346 -s openat

# 包含默认被屏蔽的高频后台线程
./stackplz -n com.example.app -s openat --full-tname
```

PID 在重启应用后会改变；UID 与 PID 含义不同。多目标参数可使用逗号分隔。线程名筛选为 `--tname`，排除为 `--no-tname`，线程名受 16 字节限制。

## 4. 用户态函数追踪

```sh
# libc 字符串函数：参数按字符串读取
./stackplz -n com.example.app -w 'strstr[str,str]' --stack

# 同时观察多个函数
./stackplz -n com.example.app -w 'strstr[str,str]' -w 'open[str,int]' -o libc.log

# 指定应用 SO 和导出符号
./stackplz -n com.example.app -l libnative.so -w 'native_func[ptr,int]' --stack --regs

# 指定 SO 内偏移：0x12340 为示例
./stackplz -n com.example.app -l libnative.so -w '0x12340[ptr,int]' --stack

# libc write：按 x2 的值读取 x1 指向的 buffer
./stackplz -n com.example.app -w 'write[int,buf:x2,int]' --dumphex

# 固定读取 32 字节
./stackplz -n com.example.app -w 'write[int,buf:32,int]' --dumphex
```

未指定 `-l` 时默认使用 libc。`str` 为字符串、`ptr` 为指针值、`int` 为整数、`buf` 为内存数据。参数类型和长度需与实际函数签名一致。

`-w` 中带括号的表达式统一用引号包裹。偏移按工具所需的库内位置填写，先核对 ELF 地址与文件布局，别直接填 ASLR 后的绝对地址。若库名搜索失败，读取 `/proc/12345/maps`，使用实际映射路径作为 `-l`。

## 5. 日志与输出

```sh
# 只写文件
./stackplz -n com.example.app -s openat -o trace.log --quiet

# JSON 格式
./stackplz -n com.example.app -s connect --json -o trace.json

# 输出事件时间与 UID
./stackplz -n com.example.app -s openat --showtime --showuid -o timed.log

# 终端彩色 hexdump
./stackplz -n com.example.app -s sendto --dumphex --color

# 缓冲区调到 16 MiB，缓解丢样
./stackplz -n com.example.app -s connect,sendto,recvfrom -b 16 -o net.log
```

`--showtime` 是开机以来的纳秒时间。日志位于手机当前工作目录；电脑另开终端导出：

```powershell
adb pull /data/local/tmp/trace.log .\trace.log
adb pull /data/local/tmp/net.log .\net.log
```

## 6. 用户态硬件断点

地址和偏移均为示例，需先确定当前目标进程中的位置。

```sh
# 库内执行断点
./stackplz -p 12345 --brk-lib libnative.so --brk 0x12340:x --stack

# 进程绝对地址执行断点
./stackplz -p 12345 --brk 0x7000012340:x --stack --regs
```

断点类型有 `r`、`w`、`rw`、`x`；支持情况受硬件、地址对齐与内核配置影响。

## 7. 常见问题

| 现象 | 检查方法 |
| --- | --- |
| 没有事件 | 核对 PID/UID，触发目标行为；必要时添加 `--full-tname` |
| 函数探针无输出 | 确认 SO 已加载，符号是实际实现，必要时使用准确偏移 |
| 丢样提示 | 减少追踪点和堆栈输出，适当增加 `-b`；内存分配失败时降低数值 |
| 栈信息不足 | 比较 `--stack` 与 `--mstack`，确认目标库展开信息 |
| 参数不认识 | 先查本地 `--help`，核对版本语法 |

旧版 master 使用 `stack` / `syscall` 子命令、`--symbol` / `--offset` 等参数，和本文的新语法有区别，避免混用。

## 参考与核对范围

依据 [上游 dev 版说明](https://github.com/SeeFlowerX/stackplz/blob/dev/README.md) 整理，核对日期：2026-10-27。本地二进制含 `dumphex`、`brk-lib` 等新版参数字符串；本次未连接 Android 设备运行验证。批量配置请参阅 [配置文档](https://github.com/SeeFlowerX/stackplz/blob/dev/docs/CONFIG.md)。

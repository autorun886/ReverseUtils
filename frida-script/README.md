# rustfrida hooks

本目录三个 JS 保留原版 Frida API；`./rustfrida/` 内是专用转换版本，面向 ARM64 Android。
转换依据是相邻 `../rustfrida/JS_API.md` 和配套二进制。

```powershell
# 默认 spawn 包名，加载三个 hook，实时显示输出
python run_rustfrida.py -n com.example.app

# 同时保存本机 UTF-8 日志（覆盖同名文件）
python run_rustfrida.py -n com.example.app -o hooks.log

# 单独加载；-l 可以重复传入
# 简写选择内置脚本（支持多个）
python run_rustfrida.py -n com.example.app --only dlsym
python run_rustfrida.py -n com.example.app --only dlsym so_load

# 全部加载，终端只显示 dlsym 事件；文件日志仍保留全部输出
python run_rustfrida.py -n com.example.app --show dlsym -o hooks.log

# 只加载两个脚本，终端只显示其中一个
python run_rustfrida.py -n com.example.app --only dlsym pthread_create --show pthread_create

# 也可以通过文件路径加载
python run_rustfrida.py -n com.example.app -l ./rustfrida/hook_dlsym.js
python run_rustfrida.py -n com.example.app -l ./rustfrida/hook_so_load.js -l ./rustfrida/hook_pthread_create.js

# 附加已运行的进程；选择 adb 设备
python run_rustfrida.py -n com.example.app --attach -s DEVICE_SERIAL

# 有限时间实测，15 秒后自动结束当前注入会话
python run_rustfrida.py -n com.tencent.ACE.gamesec2026.final -o ace_test.log --duration 15
```

需要 Python 3.9+、PATH 中的 adb、已连接的 ARM64 Android 设备及可用的 `su -c`。
若 adb shell 已经是 root，可用 `--no-su`。`--rustfrida-dir` 可以指定 rustfrida 文件夹。
默认从相邻 `../rustfrida/rustfrida` 推送可执行文件，不需要 pip 依赖。

每次运行创建独立的 `/data/local/tmp/rustfrida-<随机ID>` 目录，自动 push、chmod、启动。
stdin 保持打开，stdout/stderr 以 UTF-8 实时合并显示，`-o` 同时保存启动信息和脚本输出。
`--duration` 从开始接收设备输出时计时，包含注入等待时间。
`--only` 和 `-l` 二选一；`--show` 支持多个名称，只过滤已知 hook 事件，启动信息和错误仍显示。
Ctrl+C 结束当前会话并清理远程目录。退出注入会话对目标应用的具体影响由 rustfrida 决定。
本目录脚本只观察 native 调用，不使用 QBDI，因此无需推送 `libqbdi_helper.so` 或 KPM。

三个 hook 分别输出 dlsym 调用者/句柄/符号/返回地址、pthread_create 调用者、SO 加载路径。
默认合并加载时复用 dlsym 的 android_dlopen_ext 观察器，避免在同一地址重复安装 hook。

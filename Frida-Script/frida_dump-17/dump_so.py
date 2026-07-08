"""
dump_so.py — Frida 17 远程 dump SO 模块 + SoFixer 修复

Usage:
    python dump_so.py                    # 列出所有模块
    python dump_so.py <so_name>          # dump 指定 SO 并自动 fix
"""

import sys
import os
import frida


# SoFixer 二进制在上级目录的 android/ 下
SOFIXER_DIR = os.path.join(os.path.dirname(__file__), '..', 'frida_dump', 'android')
SOFIXER32 = os.path.join(SOFIXER_DIR, 'SoFixer32')
SOFIXER64 = os.path.join(SOFIXER_DIR, 'SoFixer64')

JS_SOURCE = os.path.join(os.path.dirname(__file__), 'dump_so.js')


def fix_so(arch: str, origin_so_name: str, so_name: str, base: str, size: int) -> str:
    """用 SoFixer 修复 dump 出来的 SO 使其可分析"""
    if arch == 'arm':
        os.system(f'adb push {SOFIXER32} /data/local/tmp/SoFixer')
    elif arch == 'arm64':
        os.system(f'adb push {SOFIXER64} /data/local/tmp/SoFixer')
    else:
        print(f'[!] 不支持的架构: {arch}，跳过 fix')
        return so_name

    os.system('adb shell chmod +x /data/local/tmp/SoFixer')
    os.system(f'adb push {so_name} /data/local/tmp/{so_name}')
    os.system(
        f'adb shell /data/local/tmp/SoFixer '
        f'-m {base} -s /data/local/tmp/{so_name} '
        f'-o /data/local/tmp/{so_name}.fix.so'
    )
    fix_name = f'{origin_so_name}_{base}_{size}_fix.so'
    os.system(f'adb pull /data/local/tmp/{so_name}.fix.so {fix_name}')

    # 清理
    for f in [so_name, so_name + '.fix.so', 'SoFixer']:
        os.system(f'adb shell rm -f /data/local/tmp/{f}')

    return fix_name


def read_js_source() -> str:
    with open(JS_SOURCE, 'r', encoding='utf-8') as f:
        return f.read()


def on_message(message, data):
    """Frida 消息回调"""
    if message['type'] == 'send':
        print('[script]', message['payload'])
    elif message['type'] == 'error':
        print('[error]', message.get('description', message))


if __name__ == '__main__':
    ip = input('Please input the target device ip: ').strip()
    device = frida.get_device_manager().add_remote_device(ip)

    # Frida 17: get_frontmost_application 返回 Application 对象
    app = device.get_frontmost_application()
    print(f'[*] Attaching to {app.name} (pid={app.pid})')

    session: frida.core.Session = device.attach(app.pid)
    script = session.create_script(read_js_source())
    script.on('message', on_message)
    script.load()

    if len(sys.argv) < 2:
        # 列出全部模块
        modules = script.exports_sync.allmodule()
        for m in modules:
            print(f'{m["name"]:50s}  @ {m["base"]}  ({m["size"]} bytes)')
    else:
        origin_so_name = sys.argv[1]
        module_info = script.exports_sync.findmodule(origin_so_name)
        print('[module]', module_info)

        base = module_info['base']
        size = module_info['size']

        module_buffer = script.exports_sync.dumpmodule(origin_so_name)
        if module_buffer != -1:
            dump_so_name = f'{origin_so_name}.dump.so'
            with open(dump_so_name, 'wb') as f:
                f.write(module_buffer)

            arch = script.exports_sync.arch()
            fix_so_name = fix_so(arch, origin_so_name, dump_so_name, base, size)
            print(f'[+] Output: {fix_so_name}')

            if os.path.exists(dump_so_name):
                os.remove(dump_so_name)
        else:
            print(f'[-] 未找到模块: {origin_so_name}')

# -*- coding:utf-8 -*-
"""
stalker_trace_so.py — IDA Plugin: 生成 Frida 17 Stalker 追踪脚本

在 Functions 窗口 / 反汇编 / 伪代码中右键 → "stalker trace so" 生成 JS 脚本。
"""

import os
import random
from functools import reduce

import idaapi
import ida_nalt
import idautils
import idc

# ── Frida 17 JS 模板 ──────────────────────────────────────────────

TEMPLATE_JS = r'''
const func_addr = [[func_addr]];
const func_name = [[func_name]];
const so_name = "[so_name]";

/*
    @param print_stack: 是否打印调用栈，默认 false
*/
const PRINT_STACK = false;

/*
    @param print_stack_mode
    - FUZZY:   尽可能多地打印调用栈
    - ACCURATE: 尽可能精确地打印调用栈
    - MANUAL:   如果打印调用栈导致崩溃，用此模式手动打印地址
*/
const STACK_MODE = "FUZZY";

function addrInSo(addr) {
    // Frida 17: Process.enumerateModules() 直接返回数组
    for (const m of Process.enumerateModules()) {
        if (addr.compare(m.base) > 0 && addr.compare(m.base.add(m.size)) < 0) {
            console.log(
                addr.toString(16), "is in", m.name,
                "offset: 0x" + addr.sub(m.base).toString(16)
            );
        }
    }
}

function hookDlopen() {
    // Frida 17: 用 Module.findGlobalExportByName 替代 Module.findExportByName(null, ...)
    const dlopenExt = Module.findGlobalExportByName('android_dlopen_ext');
    if (!dlopenExt) {
        console.log('[-] android_dlopen_ext not found, SO may already be loaded');
        traceSo();
        return;
    }

    Interceptor.attach(dlopenExt, {
        onEnter(args) {
            const path = args[0].readCString();
            if (path && path.includes(so_name)) {
                this.canHook = true;
            }
        },
        onLeave(retval) {
            if (this.canHook) {
                traceSo();
            }
        }
    });
}

function traceSo() {
    let times = 1;
    const module = Process.getModuleByName(so_name);
    const pid = Process.getCurrentThreadId();

    console.log("[Stalker] start tracing", so_name);

    Stalker.exclude({
        base: Process.getModuleByName("libc.so").base,
        size: Process.getModuleByName("libc.so").size
    });

    Stalker.follow(pid, {
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: false
        },
        onReceive(events) {},

        transform(iterator) {
            let instruction = iterator.next();
            do {
                const offset = Number(instruction.address.sub(module.base));
                const idx = func_addr.indexOf(offset);

                if (idx !== -1) {
                    console.log(`call${times}: ${func_name[idx]}`);
                    times += 1;

                    if (PRINT_STACK) {
                        if (STACK_MODE === "FUZZY") {
                            iterator.putCallout((context) => {
                                console.log(
                                    "backtrace:\n" +
                                    Thread.backtrace(context, Backtracer.FUZZY)
                                        .map(DebugSymbol.fromAddress)
                                        .join('\n')
                                );
                                console.log('---------------------');
                            });
                        } else if (STACK_MODE === "ACCURATE") {
                            iterator.putCallout((context) => {
                                console.log(
                                    "backtrace:\n" +
                                    Thread.backtrace(context, Backtracer.ACCURATE)
                                        .map(DebugSymbol.fromAddress)
                                        .join('\n')
                                );
                                console.log('---------------------');
                            });
                        } else if (STACK_MODE === "MANUAL") {
                            iterator.putCallout((context) => {
                                console.log("backtrace:");
                                Thread.backtrace(context, Backtracer.FUZZY)
                                    .map(addrInSo);
                                console.log('---------------------');
                            });
                        }
                    }
                }

                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        },

        onCallSummary(summary) {}
    });

    console.log("[Stalker] follow started on thread", pid);
}

setImmediate(hookDlopen);
'''


# ── IDA 插件逻辑 ──────────────────────────────────────────────────

class UIHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)
        if form_type in (idaapi.BWN_FUNCS, idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM):
            idaapi.attach_action_to_popup(form, popup, "stalkerTraceSo:genJsScript", None)


class GenerateFridaHookScript(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctx.widget_type == idaapi.BWN_FUNCS:
            selected = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection]
        else:
            selected = list(idautils.Functions())
        generate_js_script(selected)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def generate_hook_code(template: str, func_addr: list, func_name: list, so_name: str) -> str:
    """用函数地址/名称填充 JS 模板"""
    replacements = {
        "[func_addr]": ', '.join(func_addr),
        "[func_name]": ', '.join(func_name),
        "[so_name]": so_name,
    }
    return reduce(lambda acc, item: acc.replace(item[0], item[1]), replacements.items(), template)


def generate_js_script(func_list):
    """从 IDA 函数列表生成 Frida 17 Stalker 脚本"""
    func_addr = []
    func_name = []

    for func_ea in func_list:
        # thumb mode: 地址最低位为 1 标记
        if idc.get_sreg(func_ea, "T"):
            func_addr.append(hex(func_ea + 1))
        else:
            func_addr.append(hex(func_ea))
        func_name.append('"{}"'.format(idc.get_func_name(func_ea)))

    so_path, so_name = os.path.split(ida_nalt.get_input_file_path())
    hook_code = generate_hook_code(TEMPLATE_JS, func_addr, func_name, so_name)

    r = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5))
    script_name = f"trace_{so_name.split('.')[0]}_{r}.js"
    save_path = os.path.join(so_path, script_name)

    with open(save_path, "w", encoding="utf-8") as f:
        f.write(hook_code)

    print("Usage:")
    print(f'  frida -U -l "{save_path}" -f [package name]')


class stalker_trace_so_17(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "stalker trace so (Frida 17)"
    help = ""
    wanted_name = "stalker trace so (Frida 17)"
    wanted_hotkey = ""

    def init(self):
        print("[stalker_trace_so_17] plugin loaded.")
        idaapi.register_action(
            idaapi.action_desc_t(
                "stalkerTraceSo:genJsScript",
                "stalker trace so (Frida 17)",
                GenerateFridaHookScript(),
                None,
                None,
                201
            )
        )
        self.ui_hook = UIHook()
        self.ui_hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        generate_js_script(list(idautils.Functions()))

    def term(self):
        pass


def PLUGIN_ENTRY():
    return stalker_trace_so_17()

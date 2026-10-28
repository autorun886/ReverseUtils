# -*- coding: utf-8 -*-
"""IDA -> Frida function-entry tracer: full trace, or a retriggerable window.

HOOK_OFFSETS is an independent empty allowlist for argument/return hooks.
Offsets assume the IDA image base corresponds to the runtime module base.
"""
import json
import os
import traceback

import idaapi
import ida_nalt
import idautils
import idc

MODES = {"full": "Full module trace (default)", "window": "100-entry window from current function"}
ACTION = "entryTrace:export"
WIDGETS = (idaapi.BWN_FUNCS, idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE)
SCRIPT = r'''
'use strict';
const DATA = __DATA__;

// Configure before loading. Android ART/JIT needs interpreter mode while stalking.
if (Process.arch === 'arm64') {
    const [major, minor] = Frida.version.split('.').map(Number);
    if (major < 17 || (major === 17 && minor < 10))
        throw new Error('ARM64 tracing requires Frida server 17.10+; tested with 17.23.3');
}
const JAVA_INTERPRETER = true;     // Android only; slower Java, avoids JIT StackMap failures
const MULTI_THREAD = true;         // false: main thread (full), first trigger thread (window)
const MODE = DATA.mode;             // 'full' (default) or 'window'
const HOOK_OFFSETS = [];            // e.g. ['0x10685b8']; raw args + return ONLY here
const START_OFFSET = DATA.start;    // window trigger, module-relative
const WINDOW_SIZE = 100;            // includes the trigger entry

// Delta-coded offsets keep large IDA databases out of the JS compiler's AST.
const names = new Map(DATA.names);
let previousOffset = 0n;
for (const delta of DATA.deltas.split(',')) {
    if (!delta) continue;
    previousOffset += BigInt('0x' + delta);
    const offset = '0x' + previousOffset.toString(16);
    if (!names.has(offset)) names.set(offset,
        'sub_' + (BigInt(DATA.imagebase) + previousOffset).toString(16).toUpperCase());
}
const threads = new Map(), listeners = [], pending = [];
let moduleBase = null, moduleEnd = null, moduleObserver = null, threadObserver = null;
let running = true, sequence = 0, hookSequence = 0, selectedThread = null;
let scanTimer = null;
function isVmInternal(thread) {
    if (thread.id === Process.id) return false;
    if (/^(HeapTaskDaemon|Jit thread pool|Jit worker|ReferenceQueueD|FinalizerDaemon|FinalizerWatchdog|Signal Catcher|Profile Saver|JDWP|ADB-JDWP)/.test(thread.name || ''))
        return true;
    const entry = thread.entrypoint;
    if (!entry || !entry.routine) return false;
    const module = Process.findModuleByAddress(entry.routine);
    return module !== null && /^libart(d)?\.so$/.test(module.name);
}
function inTarget(address) {
    return moduleBase !== null && address.compare(moduleBase) >= 0 && address.compare(moduleEnd) < 0;
}
function discoverThread(thread) {
    if (MODE !== 'full' || isVmInternal(thread)) return;
    const entry = thread.entrypoint;
    if (thread.id === Process.id || (entry && entry.routine && inTarget(entry.routine)) ||
            (thread.context && inTarget(thread.context.pc))) follow(thread.id);
}
function acceptsThread(tid) {
    if (MULTI_THREAD) return true;
    if (selectedThread === null) selectedThread = MODE === 'full' ? Process.id : tid;
    return tid === selectedThread;
}
const started = Date.now();
function flush() { if (pending.length) console.log(pending.splice(0).join('\n')); }
function emit(line) { pending.push(line); if (pending.length >= 512) flush(); }
function offsetOf(value) { return ptr(value).toString(); }
function label(offset) { return DATA.module + '+' + offset + ' ' + (names.get(offset) || '?'); }
function stamp(tid) { return '+' + String(Date.now() - started).padStart(7) + 'ms T' + tid; }
function codeAddress(offset) {
    const address = moduleBase.add(offset);
    return DATA.thumb ? address.or(1) : address;
}
function excludeOutside() {
    for (const range of Process.enumerateRanges('--x')) {
        const end = range.base.add(range.size);
        if (end.compare(moduleBase) <= 0 || range.base.compare(moduleEnd) >= 0)
            Stalker.exclude(range);
    }
}
function unfollow(tid) {
    const thread = threads.get(tid);
    if (!thread || !thread.following) return;
    thread.following = false;
    Stalker.unfollow(tid);
}
function entry(tid, offset, trigger = false) {
    if (!running || !acceptsThread(tid)) return;
    const thread = threads.get(tid);
    if (!thread) return;
    if (MODE === 'window') {
        if (trigger) {
            thread.remaining = WINDOW_SIZE;
            emit('[window] ' + stamp(tid) + ' RESET ' + WINDOW_SIZE + ' ' + label(offset));
        }
        if (thread.remaining === 0) return;
        --thread.remaining;
    }
    ++thread.hits;
    emit(String(++sequence).padStart(8, '0') + ' ' + stamp(tid) + ' ' + label(offset));
    if (MODE === 'window' && thread.remaining === 0) {
        unfollow(tid);
        emit('[window] ' + stamp(tid) + ' END; waiting for trigger');
        setImmediate(() => Stalker.garbageCollect());
    }
}
function follow(tid) {
    if (!running || !acceptsThread(tid)) return;
    let thread = threads.get(tid);
    if (!thread) {
        thread = { hits: 0, remaining: 0, following: false };
        threads.set(tid, thread);
    }
    if (!running || thread.following) return;
    const base = moduleBase, end = moduleEnd;
    thread.following = true;
    try {
        Stalker.follow(tid, {
            transform(iterator) {
                let instruction;
                while ((instruction = iterator.next()) !== null) {
                    const address = instruction.address;
                    if (address.compare(base) >= 0 && address.compare(end) < 0 &&
                            iterator.memoryAccess === 'open') {
                        const offset = address.sub(base).toString();
                        // The trigger Interceptor records its entry exactly once.
                        if (names.has(offset) && !(MODE === 'window' && offset === START_OFFSET))
                            iterator.putCallout(() => entry(tid, offset));
                    }
                    iterator.keep();
                }
            }
        });
    } catch (error) {
        thread.following = false;
        emit('[error] follow T' + tid + ': ' + error);
    }
}
function hookFunction(offset, logArguments, windowTrigger = false) {
    const callbacks = {
        onEnter(args) {
            if (!running) return;
            if (logArguments) {
                this.id = ++hookSequence;
                this.started = Date.now();
                const values = Array.from({ length: 6 }, (_, i) => args[i].toString());
                emit('[hook #' + this.id + '] ' + stamp(this.threadId) + ' ENTER ' +
                    label(offset) + ' args[0..5]=[' + values.join(', ') + '] caller=' + this.returnAddress);
            }
            if (!windowTrigger || !acceptsThread(this.threadId)) return;
            const tid = this.threadId;
            if (!threads.has(tid))
                threads.set(tid, { hits: 0, remaining: 0, following: false });
            entry(tid, START_OFFSET, true);
            if (threads.get(tid).remaining > 0) follow(tid);
        }
    };
    if (logArguments) callbacks.onLeave = function (value) {
        if (!running || this.id === undefined) return;
        emit('[hook #' + this.id + '] ' + stamp(this.threadId) + ' LEAVE ' +
            label(offset) + ' return=' + value + ' duration=' + (Date.now() - this.started) + 'ms');
    };
    listeners.push(Interceptor.attach(codeAddress(offset), callbacks));
}
function clearModule() {
    if (threadObserver) { threadObserver.detach(); threadObserver = null; }
    if (scanTimer !== null) { clearInterval(scanTimer); scanTimer = null; }
    for (const tid of threads.keys()) unfollow(tid);
    for (const listener of listeners.splice(0)) listener.detach();
    threads.clear();
    selectedThread = null;
    moduleBase = moduleEnd = null;
    Stalker.flush();
    setImmediate(() => Stalker.garbageCollect());
}
const timer = setInterval(flush, 200);
function stop() {
    if (!running) return status();
    running = false;
    if (moduleObserver) { moduleObserver.detach(); moduleObserver = null; }
    clearModule();
    clearInterval(timer);
    emit('[trace] STOP entries=' + sequence + ' hooks=' + hookSequence);
    flush();
    return status();
}
function status() {
    return { running, mode: MODE, multiThread: MULTI_THREAD, selectedThread, entries: sequence, hooks: hookSequence,
        threads: Array.from(threads, ([tid, value]) => ({ tid, ...value })) };
}
if (!['full', 'window'].includes(MODE)) throw new Error('Unknown MODE: ' + MODE);
function startModuleObserver() {
moduleObserver = Process.attachModuleObserver({
    onAdded(module) {
        if (!running || moduleBase !== null || module.name !== DATA.module) return;
        moduleBase = module.base;
        moduleEnd = module.base.add(module.size);
        excludeOutside();
        try {
            const hooks = new Set(HOOK_OFFSETS.map(offsetOf));
            for (const value of hooks) {
                if (!names.has(value)) throw new Error('Hook is not an IDA function entry: ' + value);
                if (!(MODE === 'window' && value === START_OFFSET)) hookFunction(value, true);
            }
            if (MODE === 'window') {
                if (!names.has(START_OFFSET)) throw new Error('Unknown START_OFFSET: ' + START_OFFSET);
                // A trigger in the argument allowlist shares one Interceptor listener.
                hookFunction(START_OFFSET, hooks.has(START_OFFSET), true);
            }
            // Install outside the loader callback; also clean window states on thread exit.
            setImmediate(() => {
                if (!running || moduleBase === null) return;
                threadObserver = Process.attachThreadObserver({
                    onAdded(thread) { discoverThread(thread); },
                    onRemoved(thread) {
                        unfollow(thread.id);
                        threads.delete(thread.id);
                        if (selectedThread === thread.id) selectedThread = null;
                    }
                });
                if (MODE === 'full' && MULTI_THREAD)
                    scanTimer = setInterval(() => Process.enumerateThreads().forEach(discoverThread), 250);
            });
            emit('[trace] READY ' + DATA.module + ' base=' + moduleBase +
                ' mode=' + MODE + ' multi-thread=' + MULTI_THREAD + ' hook-list=' + HOOK_OFFSETS.length +
                (MODE === 'window' ? ' start=' + START_OFFSET + ' size=' + WINDOW_SIZE : ''));
            flush();
        } catch (error) { emit('[error] ' + error); stop(); }
    },
    onRemoved(module) {
        if (moduleBase !== null && module.base.equals(moduleBase)) {
            clearModule();
            emit('[trace] module unloaded; waiting for reload');
            flush();
        }
    }
});
}
rpc.exports = { stop, status };
try {
    const hasArt = Process.platform === 'linux' && Process.findModuleByName('libart.so') !== null;
    if (JAVA_INTERPRETER && hasArt) {
        if (typeof Java === 'undefined' || !Java.available)
            throw new Error('Java bridge required: load with Frida CLI or bundle frida-java-bridge');
        Java.performNow(() => {
            Java.deoptimizeEverything();
            emit('[trace] Java interpreter enabled; Frida ' + Frida.version);
            startModuleObserver();
        });
    } else startModuleObserver();
} catch (error) {
    emit('[error] runtime initialization: ' + error);
    stop();
}
'''

def render_script(root_ea=None, mode="full"):
    if mode not in MODES:
        raise ValueError("Unknown mode: " + str(mode))
    root = idaapi.get_func(root_ea) if root_ea is not None else None
    if mode == "window" and root is None:
        raise ValueError("Place the cursor inside the window trigger function")
    base = ida_nalt.get_imagebase()
    deltas, named = [], []
    previous = 0
    for ea in idautils.Functions():
        offset = ea - base
        if offset < previous:
            raise ValueError("Function offsets must be non-negative and sorted")
        deltas.append(format(offset - previous, "x"))
        previous = offset
        name = " ".join((idc.get_func_name(ea) or "sub_%X" % ea).split())
        if name != "sub_%X" % ea:
            named.append([hex(offset), name])
    if root is not None and root.start_ea < base:
        raise ValueError("Root function precedes image base")
    data = {
        "mode": mode,
        "module": ida_nalt.get_root_filename(),
        "start": hex(root.start_ea - base) if root else "0x0",
        "thumb": root is not None and idc.get_sreg(root.start_ea, "T") == 1,
        "deltas": ",".join(deltas),
        "names": named,
        "imagebase": hex(base),
    }
    return SCRIPT.replace("__DATA__", json.dumps(data, ensure_ascii=True))

def write_script(path, source):
    """Save without overwriting existing files, including concurrent exports."""
    stem, extension = os.path.splitext(os.path.abspath(path))
    index = 0
    while True:
        candidate = stem + ("_%d" % index if index else "") + extension
        try:
            stream = open(candidate, "x", encoding="utf-8", newline="\n")
        except OSError as error:
            # Windows may report an existing directory as PermissionError.
            if not isinstance(error, FileExistsError) and not os.path.lexists(candidate):
                raise
            index += 1
            continue
        try:
            with stream:
                stream.write(source)
        except BaseException:
            try:
                os.unlink(candidate)
            except OSError:
                pass
            raise
        return candidate


def export(root_ea=None, mode="full"):
    try:
        input_path = ida_nalt.get_input_file_path()
        if not input_path or not os.path.isabs(input_path):
            raise ValueError("IDA input file must have an absolute path")
        source = render_script(root_ea, mode)
        path = os.path.join(os.path.dirname(input_path),
                            "trace_entries.js" if mode == "full" else "trace_window.js")
        path = write_script(path, source)
        print("[entry-trace] Saved " + path)
        return path
    except Exception as error:
        traceback.print_exc()
        idaapi.warning("Entry trace: " + str(error))


class ExportAction(idaapi.action_handler_t):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode

    def activate(self, ctx):
        if self.mode == "full":
            export(mode="full")
            return 1
        if ctx.widget_type == idaapi.BWN_FUNCS:
            if len(ctx.chooser_selection) != 1:
                idaapi.warning("Select exactly one root function")
                return 1
            function = idaapi.getn_func(ctx.chooser_selection[0])
            if function is None:
                return 1
            address = function.start_ea
        else:
            address = ctx.cur_ea
        export(address, self.mode)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in WIDGETS else idaapi.AST_DISABLE_FOR_WIDGET

class Popup(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) in WIDGETS:
            for mode in MODES:
                idaapi.attach_action_to_popup(widget, popup, ACTION + ":" + mode, "Entry Trace/")

class EntryTrace(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Full module trace or retriggerable 100-entry window"
    help = ""
    wanted_name = "Entry Trace: Export full trace"
    wanted_hotkey = ""

    def init(self):
        self.popup = None
        self.handlers = {}
        for mode, label in MODES.items():
            handler = ExportAction(mode)
            if not idaapi.register_action(idaapi.action_desc_t(ACTION + ":" + mode, label, handler)):
                self.term()
                return idaapi.PLUGIN_SKIP
            self.handlers[mode] = handler
        self.popup = Popup()
        self.popup.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        export(mode="full")

    def term(self):
        if self.popup:
            self.popup.unhook()
            self.popup = None
        for mode in self.handlers:
            idaapi.unregister_action(ACTION + ":" + mode)
        self.handlers.clear()

def PLUGIN_ENTRY():
    return EntryTrace()

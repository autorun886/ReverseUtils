// Fictional module and offsets: replace CONFIG with your target values.
// Entry Trace: edit CONFIG below to change targets, argument types and filters.
// Offsets are relative to the runtime module base; Thumb targets carry thumb:true.
// when.all = AND, when.any = OR. Only matching calls log ENTER and LEAVE.
// Filters observe values; they do not modify arguments or return values.
'use strict';
const CONFIG = {
  "module": "libsample.so",
  "maxString": 256,
  "backtrace": false,
  "timestamps": false,
  "singleThread": false,
  "hooks": [
    {
      "name": "parse_packet",
      "offset": "0x1000",
      "thumb": false,
      "args": [
        "int",
        "cstring"
      ],
      "ret": "int",
      "when": {
        "all": [
          {
            "arg": 0,
            "type": "int",
            "op": "eq",
            "value": 7
          },
          {
            "arg": 1,
            "type": "cstring",
            "op": "contains",
            "value": "hello"
          }
        ]
      }
    },
    {
      "name": "handle_message",
      "offset": "0x2000",
      "thumb": false,
      "args": [
        "int",
        "cstring"
      ],
      "ret": "int",
      "when": {
        "all": [
          {
            "arg": 0,
            "type": "int",
            "op": "eq",
            "value": 7
          },
          {
            "arg": 1,
            "type": "cstring",
            "op": "contains",
            "value": "hello"
          }
        ]
      }
    }
  ]
};
const listeners = [];
let observer = null, base = null, running = true, matches = 0;

function read(value, type) {
    try {
        if (type === 'int') return value.toInt32();
        if (type === 'uint') return value.toUInt32();
        if (type === 'cstring') return value.isNull() ? null : value.readUtf8String(CONFIG.maxString);
        if (type === 'utf16') return value.isNull() ? null : value.readUtf16String(CONFIG.maxString);
        return value.toString();
    } catch (_) { return undefined; }
}
function match(args, when) {
    if (!when) return true;
    if (when.all) return when.all.every(c => match(args, c));
    if (when.any) return when.any.some(c => match(args, c));
    const actual = read(args[when.arg], when.type || 'pointer'), expected = when.value;
    if (actual === undefined) return false;
    switch (when.op) {
        case 'eq': return actual === expected;
        case 'ne': return actual !== expected;
        case 'contains': return typeof actual === 'string' && actual.includes(expected);
        case 'startsWith': return typeof actual === 'string' && actual.startsWith(expected);
        case 'endsWith': return typeof actual === 'string' && actual.endsWith(expected);
        case 'regex': return typeof actual === 'string' && new RegExp(expected).test(actual);
        case 'gt': return actual > expected;
        case 'gte': return actual >= expected;
        case 'lt': return actual < expected;
        case 'lte': return actual <= expected;
    }
    return false;
}
function clear() { for (const h of listeners.splice(0)) h.detach(); base = null; }
function stop() {
    running = false;
    if (observer) { observer.detach(); observer = null; }
    clear();
    return { running, matches, installed: listeners.length };
}
observer = Process.attachModuleObserver({
    onAdded(module) {
        if (!running || base !== null || module.name !== CONFIG.module) return;
        base = module.base;
        for (const hook of CONFIG.hooks) {
            let address = base.add(hook.offset);
            if (hook.thumb) address = address.or(1);
            try {
                listeners.push(Interceptor.attach(address, {
                    onEnter(args) {
                        this.accepted = running && (!CONFIG.singleThread || this.threadId === Process.id)
                            && match(args, hook.when);
                        if (!this.accepted) return;
                        this.id = ++matches;
                        this.started = CONFIG.timestamps ? Date.now() : 0;
                        const values = hook.args.map((type, i) => read(args[i], type));
                        console.log('[ENTER #' + this.id + '] T' + this.threadId + ' ' + hook.name +
                            ' +' + hook.offset + ' args=' + JSON.stringify(values));
                        if (CONFIG.backtrace) console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                    },
                    onLeave(retval) {
                        if (!running || !this.accepted) return;
                        console.log('[LEAVE #' + this.id + '] ' + hook.name + ' return=' + read(retval, hook.ret) +
                            (CONFIG.timestamps ? ' duration=' + (Date.now()-this.started) + 'ms' : ''));
                    }
                }));
            } catch (error) { console.error('[hook error] ' + hook.name + ': ' + error); }
        }
        console.log('[ready] ' + CONFIG.module + ' base=' + base + ' installed=' + listeners.length);
    },
    onRemoved(module) { if (base !== null && module.base.equals(base)) clear(); }
});
rpc.exports = { stop, status: () => ({ running, matches, installed: listeners.length }) };

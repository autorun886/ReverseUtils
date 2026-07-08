/*
 * dump_so.js -- 通过 RPC dump SO 模块 (Frida 17)
 *
 * Usage:
 *   frida -U <package> -l dump_so.js
 *   然后通过 RPC 调用: exports.findmodule(name), exports.dumpmodule(name), exports.allmodule()
 */

'use strict';

rpc.exports = {
    findmodule(soName) {
        return Process.findModuleByName(soName);
    },

    dumpmodule(soName) {
        const lib = Process.findModuleByName(soName);
        if (!lib) return -1;

        Memory.protect(lib.base, lib.size, 'rwx');
        return lib.base.readByteArray(lib.size);
    },

    allmodule() {
        // Frida 17: Process.enumerateModules() 直接返回数组
        return Process.enumerateModules();
    },

    arch() {
        return Process.arch;
    }
};

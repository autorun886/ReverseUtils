/*
 * dump_dex.js -- Hook libart.so 的 DefineClass 来 dump DEX (Frida 17)
 *
 * Usage:
 *   frida -U -f <package> -l dump_dex.js
 */

'use strict';

const LIBC = Process.getModuleByName('libc.so');

function getSelfProcessName() {
    const open = new NativeFunction(LIBC.getExportByName('open'), 'int', ['pointer', 'int']);
    const read = new NativeFunction(LIBC.getExportByName('read'), 'int', ['int', 'pointer', 'int']);
    const close = new NativeFunction(LIBC.getExportByName('close'), 'int', ['int']);

    const path = Memory.allocUtf8String('/proc/self/cmdline');
    const fd = open(path, 0);
    if (fd !== -1) {
        const buffer = Memory.alloc(0x1000);
        read(fd, buffer, 0x1000);
        close(fd);
        return buffer.readCString();
    }
    return '-1';
}

function mkdir(path) {
    const mkdir = new NativeFunction(LIBC.getExportByName('mkdir'), 'int', ['pointer', 'int']);
    const opendir = new NativeFunction(LIBC.getExportByName('opendir'), 'pointer', ['pointer']);
    const closedir = new NativeFunction(LIBC.getExportByName('closedir'), 'int', ['pointer']);

    const cPath = Memory.allocUtf8String(path);
    const dir = opendir(cPath);
    if (!dir.isNull()) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 0o755);
    chmod(path);
}

function chmod(path) {
    const chmod = new NativeFunction(LIBC.getExportByName('chmod'), 'int', ['pointer', 'int']);
    const cPath = Memory.allocUtf8String(path);
    chmod(cPath, 0o755);
}

function dumpDex() {
    const libart = Process.findModuleByName('libart.so');
    if (!libart) return;

    let addrDefineClass = null;
    for (const sym of libart.enumerateSymbols()) {
        const name = sym.name;
        // DefineClass 的函数签名 (Android 9+)
        // _ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
        if (name.includes('ClassLinker') &&
            name.includes('DefineClass') &&
            name.includes('Thread') &&
            name.includes('DexFile')) {
            console.log(name, sym.address);
            addrDefineClass = sym.address;
        }
    }

    console.log('[DefineClass:]', addrDefineClass);
    if (!addrDefineClass) return;

    const dexMaps = {};
    let dexCount = 1;

    Interceptor.attach(addrDefineClass, {
        onEnter(args) {
            const dexFile = args[5];
            // dexFile + pointerSize → const uint8_t* begin_
            // dexFile + pointerSize*2 → const size_t size_
            const base = dexFile.add(Process.pointerSize).readPointer();
            const size = dexFile.add(Process.pointerSize + Process.pointerSize).readUInt();

            if (dexMaps[base] === undefined) {
                dexMaps[base] = size;
                const magic = base.readCString();
                if (magic && magic.startsWith('dex')) {
                    const processName = getSelfProcessName();
                    if (processName !== '-1') {
                        const dexDirPath = `/data/data/${processName}/files/dump_dex_${processName}`;
                        mkdir(dexDirPath);
                        const dexPath = `${dexDirPath}/class${dexCount === 1 ? '' : dexCount}.dex`;
                        console.log('[find dex]:', dexPath);
                        const fd = new File(dexPath, 'wb');
                        if (fd && fd !== null) {
                            dexCount++;
                            fd.write(base.readByteArray(size));
                            fd.flush();
                            fd.close();
                            console.log('[dump dex]:', dexPath);
                        }
                    }
                }
            }
        }
    });
}

let isHookLibart = false;

// Frida 17: 使用 Module.findGlobalExportByName 替代 Module.findExportByName(null, ...)
Interceptor.attach(Module.findGlobalExportByName('dlopen'), {
    onEnter(args) {
        const pathptr = args[0];
        if (pathptr) {
            const path = pathptr.readCString();
            if (path && path.includes('libart.so')) {
                this.canHookLibart = true;
                console.log('[dlopen:]', path);
            }
        }
    },
    onLeave(retval) {
        if (this.canHookLibart && !isHookLibart) {
            dumpDex();
            isHookLibart = true;
        }
    }
});

Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
    onEnter(args) {
        const pathptr = args[0];
        if (pathptr) {
            const path = pathptr.readCString();
            if (path && path.includes('libart.so')) {
                this.canHookLibart = true;
                console.log('[android_dlopen_ext:]', path);
            }
        }
    },
    onLeave(retval) {
        if (this.canHookLibart && !isHookLibart) {
            dumpDex();
            isHookLibart = true;
        }
    }
});

setImmediate(dumpDex);

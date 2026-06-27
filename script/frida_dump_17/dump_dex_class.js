/*
 * dump_dex_class.js -- 遍历 ClassLoader 触发所有类加载，配合 hook_dex 做 DEX dump (Frida 17)
 *
 * Usage:
 *   frida -U -f <package> -l dump_dex_class.js
 */

'use strict';

function getSelfProcessName() {
    const libc = Process.getModuleByName('libc.so');
    const open = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int']);
    const read = new NativeFunction(libc.getExportByName('read'), 'int', ['int', 'pointer', 'int']);
    const close = new NativeFunction(libc.getExportByName('close'), 'int', ['int']);

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

function loadAllClasses() {
    if (!Java.available) return;

    Java.perform(() => {
        const DexFileClass = Java.use('dalvik.system.DexFile');
        const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
        const DexPathList = Java.use('dalvik.system.DexPathList');

        Java.enumerateClassLoaders({
            onMatch(loader) {
                try {
                    const baseLoader = Java.cast(loader, BaseDexClassLoader);
                    const pathList = baseLoader.pathList.value;
                    const pathListObj = Java.cast(pathList, DexPathList);
                    const dexElements = pathListObj.dexElements.value;

                    for (const element of dexElements) {
                        try {
                            const dexFile = element.dexFile.value;
                            const dexFileObj = Java.cast(dexFile, DexFileClass);
                            console.log('dexFile:', dexFileObj);

                            const enumerator = dexFileObj.entries();
                            while (enumerator.hasMoreElements()) {
                                const className = enumerator.nextElement().toString();
                                try {
                                    loader.loadClass(className);
                                } catch (e) {
                                    console.log('loadClass error:', e);
                                }
                            }
                        } catch (e) {
                            console.log('dexfile error:', e);
                        }
                    }
                } catch (e) {
                    console.log('loader error:', e);
                }
            },
            onComplete() {}
        });

        console.log('loadAllClasses end.');
    });
}

const dexMaps = {};

function dumpDex() {
    loadAllClasses();

    for (const base in dexMaps) {
        const size = dexMaps[base];
        console.log(base);

        const magic = ptr(base).readCString();
        if (magic && magic.startsWith('dex')) {
            const processName = getSelfProcessName();
            if (processName !== '-1') {
                const dexPath = `/data/data/${processName}/files/${ptr(base).toString(16)}_${size.toString(16)}.dex`;
                console.log('[find dex]:', dexPath);
                const fd = new File(dexPath, 'wb');
                if (fd && fd !== null) {
                    fd.write(ptr(base).readByteArray(size));
                    fd.flush();
                    fd.close();
                    console.log('[dump dex]:', dexPath);
                }
            }
        }
    }
}

function hookDex() {
    const libart = Process.findModuleByName('libart.so');
    if (!libart) return;

    let addrDefineClass = null;
    for (const sym of libart.enumerateSymbols()) {
        const name = sym.name;
        // DefineClass (Android 9+)
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

    Interceptor.attach(addrDefineClass, {
        onEnter(args) {
            const dexFile = args[5];
            const base = dexFile.add(Process.pointerSize).readPointer();
            const size = dexFile.add(Process.pointerSize + Process.pointerSize).readUInt();

            if (dexMaps[base] === undefined) {
                dexMaps[base] = size;
                console.log('hookDex:', base, size);
            }
        }
    });
}

let isHookLibart = false;

// Frida 17: Module.findGlobalExportByName
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
            hookDex();
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
            hookDex();
            isHookLibart = true;
        }
    }
});

setImmediate(hookDex);

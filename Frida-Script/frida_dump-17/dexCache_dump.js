/*
 * dexCache_dump.js -- 通过 Java DexCache 对象 dump DEX (Frida 17)
 *
 * Usage:
 *   frida -U <package> -l dexCache_dump.js
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

function mkdir(pathStr) {
    const mkdir = new NativeFunction(LIBC.getExportByName('mkdir'), 'int', ['pointer', 'int']);
    const opendir = new NativeFunction(LIBC.getExportByName('opendir'), 'pointer', ['pointer']);
    const closedir = new NativeFunction(LIBC.getExportByName('closedir'), 'int', ['pointer']);

    const cPath = Memory.allocUtf8String(pathStr);
    const dir = opendir(cPath);
    if (!dir.isNull()) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 0o755);
    chmod(pathStr);
}

function chmod(pathStr) {
    const chmod = new NativeFunction(LIBC.getExportByName('chmod'), 'int', ['pointer', 'int']);
    const cPath = Memory.allocUtf8String(pathStr);
    chmod(cPath, 0o755);
}

function saveDex(base, size, dexCount) {
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
    return dexCount;
}

function dexCacheDump() {
    if (!Java.available) return;

    Java.perform(() => {
        let dexCount = 1;

        Java.choose('java.lang.DexCache', {
            onMatch(instance) {
                const classLoader = instance.classLoader.value;
                const location = instance.location.value;
                const dexFile = instance.dexFile.value;

                if (classLoader) {
                    const dexPtr = ptr(dexFile).add(Process.pointerSize).readPointer();
                    const dexSize = dexPtr.add(0x20).readU32();
                    console.log(classLoader, location, dexPtr, dexSize,
                        '\r\n', hexdump(dexPtr));
                    dexCount = saveDex(dexPtr, dexSize, dexCount);
                }
            },
            onComplete() {}
        });
    });
}

setImmediate(dexCacheDump);

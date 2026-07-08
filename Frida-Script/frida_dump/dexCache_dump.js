
function get_self_process_name() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);

        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}


function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);

    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);

    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);

    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}

function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}

function save_dex(base, size, dex_count) {
    var magic = ptr(base).readCString();
    if (magic.indexOf("dex") == 0) {

        var process_name = get_self_process_name();
        if (process_name != "-1") {
            var dex_dir_path = "/data/data/" + process_name + "/files/dump_dex_" + process_name;
            mkdir(dex_dir_path);
            var dex_path = dex_dir_path + "/class" + (dex_count == 1 ? "" : dex_count) + ".dex";
            console.log("[find dex]:", dex_path);
            var fd = new File(dex_path, "wb");
            if (fd && fd != null) {
                dex_count++;
                var dex_buffer = ptr(base).readByteArray(size);
                fd.write(dex_buffer);
                fd.flush();
                fd.close();
                console.log("[dump dex]:", dex_path);

            }
        }
    }

    return dex_count
}


function DexCache_dump() {
    Java.perform(() => {
        let dex_count = 1;
        Java.choose("java.lang.DexCache", {
            onMatch(instance) {
                let classLoader = instance.classLoader.value;
                let location = instance.location.value;
                let dexFile = instance.dexFile.value;
                if (classLoader) {
                    let dex_ptr = ptr(dexFile).add(Process.pointerSize).readPointer();
                    let dex_size = dex_ptr.add(0x20).readU32()
                    console.log(classLoader, location, dex_ptr, ptr(dex_size), "\r\n", hexdump(ptr(dex_ptr)));
                    dex_count = save_dex(dex_ptr, dex_size, dex_count)
                }

            }, onComplete() {

            }
        })
    })
}
setImmediate(DexCache_dump)
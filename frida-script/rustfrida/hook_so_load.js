console.log("")
var dlopen_interceptor = hook_dlopen();

function hook_dlopen() {
    globalThis.rfLogSoLoad = true
    // Reuse the dlsym script's observer when both scripts are loaded together.
    if (globalThis.rfDlopenObserved) return null
    var address = Module.findExportByName("libdl.so", "android_dlopen_ext")
    if (address == null) throw new Error("android_dlopen_ext export not found in libdl.so")
    return Interceptor.attach(address,
        {
            onEnter: function (args) {
                this.fileName = args[0].toString() === "0x0" ? "<null>" : args[0].readCString()
                console.log(`dlopen onEnter: ${this.fileName}`)
            }, onLeave: function(retval){
                console.log(`dlopen onLeave fileName: ${this.fileName}`)
            }
        }
    );
}

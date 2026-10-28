function format_address(address) {
    var module = Module.findByAddress(address)
    if (module != null) {
        return module.name + "!" + address.sub(module.base)
    }
    return address.toString()
}

var dl_handles = {}

function format_handle(handle) {
    if (handle.toString() === "0x0") {
        return handle + "=>RTLD_DEFAULT"
    }

    var handleValue = handle.toString()
    if (handleValue === "0xffffffffffffffff" || handleValue === "-0x1") {
        return handle + "=>RTLD_NEXT"
    }

    if (dl_handles[handleValue]) {
        return handle + "=>" + dl_handles[handleValue]
    }

    return handle + "=>unknown"
}

function hook_dlopen_handles() {
    var names = ["android_dlopen_ext", "dlopen"]
    for (var i = 0; i < names.length; i++) {
        var address = Module.findExportByName("libdl.so", names[i])
        if (address == null) {
            continue
        }

        Interceptor.attach(address, {
            onEnter: function (args) {
                this.path = args[0].toString() === "0x0" ? null : args[0].readCString()
                if (globalThis.rfLogSoLoad) console.log("dlopen onEnter: " + this.path)
            },
            onLeave: function (retval) {
                if (retval.toString() !== "0x0" && this.path) {
                    dl_handles[retval.toString()] = this.path
                }
                if (globalThis.rfLogSoLoad) console.log("dlopen onLeave fileName: " + this.path)
            }
        })
        if (names[i] === "android_dlopen_ext") globalThis.rfDlopenObserved = true
    }
}

function hook_dlsym() {
    console.log("=== hook_dlsym.js: HOOKING dlsym ===")
    var address = Module.findExportByName("libdl.so", "dlsym")
    if (address == null) throw new Error("dlsym export not found in libdl.so")
    var interceptor = Interceptor.attach(address,
        {
            onEnter: function (args) {
                this.handle = args[0]
                this.symbol = ptr(args[1]).readCString()
                this.caller = ptr(this.returnAddress)
                console.log("[dlsym] caller=" + format_address(this.caller) + " handle=" + format_handle(this.handle))
            },
            onLeave: function(retval) {
                console.log("[dlsym_ret] symbol=" + this.symbol + " retval=" + format_address(retval))
                console.log("")
            }
        }
    )
    return interceptor
}
console.log("")
hook_dlopen_handles();
hook_dlsym();

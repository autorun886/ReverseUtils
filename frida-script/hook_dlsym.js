function format_address(address) {
    var module = Process.findModuleByAddress(address)
    if (module != null) {
        return module.name + "!" + address.sub(module.base)
    }
    return address.toString()
}

var dl_handles = {}

function format_handle(handle) {
    if (handle.isNull()) {
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
        var address = Module.findGlobalExportByName(names[i])
        if (address == null) {
            continue
        }

        Interceptor.attach(address, {
            onEnter: function (args) {
                this.path = args[0].isNull() ? null : args[0].readCString()
            },
            onLeave: function (retval) {
                if (!retval.isNull() && this.path) {
                    dl_handles[retval.toString()] = this.path
                }
            }
        })
    }
}

function hook_dlsym() {
    console.log("=== hook_dlsym.js: HOOKING dlsym ===")
    var interceptor = Interceptor.attach(Module.findGlobalExportByName("dlsym"),
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

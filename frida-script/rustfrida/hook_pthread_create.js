function hook_pthred_create(){
    var address = Module.findExportByName("libc.so", "pthread_create")
    if (address == null) throw new Error("pthread_create export not found in libc.so")
    var interceptor = Interceptor.attach(address,
        {
            onEnter: function (args) {
                var module = Module.findByAddress(ptr(this.returnAddress))
                if (module != null) {
                    console.log("[pthread_create] called from", module.name)
                }
                else {
                    console.log("[pthread_create] called from", ptr(this.returnAddress))
                }
            },
        }
    )
}
console.log("")
hook_pthred_create();

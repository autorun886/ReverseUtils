function hook_pthred_create(){
    var interceptor = Interceptor.attach(Module.findGlobalExportByName("pthread_create"),
        {
            onEnter: function (args) {
                var module = Process.findModuleByAddress(ptr(this.returnAddress))
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
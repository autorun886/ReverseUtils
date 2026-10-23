console.log("")
var dlopen_interceptor = hook_dlopen();

function hook_dlopen() {
    Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"),
        {
            onEnter: function (args) {
                this.fileName = args[0].readCString()
                console.log(`dlopen onEnter: ${this.fileName}`)
            }, onLeave: function(retval){
                console.log(`dlopen onLeave fileName: ${this.fileName}`)
            }
        }
    );
}

rpc.exports = {
    run: function (min_size) {
        var ptr_malloc_usable_size = Module.findExportByName("libc.so", "malloc_usable_size");
        if (ptr_malloc_usable_size == null) {
            console.error("unable to find function with name `malloc_usable_size` in `libc.so`");
        } else {
            var func_malloc_usable_size = new NativeFunction(ptr_malloc_usable_size, 'size_t', ['pointer']);
            Interceptor.attach(Module.findExportByName("libc.so", "free"), {
                onEnter: function (args) {
                    try {
                        if (args[0].isNull()) {
                            return
                        }
                        var size = func_malloc_usable_size(args[0]);
                        if (size < min_size) {
                            return
                        }
                        var bs = args[0].readByteArray(size);
                        var payload = { pointer: args[0], size: size };
                        send(payload, bs);
                    } catch (e) {
                        console.error(`Error on onEnter() of free() hook: args[0]=${args[0]} e=${e}`);
                    }
                },
                onLeave: function (retval) {
                }
            });
        }
    }
};

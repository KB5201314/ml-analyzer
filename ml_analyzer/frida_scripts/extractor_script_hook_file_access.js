rpc.exports = {
    run: function (filter_dirs) {
        Interceptor.attach(Module.findExportByName("libc.so", "open"), {
            onEnter: function (args) {
                try {
                    if (args[0].isNull()) {
                        return
                    }
                    var args0 = args[0];
                    var file_path = Memory.readCString(args0);
                    for (var dir_index in filter_dirs) {
                        if (file_path.startsWith(filter_dirs[dir_index])) {
                            var payload = { file_path: file_path };
                            send(payload);
                            return
                        }
                    }
                } catch (e) {
                    console.error(`Error on onEnter() of free() hook: args[0]=${args[0]} e=${e}`);
                }
            },
            onLeave: function (retval) {
            }
        });
    }
};

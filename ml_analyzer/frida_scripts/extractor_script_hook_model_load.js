rpc.exports = {
    // model_load_functions: a list of functions to be hook
    run: function (model_load_functions) {
        // we need to hook both the following two dlopen implementations
        // void* android_dlopen_ext(const char* __filename, int __flags, const android_dlextinfo* __info): https://cs.android.com/android/platform/superproject/+/android-10.0.0_r30:bionic/libc/include/android/dlext.h;l=183
        // void *dlopen(const char *filename, int flags);
        var hook_dlopen = function (func_name_dlopen) {
            var ptr_dlopen = Module.getExportByName("libc.so", func_name_dlopen);
            if (ptr_dlopen == null) {
                console.warn(`can not found dlopen funtion with name ${func_name_dlopen} in libc.so`);
                return;
            }
            Interceptor.attach(ptr_dlopen, {
                onEnter: function (args) {
                    this.filename = Memory.readCString(args[0]);
                    console.log(`call ${func_name_dlopen}() with path: ${this.filename}`);
                },
                onLeave: function (retval) {
                    for (var func of model_load_functions) {
                        console.trace(`${func_name_dlopen}(${this.filename}): searching for function: ${func}`);
                        var ptr_func = Module.findExportByName(this.filename, func['func_name']);
                        if (ptr_func == null) {
                            console.error(`${func_name_dlopen}(${this.filename}): unable to find function with name \`${func['func_name']}\``);
                        } else {
                            console.info(`${func_name_dlopen}(${this.filename}): \`${func['func_name']}\` detected here`);
                            Interceptor.attach(ptr_func, {
                                onEnter: function (args) {
                                    try {
                                        if (func['param_type'] == 0) {
                                            // param is a file path cstring
                                            var model_path = Memory.readCString(args[func['indexs'][0]]);
                                            var payload = { model_path: model_path };
                                            send(payload);
                                        } else if (func['param_type'] == 1) {
                                            // param is a byte pointer and length
                                            var model_data = args[func['indexs'][0]];
                                            var model_size = args[func['indexs'][1]];
                                            var bs = model_data.readByteArray(model_size);
                                            var payload = { model_data: model_data, model_size: model_size };
                                            send(payload, bs);
                                        }
                                    } catch (e) {
                                        console.error(`${func_name_dlopen}(${this.filename}): Error in onEnter() of ${func['func_name']}() hook: e=${e}`);
                                    }
                                },
                                onLeave: function (retval) {
                                }
                            });
                        }
                    }
                }
            });
        }
        hook_dlopen("dlopen");
        hook_dlopen("android_dlopen_ext");
    }
};

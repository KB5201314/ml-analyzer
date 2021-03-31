rpc.exports = {
    run: function () {
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
                    var ptr_TfLiteModelCreate = Module.findExportByName(this.filename, "TfLiteModelCreate");
                    if (ptr_TfLiteModelCreate == null) {
                        console.error(`${func_name_dlopen}(${this.filename}): unable to find function with name \`TfLiteModelCreate\``);
                    } else {
                        console.info(`${func_name_dlopen}(${this.filename}): \`TfLiteModelCreate\` detected here`);
                        // https://github.com/tensorflow/tensorflow/blob/57f589f66c63fe7dd2f633c7304db78fc54aff0f/tensorflow/lite/c/c_api.cc#L90
                        // TfLiteModel* TfLiteModelCreate(const void* model_data, size_t model_size) {
                        Interceptor.attach(ptr_TfLiteModelCreate, {
                            onEnter: function (args) {
                                var model_data = args[0];
                                var model_size = args[1];
                                try {
                                    var bs = model_data.readByteArray(model_size);
                                    var payload = { model_data: model_data, model_size: model_size };
                                    send(payload, bs);
                                } catch (e) {
                                    console.error(`Error in onEnter() of TfLiteModelCreate() hook: model_data=${model_data}. model_size=${model_size} e=${e}`);
                                }
                            },
                            onLeave: function (retval) {
                            }
                        });
                    }

                    var ptr_TfLiteModelCreateFromFile = Module.findExportByName(this.filename, "TfLiteModelCreateFromFile");
                    if (ptr_TfLiteModelCreateFromFile == null) {
                        console.error(`${func_name_dlopen}(${this.filename}): unable to find function with name \`TfLiteModelCreateFromFile\``);
                    } else {
                        console.info(`${func_name_dlopen}(${this.filename}): \`TfLiteModelCreateFromFile\` detected here`);
                        // https://github.com/tensorflow/tensorflow/blob/57f589f66c63fe7dd2f633c7304db78fc54aff0f/tensorflow/lite/c/c_api.cc#L97
                        // TfLiteModel* TfLiteModelCreateFromFile(const char* model_path) {
                        Interceptor.attach(ptr_TfLiteModelCreateFromFile, {
                            onEnter: function (args) {
                                try {
                                    var model_path = Memory.readCString(args[0]);
                                    var payload = { model_path: model_path };
                                    send(payload);
                                } catch (e) {
                                    console.error(`Error in onEnter() of TfLiteModelCreateFromFile() hook: model_path=${model_path} e=${e}`);
                                }
                            },
                            onLeave: function (retval) {
                            }
                        });
                    }
                }
            });
        }
        hook_dlopen("dlopen");
        hook_dlopen("android_dlopen_ext");
    }
};

rpc.exports = {
    run: function () {
        var ptr_TfLiteModelCreate = Module.findExportByName(null, "TfLiteModelCreate");
        if (ptr_TfLiteModelCreate == null) {
            console.error("unable to find function with name `TfLiteModelCreate`");
        } else {
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

        var ptr_TfLiteModelCreateFromFile = Module.findExportByName(null, "TfLiteModelCreateFromFile");
        if (ptr_TfLiteModelCreateFromFile == null) {
            console.error("unable to find function with name `TfLiteModelCreateFromFile`");
        } else {
            // https://github.com/tensorflow/tensorflow/blob/57f589f66c63fe7dd2f633c7304db78fc54aff0f/tensorflow/lite/c/c_api.cc#L97
            // TfLiteModel* TfLiteModelCreateFromFile(const char* model_path) {
            Interceptor.attach(ptr_TfLiteModelCreateFromFile, {
                onEnter: function (args) {
                    try {
                        var model_path = Memory.readCString(args[0]);
                        var payload = { model_path: model_path };
                        var bs = model_data.readByteArray(model_size);
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
};

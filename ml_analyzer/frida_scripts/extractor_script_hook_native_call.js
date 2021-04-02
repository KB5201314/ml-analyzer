function fast_byte_array_java_to_js(bytelist) {
    var jsonString = Java.use('org.json.JSONArray').$new(bytelist).toString();
    return JSON.parse(jsonString);
}

function is_java_primary_type(atype) {
    return ['void', 'boolean', 'byte', 'short', 'char', 'int', 'long', 'float', 'double'].includes(atype);
}

rpc.exports = {
    run: function (native_methods) {
        var send_buffer = function (bs) {
            // TODO: change send paramters
            var payload = { /* TODO: fill this */ };
            send(payload, bs);
        }

        // will be initialized later
        var byte_class;
        var byte_array_class;
        var array_class;

        // a table which map type to it's insightor function
        var map_type_to_insightor = {
            // TODO: fill more
            'java.nio.ByteBuffer': (arg) => {
                var byte_buffer = arg.slice();
                var bytes = array_class.newInstance(byte_class, byte_buffer.remaining())
                var get_method = Java.use('java.nio.ByteBuffer').class.getMethod('get', [byte_array_class.class])
                get_method.invoke(byte_buffer, [bytes]);
                // TODO: collect trace stack
                send_buffer(fast_byte_array_java_to_js(bytes))
            },
            '[B': (arg) => {
                send_buffer(fast_byte_array_java_to_js(bytes))
            }
        }
        var generate_hook = function (clazz, method, args_type) {
            // setup insightors functions for each args by it's type
            var insightors = [];
            for (var arg_ind = 0; arg_ind < args_type.length; arg_ind++) {
                var type = args_type[arg_ind];
                // A model data muse not be stored in a private type, so we can skip it
                if (is_java_primary_type(type)) {
                    continue;
                }
                var arg_class;
                try {
                    arg_class = Java.use(type);
                } catch (e) {
                    console.warn(`Can not get class instance of class name: ${type} e=${e}`);
                    continue;
                }
                for (var maped_type in map_type_to_insightor) {
                    // we should also consider super class / interface class
                    if (Java.use(maped_type).class.isAssignableFrom(arg_class.class)) {
                        insightors.push([arg_ind, map_type_to_insightor[maped_type]]);
                    }
                }
            }
            return function (...args) {
                // call each insightor function with args[insightor[0]] as argument
                for (var insightor of insightors) {
                    insightor[1](args[insightor[0]]);
                }
                // call the original method
                return method.apply(this, args)
            }
        }

        Java.perform(() => {
            // get some java class instance
            byte_class = Java.use('java.lang.Byte').class.getField('TYPE').get(null);
            byte_array_class = Java.use('[B');
            array_class = Java.use('java.lang.reflect.Array');
            for (var info of native_methods) {
                console.log(`Perform hook on native method: ${info[0]}.${info[1]}(${info[2]})`);
                var clazz = Java.use(info[0]);
                var method = clazz[info[1]];
                var args_type = info[2];
                try {
                    method.overload.apply(method, args_type).implementation = generate_hook(clazz, method, args_type);
                } catch (e) {
                    console.error(`Error on hook native method clazz=${clazz} method=${info[1]} args_type=[${args_type}] e=${e}`);
                }
            }
        });
    }
};

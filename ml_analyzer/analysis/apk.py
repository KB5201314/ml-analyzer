from typing import List
import logging
import os
import pathlib

import androguard.decompiler.dad.util as androguard_util
from androguard.core.bytecodes.dvm import EncodedMethod, DalvikVMFormat
import lief

from ml_analyzer.context import Context

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ApkAnalyzer:
    def __init__(self, context: Context, args):
        self.context = context
        self.args = args

    def analysis(self):
        # load .so file from detect results
        detect_results = self.context.storage.read_detect_framework_results(
            self.context.sha1)
        native_lib_paths = list(map(lambda r: r.remark, filter(
            lambda r: r.remark.endswith('.so'), detect_results)))
        # collect all exported function names
        exported_function_names = set()
        for lib_path in native_lib_paths:
            lib_bs = self.context.androguard_apk.get_file(lib_path)
            lib = lief.parse(lib_bs)
            exported_function_names.update(
                f.name for f in lib.exported_functions)

        # collect native_methods
        native_methods = collect_all_java_native_method(
            self.context.androguard_dexs)
        # generate name map
        jni_name_to_method = dict(map(lambda m: (androguard_method_to_jni_name(
            m.get_class_name(), m.get_name()), m), native_methods))
        jni_name_to_method.update(dict(map(lambda m: (androguard_method_to_jni_name(
            m.get_class_name(), m.get_name(), m.get_descriptor(), overloaded=True), m), native_methods)))
        method_to_jimple_name = dict(map(lambda m: (m, androguard_method_to_jimple_name(
            m.get_class_name(), m.get_name(), m.get_descriptor())), native_methods))

        # filter native_methods and map to jimple_names
        finally_jimple_names = list()
        for jni_name, method in jni_name_to_method.items():
            if jni_name in exported_function_names:
                finally_jimple_names.append(method_to_jimple_name[method])

        sink_points = ''
        for jname in finally_jimple_names:
            sink_points += ('{} -> _SINK_\n'.format(jname))
        logger.info('Generated sink points:')
        logger.info(sink_points)
        if self.args.flowdroid_file is not None:
            flowdroid_file = self.args.flowdroid_file
        else:
            flowdroid_file = os.path.join(self.args.data_dir, 'flowdroid')
            pathlib.Path(flowdroid_file).mkdir(parents=True, exist_ok=True)
            flowdroid_file = os.path.join(
                flowdroid_file, '{}.txt'.format(self.context.sha1))

        logger.info('Generated FlowDroid input file: %s', flowdroid_file)
        with open(flowdroid_file, 'w') as f:
            f.write('<android.media.AudioRecord: int read(short[],int,int)> -> _SOURCE_\n<android.media.AudioRecord: int read(byte[],int,int)> -> _SOURCE_\n<android.media.AudioRecord: int read(java.nio.ByteBuffer,int)> -> _SOURCE_\n')
            f.write(sink_points)


def collect_all_java_native_method(androguard_dexs: List[DalvikVMFormat]) -> List[EncodedMethod]:
    native_methods = []
    for dex in androguard_dexs:
        for method in dex.get_methods():
            # should be native method
            if method.get_access_flags() & 0b100000000 == 0:
                continue
            native_methods.append(method)
    return native_methods


def androguard_method_to_jimple_name(class_name: str, method_name: str, descriptor: str) -> str:
    def descriptor_to_jimple(atype: str) -> str:
        TYPE_DESCRIPTOR = {
            'V': 'void',
            'Z': 'boolean',
            'B': 'byte',
            'S': 'short',
            'C': 'char',
            'I': 'int',
            'J': 'long',
            'F': 'float',
            'D': 'double',
        }
        res = TYPE_DESCRIPTOR.get(atype)
        if res is not None:
            return res
        if atype[0] == 'L':
            res = atype[1:-1].replace('/', '.')
        else:
            assert atype[0] == '['
            res = '%s[]' % descriptor_to_jimple(atype[1:])
        return res

    jname = '<'
    assert class_name[0] == 'L'
    assert class_name[-1] == ';'
    jname += descriptor_to_jimple(class_name)
    jname += ': '
    jname += descriptor_to_jimple(descriptor[descriptor.find(')')+1:].strip())
    jname += ' '
    jname += method_name
    jname += '('
    jname += ','.join([descriptor_to_jimple(t)
                       for t in androguard_util.get_params_type(descriptor)])
    jname += ')'
    jname += '>'
    return jname


def androguard_method_to_jni_name(class_name: str, method_name: str, descriptor: str = None, overloaded: bool = False) -> str:
    """
    https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/design.html
    class_name: 'Lorg/tensorflow/lite/NativeInterpreterWrapper;'
    method_name: 'allocateTensors'
    descriptor: '(J J)J'

    """

    def mangle_name(name: str, is_signature: bool) -> str:
        # replace '_' with '_1'
        name = name.replace('_', '_1')
        # replace '/' with '_'
        name = name.replace('/', '_')
        # replace non-ASCII Unicode characters
        name = ''.join(map(lambda c: c if c.isascii()
                           else '_0{:04x}'.format(ord(c)), list(name)))
        if is_signature:
            # _2 the character “;” in signatures
            name = name.replace(';', '_2')
            # _3 the character “[“ in signatures
            name = name.replace('[', '_3')
        return name

    # the prefix
    fname = 'Java_'

    # a mangled fully-qualified class name
    assert class_name[0] == 'L'
    assert class_name[-1] == ';'
    class_name = class_name[1:-1]
    class_name = mangle_name(class_name, False)
    fname += class_name
    # an underscore (“_”) separator
    fname += '_'
    # a mangled method name
    method_name = mangle_name(method_name, False)
    fname += method_name

    if overloaded:
        assert descriptor is not None
        params_type = androguard_util.get_params_type(descriptor)
        # for overloaded native methods, two underscores (“__”) followed by the mangled argument signature
        fname += '__'
        for pt in params_type:
            fname += mangle_name(pt, True)
    return fname

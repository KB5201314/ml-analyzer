import logging
import hashlib
import os
import sys

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def sha1_of_bytes(bs: bytes) -> str:
    m = hashlib.sha1()
    m.update(bs)
    return m.hexdigest()


def md5_of_bytes(bs: bytes) -> str:
    m = hashlib.md5()
    m.update(bs)
    return m.hexdigest()


def read_frida_script(script_path: str) -> str:
    script_dir = os.path.dirname(__file__)  # absolute dir the script is in
    script_path = os.path.join(script_dir, 'frida_scripts', script_path)
    with open(script_path, 'r') as f:
        return f.read()


# TODO: write test for this
def parse_descriptor_for_frida(atype: str, parse_primary_type: str = True) -> str:
    """
    Retrieve the java type of a descriptor (e.g : I).
    This function is the same as `androguard.decompiler.dad.util.get_type()`,
    but some changes have been made so that it can be used directly as a 
    parameter of `.overload()` in frida.
    """
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
    if parse_primary_type:
        res = TYPE_DESCRIPTOR.get(atype)
        if res is not None:
            return res
    if atype[0] == 'L':
        res = atype[1:-1].replace('/', '.')
    elif atype[0] == '[':
        res = '[%s' % parse_descriptor_for_frida(atype[1:], False)
    else:
        res = atype
        logger.debug('Unknown descriptor: "%s".', atype)
    return res


def mute_stdout_and_stderr():
    f = open('/dev/null', 'wb')
    os.dup2(f.fileno(), sys.stdout.fileno())
    os.dup2(f.fileno(), sys.stderr.fileno())

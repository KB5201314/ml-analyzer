import hashlib
import os


def sha1_of_bytes(bs: bytes) -> str:
    m = hashlib.sha1()
    m.update(bs)
    return m.hexdigest()


def read_frida_script(script_path: str) -> str:
    script_dir = os.path.dirname(__file__)  # absolute dir the script is in
    script_path = os.path.join(script_dir, 'frida_scripts', script_path)
    with open(script_path, 'r') as f:
        return f.read()

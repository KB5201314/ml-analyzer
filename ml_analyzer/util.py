import hashlib


def sha1_of_bytes(bs: bytes) -> str:
    m = hashlib.sha1()
    m.update(bs)
    return m.hexdigest()

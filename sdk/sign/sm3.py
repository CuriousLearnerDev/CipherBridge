"""SM3 国密哈希."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from sm_crypto import sm3_hash


def sm3(data: str) -> str:
    return sm3_hash(data.encode("utf-8"))

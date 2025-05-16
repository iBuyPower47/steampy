import os
import hmac
import json
import struct
from time import time
from typing import Dict
from hashlib import sha1
from base64 import b64encode, b64decode


def load_steam_guard(steam_guard: any) -> Dict[str, str]:
    """加载 Steam Guard 凭证，支持从文件、JSON 字符串或已解析的字典中读取。

    参数:
        steam_guard (Any): 可以是文件路径、JSON 字符串或已解析的字典。

    返回:
        Dict[str, str]: 解析后的 JSON 数据，所有键和值均为字符串类型。
    """
    # 如果输入已经是字典，直接返回
    if isinstance(steam_guard, dict):
        return {str(k): str(v) for k, v in steam_guard.items()}

    # 如果输入是文件路径，读取并解析 JSON
    if os.path.isfile(steam_guard):
        with open(steam_guard, 'r', encoding='utf-8') as f:
            return json.loads(f.read(), parse_int=str)

    # 否则，尝试将输入作为 JSON 字符串解析
    try:
        return json.loads(steam_guard, parse_int=str)
    except json.JSONDecodeError as e:
        raise ValueError("提供的输入既不是有效的文件路径，也不是有效的 JSON 字符串或字典。") from e


def generate_one_time_code(shared_secret: str, timestamp: int = None) -> str:
    if timestamp is None:
        timestamp = int(time())
    time_buffer = struct.pack('>Q', timestamp // 30)  # pack as Big endian, uint64
    time_hmac = hmac.new(b64decode(shared_secret), time_buffer, digestmod=sha1).digest()
    begin = ord(time_hmac[19:20]) & 0xF
    full_code = struct.unpack('>I', time_hmac[begin:begin + 4])[0] & 0x7FFFFFFF  # unpack as Big endian uint32
    chars = '23456789BCDFGHJKMNPQRTVWXY'
    code = ''

    for _ in range(5):
        full_code, i = divmod(full_code, len(chars))
        code += chars[i]

    return code


def generate_confirmation_key(identity_secret: str, tag: str, timestamp: int = int(time())) -> bytes:
    buffer = struct.pack('>Q', timestamp) + tag.encode('ascii')
    return b64encode(hmac.new(b64decode(identity_secret), buffer, digestmod=sha1).digest())


# It works, however it's different that one generated from mobile app
def generate_device_id(steam_id: str) -> str:
    hexed_steam_id = sha1(steam_id.encode('ascii')).hexdigest()
    return 'android:' + '-'.join((
        hexed_steam_id[:8],
        hexed_steam_id[8:12],
        hexed_steam_id[12:16],
        hexed_steam_id[16:20],
        hexed_steam_id[20:32],
    ))

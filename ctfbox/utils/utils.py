import re
from base64 import (b32encode, b64decode, b64encode, urlsafe_b64decode,
                    urlsafe_b64encode)
from binascii import hexlify, unhexlify
from hashlib import md5 as _md5
from hashlib import sha1 as _sha1
from hashlib import sha256 as _sha256
from itertools import chain
from json import dumps, loads
from random import choice, randint
from string import ascii_lowercase, digits
from struct import pack, unpack
from typing import Dict, Union
from urllib.parse import quote_plus, unquote_plus

import jwt
import requests

DEFAULT_ALPHABET = list(ascii_lowercase + digits)


def url_encode(s: str, encoding: str = 'utf-8') -> str:
    try:
        return quote_plus(s, encoding=encoding)
    except Exception:
        return ""


def url_decode(s: str, encoding: str = 'utf-8') -> str:
    try:
        return unquote_plus(s, encoding=encoding)
    except Exception:
        return ""


def base64_decode(s: str, encoding='utf-8') -> str:
    try:
        return b64decode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def base64_encode(s: str, encoding='utf-8') -> str:
    try:
        return b64encode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def bin2hex(s: str) -> str:
    try:
        return hexlify(s.encode()).decode()
    except Exception:
        return ""


def hex2bin(s: str) -> str:
    try:
        return unhexlify(s).decode()
    except Exception:
        return ""


def sha1(s: str, encoding='utf-8') -> str:
    try:
        return _sha1(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def sha256(s: str, encoding='utf-8') -> str:
    try:
        return _sha256(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def md5(s: str, encoding='utf-8') -> str:
    try:
        return _md5(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def random_int(minN: int = 0, maxN: int = 1024) -> int:
    try:
        return randint(minN, maxN)
    except Exception:
        return 0


def random_string(n: int = 32, alphabet: str = DEFAULT_ALPHABET) -> str:
    try:
        return ''.join([choice(alphabet) for _ in range(n)])
    except Exception:
        return ""


def json_encode(obj) -> object:
    try:
        return dumps(obj)
    except Exception:
        return object()


def json_decode(data) -> str:
    try:
        return loads(data)
    except Exception:
        return ""


def jwt_encode(header: dict, payload: dict, key=None, algorithm=None) -> str:
    if key is None and algorithm is None:
        # dict to json
        hearder_json = dumps(header, sort_keys=True, separators=(',', ':'))
        payload_json = dumps(payload, sort_keys=True, separators=(',', ':'))
        # json to base64
        header_b64 = urlsafe_b64encode(
            hearder_json.encode()).replace(b'=', b'')
        payload_b64 = urlsafe_b64encode(
            payload_json.encode()).replace(b'=', b'')

        return (header_b64 + b'.' + payload_b64).decode()
    else:
        return jwt.encode(payload=payload, key=key, algorithm=algorithm, headers=header)


def jwt_decode(token: str) -> bytes:
    data = [b''] * 3
    try:
        for i, each in enumerate(token.split('.')):
            padding = 4 - len(each) % 4
            if padding:
                each += ('=' * padding)
            data[i] = urlsafe_b64decode(each.encode())
    except Exception:
        pass

    return b'-'.join(data)

# ? web


def get_flask_pin(username: str,  absRootPath: str, macAddress: str, machineId: str, modName: str = "flask.app", appName: str = "Flask") -> str:
    rv, num = None, None
    probably_public_bits = [
        username,
        modName,
        # getattr(app, '__name__', getattr(app.__class__, '__name__'))
        appName,
        # getattr(mod, '__file__', None),
        absRootPath,
    ]

    private_bits = [
        # str(uuid.getnode()),  /sys/class/net/ens33/address
        str(int(macAddress.strip().replace(":", ""), 16)),
        machineId,  # get_machine_id(), /etc/machine-id
    ]

    h = _md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num
    return rv


def _is_json(data):
    try:
        loads(data)
    except ValueError:
        return False
    return True


def _parse_form_data(body, encoding: str = "utf-8"):
    if not body.startswith("-"):
        return {}, body
    parse_dict = {"data": {}, "files": {}}
    lines = body.split("\n")
    start, end = 0, 0
    while start < len(lines):
        boundary = lines[start]
        if boundary == "":
            start += 1
            continue
        end = start + lines[start:].index(boundary + "--")
        file_lines = lines[start:end]
        split_index = file_lines.index('')
        file_headers = file_lines[1:split_index]
        file_bodys = file_lines[split_index+1:end]
        header = file_headers[0]
        content_type = ""

        # ? header
        if not header.lower().startswith("content-disposition: "):
            start = end + 1
            continue
        other_headers = header[header.index(";"):]
        _dict = dict([l.split("=")
                      for l in other_headers.strip().split(";") if "=" in l])
        _dict = {k.strip(): v.strip('"') for k, v in _dict.items()}
        field = _dict.get('name', "")
        filename = _dict.get('filename', "")

        # ? content_type
        if len(file_headers) > 1:
            content_type_header = file_headers[1]
            if content_type_header.lower().startswith("content-type:"):
                content_type = content_type_header.split(":")[1].strip()
            else:
                content_type = "text/plain"

        body_string = '\n'.join(file_bodys)
        body_content = body_string.encode(encoding=encoding)
        if filename == "":
            parse_dict["data"][field] = body_string
        else:
            parse_dict["files"][field] = (filename, body_content, content_type)
        start = end + 1
    return parse_dict


def httpraw(raw: str, **kwargs) -> requests.Response:
    """Send raw request by python-requests

    Args:
        raw (str): raw data
        **kwargs:
            - proxies(dict) : requests proxies
            - timeout(float): requests timeout
            - verify(bool)  : requests verify
            - real_host(str): use real host instead of Host if set
            - ssl(bool)     : whether https
    Returns:
        requests.Response: The request response
    """
    # ? Origin: https://github.com/boy-hack/hack-requests
    raw = raw.strip()
    proxies = kwargs.get("proxy", None)
    timeout = kwargs.get("timeout", 60.0)
    verify = kwargs.get("verify", True)
    real_host = kwargs.get("real_host", None)
    ssl = kwargs.get("ssl", False)

    # ? Judgment scheme
    scheme = 'http'
    port = 80
    if ssl:
        scheme = 'https'
        port = 443

    try:
        index = raw.index('\n')
    except ValueError:
        raise Exception("ValueError")
    # ? get method, path and protocol
    try:
        method, path, protocol = raw[:index].split(" ")
    except Exception:
        raise Exception("Protocol format error")
    raw = raw[index + 1:]

    # ? get host
    try:
        host_start = raw.index("Host: ")
        host_end = raw.index('\n', host_start)

    except ValueError:
        raise ValueError("Host headers not found")

    if real_host:
        host = real_host
        if ":" in real_host:
            host, port = real_host.split(":")
    else:
        host = raw[host_start + len("Host: "):host_end]
        if ":" in host:
            host, port = host.split(":")
    raws = raw.splitlines()
    headers = {}
    index = 0
    # ? get headers
    for r in raws:
        if r == "":
            break
        try:
            k, v = r.split(": ")
        except Exception:
            k = r
            v = ""
        headers[k] = v
        index += 1
    headers["Connection"] = "close"
    # ? get body
    if len(raws) < index + 1:
        body = ''
    else:
        body = '\n'.join(raws[index + 1:]).lstrip()

    # ? get url
    url = f"{scheme}://{host}:{port}/{path}"
    # ? get content-length
    if body and "Content-Length" not in headers and "Transfer-Encoding" not in headers:
        headers["Content-Length"] = str(len(body))
    # ? deal with chunked
    if body and headers.get("Transfer-Encoding", '').lower() == "chunked":
        body = body.replace('\r\n', '\n')
        body = body.replace('\n', '\r\n')
        body = body + "\r\n" * 2
    # ? deal with Content-Type

    # ? deal with body
    parse_dict = {"files": {}, "data": {}}
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif _is_json(body) and headers["Content-Type"] not in ["application/json", "multipart/form-data"]:
        headers["Content-Type"] = "application/json"
    if headers["Content-Type"] == "application/x-www-form-urlencoded":
        body = dict([l.split("=")
                     for l in body.strip().split(";") if "=" in l])
    elif headers["Content-Type"] == "multipart/form-data":
        parse_dict = _parse_form_data(body)
        body = parse_dict["data"]

    # ? prepare request
    s = requests.Session()
    req = requests.Request(method, url, data=body, files=parse_dict["files"])
    prepped = req.prepare()
    return s.send(prepped,
                  proxies=proxies,
                  timeout=timeout,
                  verify=verify,
                  )


# ? Reverse

def printHex(data: Union[bytes, str], up: bool = True, sep: str = ' '):
    if isinstance(data, str):
        data = data.encode()
    bs = list(data)
    for i in range(len(bs)):
        print(('%02X' if up else '%02x') % bs[i], end=sep)
        if (i+1) % 16 == 0:
            print()


def _get_pack_fmtstr(sign, endianness, N):
    byte_order = {
        'little': '<',
        'big': '>'
    }
    number_type = {
        'unsigned': {
            16: 'H',
            32: 'I',
            64: 'Q',
        },
        'signed': {
            16: 'h',
            32: 'i',
            64: 'q',
        }
    }
    return byte_order[endianness] + number_type[sign][N]


def _pN(N: int, number: int, sign: str, endianness: str) -> bytes:
    fmt = _get_pack_fmtstr(sign, endianness, N)
    # use 0xff...ff and N to calculate a mask
    return pack(fmt, number & (0xffffffffffffffff >> (64 - N)))


def p16(number: int, sign: str = 'unsigned', endianness: str = 'little') -> bytes:
    """Pack a 16-bit number

    Args:
        number (int): Number to convert
        sign (str, optional): Signedness ("signed"/"unsigned"). Defaults to 'unsigned'.
        endianness (str, optional): Endianness ("little"/"big"). Defaults to 'little'.

    Returns:
        bytes: The packed bytes
    """
    return _pN(16, number, sign, endianness)


def p32(number: int, sign: str = 'unsigned', endianness: str = 'little') -> bytes:
    """Pack a 32-bit number

    Args:
        number (int): Number to convert
        sign (str, optional): Signedness ("signed"/"unsigned"). Defaults to 'unsigned'.
        endianness (str, optional): Endianness ("little"/"big"). Defaults to 'little'.

    Returns:
        bytes: The packed bytes
    """
    return _pN(32, number, sign, endianness)


def p64(number: int, sign: str = 'unsigned', endianness: str = 'little') -> bytes:
    """Pack a 64-bit number

    Args:
        number (int): Number to convert
        sign (str, optional): Signedness ("signed"/"unsigned"). Defaults to 'unsigned'.
        endianness (str, optional): Endianness ("little"/"big"). Defaults to 'little'.

    Returns:
        bytes: The packed bytes
    """
    return _pN(64, number, sign, endianness)


def _uN(N: int, data: bytes, sign: str, endianness: str, ignore_size: bool) -> int:
    fmt = _get_pack_fmtstr(sign, endianness, N)

    if ignore_size:
        size = N // 8
        data_len = len(data)
        if data_len < size:
            data += b'\x00' * (size - data_len)
        elif data_len > size:
            data = data[:size]

    return unpack(fmt, data)[0]


def u16(data: bytes, sign: str = 'unsigned', endianness: str = 'little', ignore_size=True) -> int:
    """Unpacks an 16-bit integer

    Args:
        data (bytes): bytes data to convert
        sign (str, optional): signedness ("signed"/"unsigned"). Defaults to 'unsigned'.
        endianness (str, optional): endianness ("little"/"big"). Defaults to 'little'.
        ignore_size (bool, optional): automatically pad data or truncate it to match the size . Defaults to True.

    Returns:
        int: The unpacked number
    """
    return _uN(16, data, sign, endianness, ignore_size)


def u32(data: bytes, sign: str = 'unsigned', endianness: str = 'little', ignore_size=True) -> int:
    """Unpacks an 32-bit integer

    Args:
        data (bytes): bytes data to convert
        sign (str, optional): signedness ("signed"/"unsigned"). Defaults to 'unsigned'.
        endianness (str, optional): endianness ("little"/"big"). Defaults to 'little'.
        ignore_size (bool, optional): automatically pad data or truncate it to match the size . Defaults to True.

    Returns:
        int: The unpacked number
    """
    return _uN(32, data, sign, endianness, ignore_size)


def u64(data: bytes, sign: str = 'unsigned', endianness: str = 'little', ignore_size=True) -> int:
    """Unpacks an 64-bit integer

    Args:
        data (bytes): bytes data to convert
        sign (str, optional): signedness ("signed"/"unsigned"). Defaults to 'unsigned'.
        endianness (str, optional): endianness ("little"/"big"). Defaults to 'little'.
        ignore_size (bool, optional): automatically pad data or truncate it to match the size . Defaults to True.

    Returns:
        int: The unpacked number
    """
    return _uN(64, data, sign, endianness, ignore_size)


def std_b32table() -> bytes:
    """Get a standard Base32 table

    Returns:
        bytes: Base32 table in bytes format, use std_b64table().decode() to get a 'str' one
    """
    return b32encode(bytes(list(map(lambda x: int(x, 2), re.findall('.{8}', ''.join(map(lambda x: bin(x)[2:].zfill(5), list(range(32)))))))))


def std_b64table() -> bytes:
    """Get a standard Base64 table

    Returns:
        bytes: Base64 table in bytes format, use std_b64table().decode() to get a 'str' one
    """
    return b64encode(bytes(list(map(lambda x: int(x, 2), re.findall('.{8}', ''.join(map(lambda x: bin(x)[2:].zfill(6), list(range(64)))))))))

# ? other


def od_parse(data: str) -> Dict[str, Union[str, list]]:
    """Parse od command output without argument, return a dict with the following keys: hex, ascii, list, text
    Returns:
        dict: with key hex, ascii, list, text
    """
    text, asc_data, hex_data, list_data = "", "", "", []
    for line in data.split("\n"):
        for d in line.split(" ")[1:]:
            h = hex(int(d, 8))[2:].zfill(4)
            a, b = int(h[2:], 16), int(h[:2], 16)
            text += chr(a)+chr(b)
            hex_data += "0x%x 0x%x " % (a, b)
            asc_data += "%s %s " % (a, b)
            list_data += [a, b]
    return {"hex": hex_data.strip(), "ascii": asc_data.strip(), "list": list_data, "text": text}

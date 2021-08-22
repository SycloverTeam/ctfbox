from base64 import b32encode, b64encode
from re import findall
from struct import pack, unpack
from typing import Union


def printHex(data: Union[bytes, str], offset: int = 0,
             up: bool = True, addHeader: bool = False, sep: str = ' '):
    """Print data in hex bytes format

    Args:
        data (bytes | str): the data to print
        offset (int): offset to the data, can be negative numbers
        up (bool, optional): Uppercase. Defaults to True.
        addHeader (bool, optional): Wether add row header and column header. Defaults to False.
        sep (str, optional):  string inserted between values. Defaults to a space. Does not take effect when addHeader=True
    """
    if isinstance(data, str):
        data = data.encode()

    col_header_len = max(
        1,  # at least
        len('%x' % (offset - offset % 16)),
        len('%x' % (len(data) + offset))
    )

    if addHeader:
        # need to detect both positive side and negtive side
        # to fit the `offset`
        col = ' ' * col_header_len + '   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F'
        print(col)

    rest = offset % 16
    offset_floor = offset - rest

    fmt = '%' + str(col_header_len) + 'X'
    bs = list(data)
    for i in range(offset_floor, offset + len(bs)):
        if addHeader:
            if i % 16 == 0:
                print(fmt % i, end=': ')
        if i < offset:
            print('  ', end=' ')
        else:
            print(('%02X' if up else '%02x') %
                  bs[i - offset], end=sep if not addHeader else ' ')
        if (i + 1) % 16 == 0:
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
    return b32encode(bytes(list(
        map(lambda x: int(x, 2), findall('.{8}', ''.join(map(lambda x: bin(x)[2:].zfill(5), list(range(32)))))))))


def std_b64table() -> bytes:
    """Get a standard Base64 table

    Returns:
        bytes: Base64 table in bytes format, use std_b64table().decode() to get a 'str' one
    """
    return b64encode(bytes(list(
        map(lambda x: int(x, 2), findall('.{8}', ''.join(map(lambda x: bin(x)[2:].zfill(6), list(range(64)))))))))

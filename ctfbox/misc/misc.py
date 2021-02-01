""" Provide file header for common files

use dir(CommonSig) to acquire availiable signatures
"""
from enum import Enum
import os

from ctfbox.exceptions import RepairError


class CommonSig(Enum):
    SIG_PNG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    SIG_JPG = bytes([0xFF, 0xD8])
    SIG_JPEG = SIG_JPG
    SIG_BMP = bytes([0x42, 0x4D])
    SIG_GIF = b'GIF'

    SIG_ZIP = bytes([0x50, 0x4B, 0x03, 0x04])


def repair_fileheader(file_path, sig: CommonSig, backup: bool = True):
    """repair file header using signatures from enum class CommonSig

    Args:
        file_path (str): file path
        sig (CommonSig): misc.CommonSig, for example: repair_fileheader(path, CommonSig.SIG_PNG)
        backup (bool, optional): whether to create a backup. Defaults to True.
    """
    with open(file_path, 'rb') as f:
        bs = f.read()
        new_bs = sig.value + bs[len(sig.value):]

    if backup:
        os.rename(file_path, file_path+'.bak')

    with open(file_path, 'wb') as f:
        f.write(new_bs)


def repair_zip_fake_encrypt(file_path, backup: bool = True):
    """repair zip fake encrypt.

    Args:
        file_path (str): file path.
        backup (bool, optional): whether to create a backup. Defaults to True.
    """
    head = b'\x50\x4b\x03\x04'
    with open(file_path, 'rb') as f:
        bs = f.read()
    if bs[:4] != head:
        raise RepairError("The file header is not a zip file header")
    bs = bs[:6] + b"\x00" + bs[7:]
    startIndex = 0
    index = 0
    while index != -1:
        index = bs[startIndex:].find(b'\x50\x4b\x01\x02')
        if index != -1:
            bs = bs[:startIndex+index+8] + b"\x00" + bs[startIndex+index+9:]
            startIndex += index+10

    if backup:
        os.rename(file_path, file_path+'.bak')

    with open(file_path, 'wb') as f:
        f.write(bs)

""" Provide file header for common files
"""
from enum import Enum
import os

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
        

""" Provide file header for common files
"""
from enum import Enum


class CommonSig(Enum):
    sig_png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    sig_jpg = bytes([0xFF, 0xD8])
    sig_jpeg = sig_jpg
    sig_bmp = bytes([0x42, 0x4D])
    sig_gif = b'GIF'

    sig_zip = bytes([0x50, 0x4B, 0x03, 0x04])

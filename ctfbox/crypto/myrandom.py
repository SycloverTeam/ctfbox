from ctypes import *
global windows_status
windows_status = 1
def windows_srand(seed):
    """
    Args: 
        seed 随机数种子

    Returns: void
    """
    global windows_status
    windows_status = seed
def windows_rand():
    """
    Returns: 随机数
    """
    global windows_status
    windows_status=(214013*windows_status+2531011) & 0xffffffff
    return windows_status>>16&((1<<15)-1)

global android_seed 
global globalandroid_multiplier 
global globalandroid_addend 
global globalandroid_mask 
global globalandroid_seedUniquifier 

android_seed = 0
android_multiplier = 0x5DEECE66D
android_addend = 0xB
android_mask = (1 << 48) - 1
android_seedUniquifier = 8682522807148012
def android_random(seed):
    """
    Args: 
        seed(int): 随机数种子
    Returns: void
    """
    global android_seed 
    android_seed = initialScramble(seed)
def initialScramble(seed):
    global globalandroid_multiplier 
    global globalandroid_mask 
    return (seed ^ android_multiplier) & android_mask
def _next(bits):
    global android_seed 
    global globalandroid_multiplier 
    global globalandroid_addend 
    global globalandroid_mask 
    global globalandroid_seedUniquifier 
    oldseed = 0
    nextseed = 0
    seed = android_seed
    oldseed = seed
    nextseed = (oldseed * android_multiplier + android_addend) & android_mask
    android_seed = nextseed
    return c_int(((nextseed >> (48 - bits)))).value
def android_nextInt():
    """
    Returns: 目标随机数
    """
    return _next(32)
def android_nextInt_bound(bound):
    """
    Args: 
        bound(int): 随机整数上限

    Returns: 目标随机数
    """
    global android_seed 
    global globalandroid_multiplier 
    global globalandroid_addend 
    global globalandroid_mask 
    global globalandroid_seedUniquifier 
    r = _next(31)
    m = bound - 1
    if bound & m == 0:
        r = (((bound * (r & 0xffffffffffffffff)) >> 31) & 0xffffffff)
    else:
        u = r
        r = u % bound
        while u - r + m < 0:
            r = u % bound
            u = _next(31)
    return r

global linux_status
global linux_r
linux_status = 1
linux_r = []
def linux_srand(seed):
    """
    Args: 
        seed(int): 随机数种子
    """
    global linux_status
    global linux_r
    linux_r = [0] * (344 + linux_status)
    linux_r[0] = seed
    for i in range(1, 31):
        linux_r[i] = (((16807 * (0xffffffff & linux_r[i - 1])) % 2147483647)) & 0xffffffff
    for i in range(31, 34):
        linux_r[i] = linux_r[i - 31]

def linux_rand():
    """
    Returns: 目标随机数
    """
    global linux_status
    global linux_r
    linux_r.append(0)
    for i in range(34, 344 + linux_status):
        linux_r[i] = ((linux_r[i - 31] + linux_r[i - 3]) % (1 << 32))& 0xffffffff
    linux_status += 1
    return linux_r[343 + linux_status - 1] >> 1



"""
from ctfbox.crypto import crypto
crypto.android_random(2) #seed must be set
crypto.windows_srand(2) #seed must be set
crypto.linux_srand(2) #seed must be set
for i in range(50):
    print(crypto.android_nextInt()) #random number
    print(crypto.android_nextInt_bound(10)) #random numbers between[0,10)
    print(crypto.windows_rand()) #random number
    print(crypto.linux_rand()) #random number
"""

from ctypes import c_int
windows_status = 1

def windows_srand(seed):
    """
    Args:
        seed(int): Random number seed

    Returns: void

    Example:
        windows_srand(1)

    """
    global windows_status
    windows_status = seed

def windows_rand():
    """
    Returns:
        int: Random numbers

    Example:
        #seed must be set
        windows_rand()
    """
    global windows_status
    windows_status = (214013*windows_status+2531011) & 0xffffffff
    return windows_status >> 16 & ((1 << 15)-1)


android_seed = 0
android_multiplier = 0x5DEECE66D
android_addend = 0xB
android_mask = (1 << 48) - 1
android_seedUniquifier = 8682522807148012

def android_srand(seed):
    """
    Args:
        seed(int): Random numbers seed
    Returns: void

    Example:
        android_srand(1)

    """
    global android_seed
    android_seed = _initialScramble(seed)

def _initialScramble(seed):
    return (seed ^ android_multiplier) & android_mask

def _next(bits):
    global android_seed
    oldseed = 0
    nextseed = 0
    seed = android_seed
    oldseed = seed
    nextseed = (oldseed * android_multiplier + android_addend) & android_mask
    android_seed = nextseed
    return c_int(((nextseed >> (48 - bits)))).value

def android_nextInt():
    """
    Returns:
        int: Random numbers

    Example:
        # seed must be set using android_srand()
        android_nextInt()
    """
    return _next(32)

def android_nextInt_bound(bound):
    """
    Args:
        bound(int): Random numbers upper limit

    Returns:
        int: Random numbers between[0, bound)

    Example:
        #seed must be set
        android_nextInt_bound(10)

    """
    global android_seed
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


linux_status = 0
linux_r = []
def linux_srand(seed):
    """
    Args: 
        seed(int): Random numbers seed
    
    Returns: void

    Example:
        linux_srand(1)
        
    """
    if seed == 0:
        seed = 1
    word = seed
    seed = seed & 0xffffffff
    global linux_status
    global linux_r
    linux_status = 0
    linux_r = [0] * (344 + linux_status)
    linux_r[0] = seed
    for i in range(1, 31):
        if (word < 0):
            hi = (-word) // 127773
            hi = -hi
            lo = (-word) % 127773
            lo = -lo
        else:
            hi = word // 127773
            lo = word % 127773
        word = ((16807 * lo)) - ((2836 * hi))
        if word < 0:
            word = (2147483647 + word) & 0xffffffff
        linux_r[i] = word
    for i in range(31, 34):
        linux_r[i] = linux_r[i - 31]
    for i in range(34, 344):
        linux_r[i] = (((linux_r[i - 31] + linux_r[i - 3]) & 0xffffffff) % (1 << 32)) & 0xffffffff

def linux_rand():
    """
    Returns: 
        int: Random numbers

    Example:
        #seed must be set
        linux_rand()
    """
    global linux_status
    global linux_r
    linux_r.append(0)
    linux_r[344 + linux_status] = (((linux_r[344 + linux_status - 31] + linux_r[344 + linux_status - 3]) & 0xffffffff) % (1 << 32)) & 0xffffffff
    linux_status += 1
    return linux_r[344 + linux_status - 1] >> 1
'''
Routines to convert between byte strings and integers.
'''
import types

def bytes_to_int(bytes):
    """
    Converts string of bytes to integer
    """    
    if not type(bytes) is types.StringType:
        raise TypeError("String expected")

    res = 0
    for byte in bytes:
        res *= 256        
        res += ord(byte)

    return res

def int_to_bytes(number):
    """
    Converts integer into string of bytes
    """
    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("Long or int expected")

    res = ""
    while number > 0:
        res = "%s%s" % (chr(number & 0xFF), res)
        number /= 256
    
    return res

#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2012  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*
'''
Routines to convert between byte strings and integers.
'''

# standard library imports
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
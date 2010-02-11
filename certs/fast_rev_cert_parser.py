
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
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
Fast revoked certificates numbers list parser.
(Parsing big ammount of small objects with complex pyasn tool is too slow)
Parses only the revoked certificates numbers, revocation
dates and crl entry extensions are ignored
'''
import logging
logger = logging.getLogger('certs.fast_rev_cer_parser')
from converters.bytes_converter import bytes_to_int


def _decode_len(substrate):
  '''
  Returns length of object and size of length string.
  '''
  first_byte = ord(substrate[0])
  if first_byte == 128:
    logger.error("Unexpected length of object, expecting definite length form")
    return 0,0
  if first_byte < 128:
    return first_byte, 1
  else:
    size = firstOctet & 0x7F    
    length_str = substrate[1:size+1]
    length = bytes_to_int(length_str)
    return length, size

def _get_date(substrate):
  '''
  Extracts date string from substrate. According to postsignum policy, this is UTCTime.
  Added also GeneralizedTime (... just to be sure...)
  '''
  date_tag = substrate[0]
  if date_tag == chr(0x17) or chr(0x18):
    date_len, size_of_len_str = _decode_len(substrate[1:])
    # content starts after tag (+1) and the length specification (+size_of_len_str)
    date_content_start = 1 + size_of_len_str
    date = substrate[date_content_start : date_content_start + date_len]
    return date
  logger.warning("Date extraction from revoked cert list failed! Returning empty string.")
  return ""
  
def _parse_one_serial(substrate):   
  '''
  Parses one integer at the beggining of sequence and date immediately after it.
  Returns parsed serial number, date of revocation (UTC format, in string) and string starting at
  the position of the next sequence with revoked certificate id.
  ''' 
  if substrate[0] == chr(0x30):
    # ok, we are starting at sequence beginning    
    object_len, size_of_len_str = _decode_len(substrate[1:])
    if (object_len == 0):
      logger.error("Error parsing sequence object length")
    content_offset = 1+size_of_len_str
    # position of next sequence object start (other revoked certificate id)
    next_start = content_offset + object_len    
    if substrate[content_offset] == chr(0x02):      
      # ok - integer id first - certificate serial number
      int_len, size_of_len_str = _decode_len(substrate[content_offset+1:])
      if (int_len == 0):
        logger.error("Error parsing integer object length")
      # position of start of serial number
      absolute_start_of_int = content_offset + size_of_len_str + 1
      # psoition of end of serial number
      absolute_end_of_int = absolute_start_of_int + int_len
      sn_bytes = substrate[absolute_start_of_int:absolute_end_of_int]
      sn = bytes_to_int(sn_bytes)      
    
      # continue with date immediately after the integer (spec says, that revocationTime is mandatory)
      date_start = absolute_end_of_int
      date = _get_date(substrate[date_start:])
        
      return sn, date, substrate[next_start:]   
    else:
      logger.error("Integer header expected (byte 0x2)")
      return -1,'', ''
      
  else:
    logger.error("Unexpected char: %x" % ord(substrate[0]))
    # return empty string to stop the parsing process
    return -1, '', ''

def parse_all(rev_cert_list):
  '''
  Returns  list of revoked certificates serial numbers
  '''
  substrate = rev_cert_list 
  res = []
  #f = open('parsed_sn', "w")
  while len(substrate) != 0:
     sn, rev_date, substrate = _parse_one_serial(substrate)
     #f.write('Parsed serial number: %x\n' % sn)
     if sn == -1:
       logger.error("Error parsing revoked certificates list") 
     else:
       res.append([sn, rev_date])
  #f.close()
  return res
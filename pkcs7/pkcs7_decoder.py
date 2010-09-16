
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
Decoding of PKCS7 messages
'''

from cStringIO import StringIO

# dslib imports
from dslib.pyasn1.codec.der import decoder
from dslib.pyasn1 import error

# local imports
from asn1_models.pkcs_signed_data import *
from asn1_models.digest_info import *
from asn1_models.TST_info import *

class StringObj(object):
  
  def __init__(self, string):
    self._string = string
    
  def __str__(self):
    return self._string
  
  def __getitem__(self, key):
    return self._string[key]

  def __len__(self):
    return len(self._string)


class StringView(object):
  
  def __init__(self, string, start=0, end=None):
    self._string = string
    self._start = start
    if end == None:
      self._end = len(string)
    else:
      self._end = end 

  def __len__(self):
    return self._end - self._start
  
  def __getitem__(self, key):
    if type(key) == int:
      if key < 0:
        return self._string[self._end+key]
      else:
        if key >= (self._end - self._start):
          raise IndexError()
        return self._string[self._start+key]
    elif type(key) == slice:
      if key.stop == None:
        end = self._end
      elif key.stop < 0:
        end = self._end+key.stop
      else:
        end = self._start+key.stop
      start = self._start+(key.start or 0)
      return StringView(self._string, start=start, end=end)
    else:
      raise IndexError()

  def __str__(self):
    return str(self._string[self._start:self._end])

  def __nonzero__(self):
    return bool(str(self))


def decode_msg(message):    
    '''
    Decodes message in DER encoding.
    Returns ASN1 message object
    '''
    # create template for decoder
    msg = Message()
    # decode pkcs signed message
    #mess_obj = StringObj(message)
    mess_view = StringView(message)
    import time
    t = time.time()
    decoded = decoder.decode(mess_view,asn1Spec=msg)
    print "DECODE:", time.time()-t
    message = decoded[0]
        
    return message

def decode_qts(qts_bytes):
    '''
    Decodes qualified timestamp
    '''
    qts = Qts()
    decoded = decoder.decode(qts_bytes,asn1Spec=qts)
    qts = decoded[0]
    
    return qts


def decode_tst(tst_bytes):
    '''
    Decodes Timestamp Token
    '''
    tst = TSTInfo()
    decoded = decoder.decode(tst_bytes,asn1Spec=tst)
    tst = decoded[0]
    
    return tst



    
    
    
 
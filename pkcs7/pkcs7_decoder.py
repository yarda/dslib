
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
from pyasn1.codec.der import decoder
from pyasn1 import error

import pkcs7.asn1_models

from asn1_models.pkcs_signed_data import *
from asn1_models.digest_info import *
from asn1_models.TST_info import *

def decode_msg(message):    
    '''
    Decodes message in DER encoding.
    Returns ASN1 message object
    '''
    # create template for decoder
    msg = Message()
    # decode pkcs signed message
    decoded = decoder.decode(message,asn1Spec=msg)
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



    
    
    
 